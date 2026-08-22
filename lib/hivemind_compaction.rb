# frozen_string_literal: true

# Long-term memory compaction for the Hivemind agent: the one-shot LLM pass
# behind /compact that reviews the session and overwrites the keyed memory
# blobs (soul / knowledge / <player>). Mixin on HiveMindAgent.
module HiveMindCompaction
  # Long-term memory compaction: a one-shot LLM pass that reviews the
  # session (the conversation thread + current memories + console) and
  # overwrites the keyed memory blobs (soul / knowledge / <player>).
  #
  # Runs INSIDE the live conversation (same chat object) so the provider
  # reuses its input-token cache for the whole thread — the only new
  # tokens are the compaction prompt itself. The pass is NOT allowed to
  # become part of the session: its messages are stripped afterwards and
  # the system prompt + tool set restored, so a session that continues is
  # exactly as it was (minus whatever the model chose to remember).
  #
  # The compaction visibility exposes ONLY the write_memories tool — never
  # say/rcon_query — and the prompt demands all updates in a single
  # batched call. Runs under the mutex so it can't interleave with a live
  # ask. Manual only: triggered by /compact — never on quit (no auto
  # compaction). The /compact command wipes the session after a SUCCESSFUL
  # pass ("distill then start fresh"); on failure the session is kept
  # (the error is logged, never silently swallowed into a clear).
  # clear_session! stays callable standalone so the wipe can be
  # scripted/tested without the LLM call.
  def compact_memory!(reason = nil)
    return false if @disabled || !memory_enabled?
    return false unless compactable?
    log "memory compaction #{reason ? "(#{reason}) " : ''}— #{session_summary}"
    @mutex.synchronize do
      chat = @chat
      return false unless chat
      tool = WriteMemories.new(store: @memory_store)
      chat.with_tool(tool)
      start = chat.messages.size
      seen = players_seen   # snapshot BEFORE the pass (console may grow during it)
      begin
        chat.with_instructions(HiveMindPrompts::COMPACTION_PROMPT)  # swaps the system prompt in place
        ask_with_retry(chat, compaction_material(seen))
        if tool.written.empty?
          log 'memory compaction — no memory changes (model decided nothing worth updating)'
        else
          tool.written.each { |key, content| log "memory compaction — #{key}: #{content.length} chars" }
        end
        # Coverage diagnostic: any player the session touched who still has
        # no memory blob? (The prompt requires one per player, but the
        # model may not comply — better to log it than to wonder.)
        missing = seen.map { |n| @memory_store.sanitize_key(n) } - @memory_store.player_names
        log "memory compaction — NO memory for: #{missing.join(', ')}" unless missing.empty?
      ensure
        # Strip the pass from the live conversation and restore the live
        # system prompt + tool set (so the session that continues is
        # unchanged, and write_memories stays compaction-only).
        removed = chat.messages.slice!(start..) || []
        chat.with_instructions(system_prompt_with_memories)
        chat.tools.delete(:write_memories)
        # Drop the persisted-conversation cache: the next persist must
        # re-serialize WITHOUT the stripped compaction messages.
        @persisted_messages = nil
        log "memory compaction — stripped #{removed.size} temp messages from the live conversation" if removed.any?
      end
    end
    true
  rescue StandardError => e
    log_error('memory compaction failed', e)
    false
  end
  # ── Long-term memory (compaction) ─────────────────────────────

  private

  # Is there anything worth compacting? A session with no conversation and
  # no console lines has nothing to distill — skip the wasted LLM call.
  def compactable?
    return true if @chat && @chat.messages.any? { |m| m.role != :system }
    @console_mutex.synchronize do
      return true unless @console_queue.empty?
    end
    false
  end

  # One-line summary of what the compaction pass is reviewing.
  def session_summary
    n_messages = @chat ? @chat.messages.count { |m| m.role != :system } : 0
    n_console = @console_mutex.synchronize { @console_queue.size }
    "#{n_messages} conversation messages, #{n_console} console lines"
  end

  # Everything the compaction model sees, as one big user prompt: current
  # memories (start from these), the players encountered this session (the
  # coverage list — every one must end with a memory, see COMPACTION_PROMPT),
  # a fresh server context, pending follow-ups (the model's own
  # plans/goals — worth remembering), and console lines not yet in the
  # conversation. The conversation THREAD itself is the message history
  # already in the live chat (compaction runs inside it), so it is not
  # duplicated here.
  def compaction_material(seen = players_seen)
    parts = []
    current = @memory_store.all
    if current.empty?
      parts << 'Current memories: none exist yet — everything will be written fresh.'
    else
      parts << "Current memories:\n" + current.map { |key, text| "=== #{key} ===\n#{text}" }.join("\n\n")
    end
    unless seen.empty?
      parts << "Players encountered this session (EVERY one of these must have a memory by the end):\n#{seen.sort.join(', ')}"
    end
    snap = context_snapshot
    parts << "Current server context:\n#{snap}" unless snap.empty?
    followups = @followup_mutex.synchronize do
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @followups.map { |f| "##{f[:id]} (in #{format_remaining(f[:due] - now)}): #{f[:task]}" }
    end
    parts << "Pending scheduled follow-ups:\n#{followups.join("\n")}" unless followups.empty?
    console = @console_mutex.synchronize do
      @console_queue.uniq.map { |p, m| p ? "#{p}: #{m}" : m }
    end
    parts << "Console lines:\n#{console.join("\n")}" unless console.empty?
    parts.join("\n\n")
  end

  # Distinct player names this session touched: anyone who joined, left, or
  # chatted, got a memory injected (memories_sent), holds an existing
  # player memory, or is currently online. Join/leave console lines carry
  # the name in the MESSAGE text (player field is nil there) — parse those
  # too, so a player who only joined and left still counts as encountered.
  # Compaction must end with a memory for every one of them (COMPACTION_PROMPT).
  # Called under @mutex (memory_prompt mutates @memories_sent under it too).
  def players_seen
    players = Set.new
    @console_mutex.synchronize do
      @console_queue.each do |p, msg|
        if p
          name = clean_text(p)
          players << name unless name.empty?
        elsif msg =~ /\A(\S+) (?:joined|left) the game/
          name = clean_text(Regexp.last_match(1))
          players << name unless name.empty?
        end
      end
    end
    @memories_sent.each { |p| players << clean_text(p) }
    @memory_store.player_names.each { |p| players << clean_text(p) }
    online_player_list.each { |p| players << clean_text(p) }
    players
  end

  # Seconds remaining as a compact human duration ("9m", "1h5m", "90s").
  def format_remaining(secs)
    s = [secs.to_i, 0].max
    return "#{s}s" if s < 60
    "#{s / 60}m#{s % 60}s"
  end
end
