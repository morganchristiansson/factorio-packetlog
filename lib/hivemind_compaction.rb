# frozen_string_literal: true

require 'json'

# Long-term memory compaction for the Hivemind agent: the one-shot LLM pass
# behind /compact that reviews the session and overwrites the keyed memory
# blobs (soul / knowledge / <player>). Mixin on HiveMindAgent.
module HiveMindCompaction
  # Long-term memory compaction: a one-shot LLM pass that reviews the
  # session (the conversation thread + current memories + console) and
  # overwrites the keyed memory blobs (soul / knowledge / <player>).
  #
  # Long-term memory compaction: a one-shot LLM pass that reviews the
  # session (the conversation thread + current memories + console) and
  # overwrites the keyed memory blobs (soul / knowledge / <player>).
  #
  # Runs on a THROWAWAY chat (build_compaction_chat) that replays the
  # live thread under the LIVE system prompt — NOT inside the live chat,
  # and NOT with a swapped system prompt. Two reasons:
  #   • Robustness: the live conversation is never touched, so there is
  #     no strip step to skip — a Ctrl-C mid-pass cannot leak pass
  #     messages into the session anymore (that leak poisoned every
  #     restart for a day).
  #   • Cache: prompt caching matches request PREFIXES. Swapping the
  #     system prompt diverges at token 0 and forfeits the whole cached
  #     thread; keeping the live system prompt makes everything up to
  #     the last live turn a prefix match, so only the pass prompt tail
  #     is uncached.
  # The pass uses NO tools — this gateway drops tool-call arguments in
  # transport (tried batched, per-call, strict, flat: {} arrived every
  # time), while plain text always survives. The compaction instructions
  # ride in the user turn; the model ends its reply with a fenced JSON
  # array of {key, content}; we parse and apply it. Runs under the mutex
  # so it can't interleave with a live ask. Manual only: triggered by
  # /compact — never on quit (no auto compaction). The /compact command
  # wipes the session after a SUCCESSFUL pass ("distill then start
  # fresh", keeping console lines that arrived mid-pass); on failure —
  # including an un-parsable reply — the session is kept. clear_session!
  # stays callable standalone so the wipe can be scripted/tested without
  # the LLM call.
  def compact_memory!(reason = nil)
    return false if @disabled || !memory_enabled?
    return false unless compactable?
    log "memory compaction #{reason ? "(#{reason}) " : ''}— #{session_summary}"
    @mutex.synchronize do
      return false unless @chat
      seen = players_seen   # snapshot BEFORE the pass (console may grow during it)
      # How much of the thread the pass will see — trim_session_after_compaction!
      # drops exactly this range (minus a recent tail) on success.
      @compaction_included_count = @chat.messages.size
      pass = build_compaction_chat
      begin
        prompt = "#{HiveMindPrompts::COMPACTION_PROMPT}\n\n#{compaction_material(seen)}"
        ask_with_retry(pass, prompt)
        writes = extract_memory_writes(pass.messages)
        if writes.nil?
          # No parsable JSON block ⇒ nothing usable was produced. MUST NOT
          # count as a successful no-op: /compact wipes the session on
          # success, and a mangled reply means an un-distilled session.
          log 'memory compaction — FAILED: no parsable memory JSON in the reply — session kept'
          return false
        end
        if writes.empty?
          log 'memory compaction — no memory changes (model decided nothing worth updating)'
        else
          writes.each do |entry|
            key = entry['key'].to_s.strip
            content = entry['content'].to_s
            if key.empty?
              log 'memory compaction — skipped entry with empty key'
            elsif @memory_store.write_key(key, content)
              log "memory compaction — #{key}: #{content.length} chars"
            else
              log "memory compaction — #{key} FAILED to write"
            end
          end
        end
        # Coverage diagnostic: any player the session touched who still has
        # no memory blob? (The prompt requires one per player, but the
        # model may not comply — better to log it than to wonder.)
        missing = seen.map { |n| @memory_store.sanitize_key(n) } - @memory_store.player_names
        log "memory compaction — NO memory for: #{missing.join(', ')}" unless missing.empty?
      ensure
        # Nothing to strip: the live conversation was never touched. Drop
        # the throwaway chat's reference and let GC take it.
        pass = nil
      end
    end
    true
  rescue StandardError => e
    log_error('memory compaction failed', e)
    false
  end
  # ── Long-term memory (compaction) ─────────────────────────────

  private

  # Build the THROWAWAY chat for one compaction pass: same model, the
  # LIVE system prompt (identical bytes ⇒ the replayed thread stays a
  # cache-prefix match), and a bounded tail of the live message thread
  # (REPLAY_LAST_MESSAGES, never starting mid-tool-round-trip — the
  # provider rejects dangling tool_call_ids). No tools: the pass speaks
  # plain text only. Observers are hooked so the console keeps showing
  # reasoning/usage during the pass. Bounded input + tight output budgets
  # (see COMPACTION_PROMPT) keep generation inside the gateway's request
  # window — full-thread passes were killed with HTTP 500 every time.
  def build_compaction_chat
    pass = RubyLLM.chat(model: @model, provider: :openai, assume_model_exists: true)
    pass.with_instructions(system_prompt_with_memories)
    msgs = @chat.messages
    start = [msgs.size - HiveMindAgent::REPLAY_LAST_MESSAGES, 1].max
    start += 1 while start < msgs.size && msgs[start].role == :tool
    msgs[start..].each do |m|
      next if m.role == :system
      if m.tool_calls && !m.tool_calls.empty?
        pass.add_message(role: m.role, content: m.content, tool_calls: m.tool_calls)
      elsif m.role == :tool
        pass.add_message(role: :tool, content: m.content, tool_call_id: m.tool_call_id)
      else
        pass.add_message(role: m.role, content: m.content)
      end
    end
    observe_chat(pass)
    pass
  end

  # Pull [{"key","content"}] out of the compaction reply: the LAST
  # non-empty assistant message of the pass, its fenced ```json block if
  # present (else the whole text), parsed leniently — a JSON::ParserError
  # falls back to the outermost [..] span. Returns [] for a legit "nothing
  # changed", nil when nothing parsable was found (caller fails the pass).
  def extract_memory_writes(pass_messages)
    text = pass_messages.select { |m| m.role == :assistant }
                        .filter_map { |m| c = m.content.to_s; c.empty? ? nil : c }
                        .last
    return nil if text.nil?
    blocks = text.scan(/```(?:json)?\s*(.*?)```/m).flatten
    candidate = (blocks.last || text).strip
    parsed = begin
      JSON.parse(candidate)
    rescue JSON::ParserError
      l = candidate.index('[')
      r = candidate.rindex(']')
      begin
        l && r && r > l ? JSON.parse(candidate[l..r]) : nil
      rescue JSON::ParserError
        nil
      end
    end
    return nil unless parsed.is_a?(Array)
    parsed.select { |e| e.is_a?(Hash) && e.key?('key') && e.key?('content') }
  end

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
