# frozen_string_literal: true

require 'json'

# Long-term memory compaction for the Hivemind agent: the FORKED passes
# behind /compact that review the session and overwrite the keyed memory
# blobs (soul / knowledge / <player>). One throwaway chat per key, all
# sharing the same replayed prefix. Mixin on HiveMindAgent.
module HiveMindCompaction
  # Forks run this many at a time. Keys are isolated (separate chats,
  # separate memory files), so parallelism is safe; keep it modest — the
  # provider is overloaded and live replies share it.
  COMPACTION_CONCURRENCY = 2
  # Long-term memory compaction: FORKED per-key passes that review the
  # session (bounded thread tail + current memories + console) and
  # overwrite the keyed memory blobs (soul / knowledge / <player>).
  #
  # Each key gets its own THROWAWAY chat (build_compaction_chat) replaying
  # the live thread under the LIVE system prompt — NOT inside the live
  # chat, and NOT with a swapped system prompt. Two reasons:
  #   • Robustness: the live conversation is never touched, so there is
  #     no strip step to skip — a Ctrl-C mid-pass cannot leak pass
  #     messages into the session anymore (that leak poisoned every
  #     restart for a day).
  #   • Cache: prompt caching matches request PREFIXES. Swapping the
  #     system prompt diverges at token 0 and forfeits the whole cached
  #     thread; keeping the live system prompt makes everything up to
  #     the last live turn a prefix match, so only the pass prompt tail
  #     is uncached.
  # The forks use NO tools — this gateway drops tool-call arguments in
  # transport (tried batched, per-call, strict, flat: {} arrived every
  # time), while plain text always survives. Each fork asks for ONE key's
  # memory; the reply is the content itself (or UNCHANGED). Runs under
  # the mutex so it can't interleave with a live ask. Manual only:
  # triggered by /compact — never on quit (no auto compaction). On
  # SUCCESS /compact trims the compacted history (trim_session_after_
  # compaction!, keeping mid-pass console lines); on failure — any key
  # with no usable reply — the session is kept. clear_session! stays
  # callable standalone so a full wipe can be scripted/tested.
  def compact_memory!(reason = nil)
    return false if @disabled || !memory_enabled?
    return false unless compactable?
    log "memory compaction #{reason ? "(#{reason}) " : ''}— #{session_summary}"
    # Snapshot under the mutex, then RELEASE it for the forks: live asks
    # (greetings, replies) interleave between keys instead of queueing
    # behind minutes of compaction. Forks never touch @chat, so the only
    # shared state is the snapshot.
    seen = nil
    @mutex.synchronize do
      return false unless @chat
      return false if @compacting          # no overlapping /compact runs
      @compacting = true
      seen = players_seen   # snapshot BEFORE the passes (console may grow during it)
      # How much of the thread the forks will see — trim_session_after_
      # compaction! drops exactly this range (minus a recent tail) on success.
      @compaction_included_count = @chat.messages.size
    end
    material = compaction_material(seen)
    written = 0
    failures = []
    begin
      # One fork per key, TWO workers in parallel: keys are isolated, each
      # writes its own memory file (atomic whole-blob), and the provider
      # already tolerates concurrency (compaction + live replies
      # interleave). Queue preserves soul/knowledge-first ordering so
      # concurrent forks still share the longest cached prefix.
      work = Queue.new
      (%w[soul knowledge] + seen.sort).each { |k| work << k }
      results = Mutex.new
      workers = Array.new(COMPACTION_CONCURRENCY) do
        Thread.new do
          loop do
            key = begin
              work.pop(true)
            rescue ThreadError
              break
            end
            pass = nil
            begin
              @mutex.synchronize { pass = build_compaction_chat if @chat }
              next unless pass
              current = @memory_store.read_key(key).to_s.strip
              turn = format(HiveMindPrompts::COMPACTION_TURN, key,
                            current.empty? ? '(none yet)' : current)
              ask_with_retry(pass, "#{HiveMindPrompts::COMPACTION_PROMPT}\n\n#{material}\n\n#{turn}")
              content = extract_memory_content(pass.messages)
              unchanged = content && content.match?(/\AUNCHANGED\z/i)
              has_blob = !current.empty?
              results.synchronize do
                if content.nil? || (unchanged && !has_blob)
                  # No usable reply — or UNCHANGED for a key with no current
                  # blob (a coverage gap). Counts as failure: the trim must not
                  # drop an un-distilled range.
                  failures << key
                elsif unchanged
                  # legit no-op
                elsif @memory_store.write_key(key, content)
                  written += 1
                  log "memory compaction — #{key}: #{content.length} chars"
                else
                  failures << key
                end
              end
            ensure
              # Nothing to strip: the live conversation was never touched.
              # Drop the throwaway chat's reference and let GC take it.
              pass = nil
            end
          end
        end
      end
      workers.each(&:join)
    ensure
      @mutex.synchronize { @compacting = false }
    end
    unless failures.empty?
      log "memory compaction — FAILED: no usable reply for #{failures.join(', ')} — session kept"
      return false
    end
    log 'memory compaction — no memory changes (model decided nothing worth updating)' if written.zero?
    # Coverage diagnostic: any player the session touched who still has
    # no memory blob? (The per-key forks require one each, but the model
    # may have answered UNCHANGED wrongly — better to log than wonder.)
    missing = seen.map { |n| @memory_store.sanitize_key(n) } - @memory_store.player_names
    log "memory compaction — NO memory for: #{missing.join(', ')}" unless missing.empty?
    true
  rescue StandardError => e
    log_error('memory compaction failed', e)
    false
  end
  # ── Long-term memory (compaction) ─────────────────────────────

  private

  # Build the THROWAWAY chat for one compaction fork: wholesale alias of
  # @chat's entire state via messages.replace — the exact request shape
  # of a working bot reply (same bytes including the live :system
  # message, warm cached prefix, small generation). Sharing the Message
  # instances is safe: the fork only ever APPENDS its own turn, it never
  # mutates existing entries. No tools: the fork speaks plain text only.
  # Observers are hooked so the console keeps showing reasoning/usage.
  def build_compaction_chat
    pass = RubyLLM.chat(model: @model, provider: :openai, assume_model_exists: true)
    pass.messages.replace(@chat.messages)
    observe_chat(pass)
    pass
  end

  # The memory content from a per-key fork: the LAST non-empty assistant
  # message, fences stripped. Returns nil when the fork produced no text
  # at all; 'UNCHANGED' (checked by the caller) means keep the current
  # blob. Anything else IS the new blob — plain text in, plain text out.
  def extract_memory_content(pass_messages)
    text = pass_messages.select { |m| m.role == :assistant }
                        .filter_map { |m| c = m.content.to_s; c.empty? ? nil : c }
                        .last
    return nil if text.nil?
    t = text.strip
    t = t.sub(/\A```[a-z]*\n?/i, '').sub(/```\s*\z/, '').strip
    t.empty? ? nil : t
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
    # Read-ONLY on purpose: the console queue belongs to the LIVE bot's
    # delivery cycle (unread_console drains it into the next live turn).
    # Compaction only peeks — lines are included in the shared fork
    # prefix AND stay queued for normal consumption afterwards.
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
