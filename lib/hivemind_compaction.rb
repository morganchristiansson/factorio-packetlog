# frozen_string_literal: true

require 'json'

# Long-term memory compaction for the Hivemind agent: the SINGLE pass
# behind /compact that reviews the session and overwrites the keyed memory
# blobs (soul / knowledge / <player>) in one request. Mixin on HiveMindAgent.
module HiveMindCompaction
  # Long-term memory compaction: ONE pass that reviews the session
  # (bounded thread tail + current memories + console) and overwrites every
  # keyed memory blob (soul / knowledge / <player>) from a single reply of
  # delimited plain-text sections — one request instead of one per key.
  #
  # The pass uses a THROWAWAY chat (build_compaction_chat) replaying the
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
  # time), while plain text always survives. The per-section word budgets
  # (see COMPACTION_PROMPT) keep the single reply to a few KB, inside the
  # gateway's request window. Manual only: triggered by /compact — never
  # on quit (no auto compaction). On SUCCESS /compact trims the compacted
  # history (trim_session_after_compaction!, keeping mid-pass console
  # lines); on failure — a missing/empty section after one retry — the
  # session is kept. clear_session! stays callable standalone so a full
  # wipe can be scripted/tested.
  def compact_memory!(reason = nil)
    return false unless @memory_store.enabled?
    return false unless compactable?
    log "memory compaction #{reason ? "(#{reason}) " : ''}— #{session_summary}"
    # Snapshot under the mutex, then RELEASE it for the pass: live asks
    # (greetings, replies) interleave with compaction instead of queueing
    # behind it. The pass never touches @chat, so the only shared state
    # is the snapshot.
    seen = nil
    @mutex.synchronize do
      return false unless @chat
      return false if @compacting          # no overlapping /compact runs
      @compacting = true
      seen = session_players   # snapshot BEFORE the passes (console may grow during it)
      # How much of the thread the pass will see — trim_session_after_
      # compaction! drops exactly this range (minus a recent tail) on success.
      @compaction_included_count = @chat.messages.size
    end
    material = compaction_material(seen)
    # soul/knowledge first, then players, stable order. The agent itself is
    # never a target (stray blobs from older builds are ignored, not
    # rewritten).
    keys = (%w[soul knowledge] + seen.sort).reject { |k| k == HiveMindAgent::AGENT_NAME }
    pass = nil
    @mutex.synchronize { pass = build_compaction_chat if @chat }
    unless pass
      @mutex.synchronize { @compacting = false }
      log 'memory compaction — FAILED (no chat)'
      return false
    end
    begin
      # Session material rides in its OWN user message; the all-keys turn
      # goes out as the ask. On a retry, ask_with_retry strips just the
      # turn — the material message stays.
      pass.add_message(role: :user, content: "#{HiveMindPrompts::COMPACTION_PROMPT}\n\n#{material}")
      turn = format(HiveMindPrompts::COMPACTION_TURN_ALL, keys.join(', '))
      ask_with_retry(pass, turn)
      bodies = parse_compaction_sections(extract_memory_content(pass.messages).to_s, keys)
      if bodies.nil?
        # One retry on malformed/empty — transient model stall, not just
        # an UNCHANGED section (which parses fine).
        log 'memory compaction — no usable sections, retrying…'
        ask_with_retry(pass, turn)
        bodies = parse_compaction_sections(extract_memory_content(pass.messages).to_s, keys)
      end
      unless bodies
        log "memory compaction — FAILED: no usable reply for #{keys.join(', ')} — session kept"
        return false
      end
      written = 0
      bodies.each do |key, body|
        current = @memory_store.read_key(key).to_s.strip
        unchanged = body.match?(/\AUNCHANGED\z/i)
        if unchanged && !current.empty?
          log "memory compaction — #{key}: UNCHANGED"
        else
          content = unchanged ? 'present this session, no notable interaction yet' : body
          if @memory_store.write_key(key, content)
            written += 1
            log "memory compaction — #{key}: #{content.length} chars — #{content}"
          else
            log "memory compaction — #{key}: FAILED (write error)"
            return false
          end
        end
      end
    ensure
      @mutex.synchronize { @compacting = false }
    end
    log 'memory compaction — no memory changes (model decided nothing worth updating)' if written.zero?
    # Coverage diagnostic: any player the session touched who still has
    # no memory blob? (Every target key requires a section, but the model
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

  # Build the THROWAWAY chat for the compaction pass: wholesale alias of
  # @chat's entire state via messages.replace — the exact request shape
  # of a working bot reply (same bytes including the live :system
  # message, warm cached prefix, small generation). Sharing the Message
  # instances is safe: the pass only ever APPENDS its own turn, it never
  # mutates existing entries. No tools: the pass speaks plain text only.
  # Observers are hooked so the console keeps showing reasoning/usage.
  def build_compaction_chat
    # History may have been created with a different provider/model (e.g.
    # free chat/completions model now unavailable, now on :openai_responses
    # for muse-spark). Responses is strict: every tool call needs a paired
    # non-empty output. The live history has a halted reply (HivemindReply
    # returns halt('') → empty tool result) that chat/completions tolerates
    # but responses rejects. Sanitize in place and keep the current @model/
    # @provider (no fallback, no new env var).
    pass = RubyLLM.chat(model: @model, provider: @provider, assume_model_exists: true)
    apply_request_headers(pass)
    sanitized = []
    pending = Set.new
    @chat.messages.each do |m|
      if m.role == :assistant && m.tool_call?
        ids = m.tool_calls.is_a?(Hash) ? m.tool_calls.keys : []
        pending.merge(ids)
        sanitized << m
      elsif m.role == :tool
        # Halt (reply → halt('')) produces empty content → synthesize so
        # responses doesn't see "No tool output found for call_..."
        if m.content.to_s.strip.empty?
          sanitized << RubyLLM::Message.new(role: :tool, content: '(sent to game)', tool_call_id: m.tool_call_id)
        else
          sanitized << m
        end
        pending.delete(m.tool_call_id)
      else
        if pending.any?
          # Orphan assistant without following tool result → drop it
          while sanitized.last && sanitized.last.role == :assistant && sanitized.last.tool_call?
            sanitized.pop
          end
          pending.clear
        end
        sanitized << m
      end
    end
    while sanitized.last && sanitized.last.role == :assistant && sanitized.last.tool_call? && pending.any?
      sanitized.pop
      pending.clear
    end
    pass.messages.replace(sanitized)
    # No observe_chat here — the compaction pass is plain-text, per-key
    # "memory compaction — <player>: …" is the single line per key.
    # Generic assistant/reasoning logs would duplicate it.
    pass
  end

  # Split a single-pass compaction reply into key => body sections. Headers
  # are `=== memory: <key> ===` lines, matched case-insensitively and mapped
  # back to the target keys; text before the first header is ignored (tolerates
  # a preamble), unknown/duplicate headers are dropped. Bodies get the same
  # fence-strip as extract_memory_content. Returns nil when ANY target key has
  # no usable section — the pass fails (one retry) and the session is kept.
  def parse_compaction_sections(text, keys)
    wanted = keys.to_h { |k| [k.downcase, k] }
    sections = {}
    current = nil
    text.each_line do |line|
      if (m = line.match(/\A===\s*memory:\s*(.+?)\s*===\s*\z/i))
        key = wanted[m[1].strip.downcase]
        if key && !sections.key?(key)
          current = key
          sections[key] = +''
        else
          current = nil
        end
      elsif current
        sections[current] << line
      end
    end
    bodies = {}
    keys.each do |k|
      raw = sections[k]
      return nil if raw.nil?
      body = raw.strip.sub(/\A```[a-z]*\n?/i, '').sub(/```\s*\z/, '').strip
      return nil if body.empty?
      bodies[k] = body
    end
    bodies
  end

  # The memory content from the single compaction reply: the LAST non-empty
  # assistant message, fences stripped. Returns nil when the pass produced
  # no text at all. The caller splits it into per-key sections
  # (parse_compaction_sections) — plain text in, plain text out.
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

  # Gate for AUTOMATIC compaction triggers (map reset): only run a pass
  # when the session holds at least AUTO_COMPACTION_MIN_CHARS of history —
  # below that there's little to distill and the pass would mostly echo
  # the current blobs back. Manual /compact bypasses this gate.
  def auto_compaction_worthwhile?
    return false unless @chat
    chars = @chat.messages.reject { |m| m.role == :system }
                    .sum { |m| m.content.to_s.length }
    chars >= HiveMindAgent::AUTO_COMPACTION_MIN_CHARS
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
  def compaction_material(seen = session_players)
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
      @followups.map { |f| "'#{f[:name]}' (in #{format_remaining(f[:due] - now)}): #{f[:task]}" }
    end
    parts << "Pending scheduled follow-ups:\n#{followups.join("\n")}" unless followups.empty?
    # Read-ONLY on purpose: the console queue belongs to the LIVE bot's
    # delivery cycle (unread_console drains it into the next live turn).
    # Compaction only peeks — lines are included in the pass prompt
    # AND stay queued for normal consumption afterwards.
    console = @console_mutex.synchronize do
      @console_queue.uniq.map { |p, m| p ? "#{p}: #{m}" : m }
    end
    parts << "Console lines:\n#{console.join("\n")}" unless console.empty?
    parts.join("\n\n")
  end

  # Players active since last compaction (THIS LLM session) — the single
  # name for this set everywhere: the `@session_players` ivar, the
  # `session_players` reader here, and the `session_players` key in
  # hivemind-session.json (persisted via append_history and memory_prompt,
  # so restarts and hot reloads can't drift it from what the conversation
  # actually contains). Players with on-disk blobs who were silent this
  # session are deliberately NOT included — there is no new material about
  # them, so the pass would just answer UNCHANGED (wasted output per
  # stale player). Deliberately NOT included either: the console queue
  # (belongs to the live bot's delivery cycle) or the online roster
  # (silent players haven't appeared in this session). Called under @mutex.
  # Returns a snapshot copy (minus the agent name — replies are not a player).
  def session_players
    players = @session_players_mutex.synchronize { Set.new(@session_players) }
    players.delete(HiveMindAgent::AGENT_NAME)
    players
  end

  # Seconds remaining as a compact human duration ("9m", "1h5m", "90s").
  def format_remaining(secs)
    s = [secs.to_i, 0].max
    return "#{s}s" if s < 60
    "#{s / 60}m#{s % 60}s"
  end
end