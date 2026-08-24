# frozen_string_literal: true

# Restart-safe session persistence for the Hivemind agent: console queue +
# LLM conversation + pending follow-ups serialized to a JSON session file
# (atomic tmp+rename). Mixin on HiveMindAgent.
module HiveMindPersistence
  # ── Session persistence (restart-safe) ──────────────────────────

  # Restore console history + LLM conversation from the session file so a
  # RESTART (not just Ctrl-C) can resume. A corrupt/missing file starts
  # fresh. Tool round-trips are restored WITH their links: assistant
  # tool_calls messages carry their call ids + arguments, tool messages
  # their tool_call_id — a tool message without its call would be rejected
  # by the provider ("missing field tool_call_id"). Tool results whose
  # call was dropped (old/corrupt file) are skipped so the conversation
  # never dangles.
  LEGACY_TOOL_NAMES = { 'hivemind_say' => 'reply' }.freeze  # pre-rename sessions

  private
  def load_session
    return unless @session_path && File.exist?(@session_path)
    data = JSON.parse(File.read(@session_path))
    # The restored conversation may or may not contain past
    # memory injections — either way the players' memories re-seed (the
    # dedup set is empty at process start; a duplicate injection is
    # harmless).
    @memories_sent.clear
    if data['console_queue'].is_a?(Array)
      @console_queue = data['console_queue'].map { |e| [e[0], e[1].to_s] }
    end
    # Players encountered this LLM session — drives compaction targets;
    # must survive restarts or targets drift from the conversation.
    @session_players = Set.new
    if data['session_players'].is_a?(Array)
      @session_players = Set.new(data['session_players'].map { |n| n.to_s })
      @session_players.delete(HiveMindAgent::AGENT_NAME)
    end
    # Re-arm pending follow-ups from their absolute unix deadlines. Format:
    #   { "prowl" => { "due_at" => ..., "task" => ... } }
    # An entry that came DUE during downtime gets a past-due monotonic time
    # and the scheduler fires it on its first tick (correct: the task was
    # already due). Anything else (older formats, bad data, empty task) is
    # simply DISCARDED — no legacy fallbacks.
    n_rearmed = 0
    if data['followups'].is_a?(Hash)
      data['followups'].each do |name, e|
        next unless e.is_a?(Hash) && e['due_at'].is_a?(Numeric)
        task_text = clean_text(e['task'])
        next if task_text.empty?
        name = clean_text(name).to_s[0, HiveMindFollowUps::MAX_FOLLOWUP_NAME_LEN]
        next if name.empty?
        now_mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @followups.reject! { |f| f[:name] == name }
        @followups << { name: name,
                        due: now_mono + (e['due_at'].to_f - Time.now.to_f),
                        due_at: e['due_at'].to_f,
                        task: task_text }
        n_rearmed += 1
      end
    end
    @followup_cond.signal if n_rearmed.positive?
    messages = data['messages'] || []
    # Tool names may predate a rename (e.g. "hivemind_say" → "reply"):
    # rewrite legacy names so restored tool calls reference the CURRENT
    # tool set (a provider rejects calls naming an undeclared tool).
    messages.each do |m|
      next unless m.is_a?(Hash) && m['tool_calls'].is_a?(Array)
      m['tool_calls'].each do |tc|
        legacy = LEGACY_TOOL_NAMES[tc['name']]
        tc['name'] = legacy if legacy
      end
    end
    # Pass 0: scrub DEAD write_memories exchanges. Compaction passes that
    # were hard-killed (Ctrl-C) never ran their strip step, so their
    # failed tool-call rounds got persisted — dozens of "write_memories({})
    # → Invalid tool arguments" pairs that poison the next compaction
    # (the model reads its own failures and imitates them). Drop the
    # calls, their results, and the orphaned compaction-material user
    # prompts (they always start with "Current memories:"; live turn
    # prompts start with "Current context:").
    wm_ids = Set.new
    messages.each do |m|
      next unless m.is_a?(Hash) && m['tool_calls'].is_a?(Array)
      m['tool_calls'].each { |tc| wm_ids << tc['id'] if tc['name'] == 'write_memories' }
    end
    scrubbed = 0
    messages.reject! do |m|
      drop =
        if m['role'] == 'assistant' && m['tool_calls'].is_a?(Array)
          m['tool_calls'].any? { |tc| tc['name'] == 'write_memories' }
        elsif m['role'] == 'tool'
          wm_ids.include?(m['tool_call_id']) || m['content'].to_s.include?('Invalid tool arguments')
        elsif m['role'] == 'user'
          m['content'].to_s.start_with?('Current memories:')
        else
          false
        end
      scrubbed += 1 if drop
      drop
    end

    # Pass 1: tool_call ids declared by assistant messages, so tool results
    # can be re-linked (a restored tool message whose call is missing would
    # dangle → provider rejects the whole request).
    call_ids = messages.select { |m| m['role'] == 'assistant' && m['tool_calls'].is_a?(Array) }
                       .flat_map { |m| m['tool_calls'].map { |tc| tc['id'] } }.to_set
    messages.each do |m|
      case m['role']
      when 'tool'
        next unless call_ids.include?(m['tool_call_id']) && m['content']
        @chat.add_message(role: :tool, content: m['content'], tool_call_id: m['tool_call_id'])
      when 'assistant'
        if m['tool_calls'].is_a?(Array) && !m['tool_calls'].empty?
          calls = m['tool_calls'].filter_map do |tc|
            next unless tc['id'] && tc['name']
            [tc['id'], RubyLLM::ToolCall.new(id: tc['id'], name: tc['name'],
                                             arguments: parse_tool_arguments(tc['arguments']))]
          end.to_h
          next if calls.empty?
          @chat.add_message(role: :assistant, content: m['content'], tool_calls: calls)
        elsif m['content']
          @chat.add_message(role: :assistant, content: m['content'])
        end
      when 'user'
        next unless m['content']
        @chat.add_message(role: :user, content: m['content'])
      end
    end
    puts "[hivemind] session resumed: #{@console_queue.size} queued console lines, " \
         "#{messages.size} conversation messages" \
         "#{n_rearmed.positive? ? ", #{n_rearmed} follow-ups re-armed" : ''}" \
         "#{scrubbed.positive? ? " (scrubbed #{scrubbed} dead write_memories messages)" : ''}"
  rescue JSON::ParserError, StandardError => e
    log_error('session load failed — starting fresh', e)
    @console_queue = []
  end

  # Tool arguments are stored JSON-encoded (see serialize_messages); parse
  # leniently — a malformed blob degrades to {} like an empty call.
  def parse_tool_arguments(arguments)
    return {} if arguments.nil? || arguments.empty?
    parsed = JSON.parse(arguments)
    parsed.is_a?(Hash) ? parsed : {}
  rescue JSON::ParserError
    {}
  end

  # Full session snapshot: console queue + recent + pending follow-ups +
  # conversation messages. BOTH persist paths must write ALL keys — a
  # partial rewrite (queue-only) used to clobber the persisted conversation
  # whenever a chat line arrived after an ask, losing the session on
  # restart (nothing left for /compact to distill).
  def session_data
    {
      'version' => 1,
      'console_queue' => @console_queue,
      'session_players' => @session_players.to_a,
      # JSON object keyed by timer name — entries are name-keyed in memory.
      'followups' => @followup_mutex.synchronize do
        @followups.to_h { |f| [f[:name], { 'due_at' => f[:due_at], 'task' => f[:task] }] }
      end,
      'messages' => (@persisted_messages ||= serialize_messages),
    }
  end

  # Full persist: called after each completion (conversation changed) and
  # from schedule/cancel so a crash between triggers can't lose a scheduled
  # timer. Re-serializes the conversation into the cache reused by
  # persist_queue! (the cheap path must never fall back to stale messages).
  def persist!
    @console_mutex.synchronize do
      @persisted_messages = serialize_messages
      write_session(session_data)
    end
  end

  # Cheap persist — called from append_history on the packet thread so a
  # crash between triggers doesn't lose unread lines. Writes the FULL
  # snapshot; the conversation comes from the cache (@persisted_messages,
  # refreshed by persist!) so serializing messages per chat line costs
  # nothing and the file can never lose messages/followups.
  # The DISK WRITE happens outside @console_mutex: snapshot under the lock
  # (queue dup'd — JSON.generate must not race with appends), then write
  # holding only @persist_mutex. Keeps the lock hold O(µs) on the packet
  # thread and still serializes actual file ops across persist!/persist_queue!
  # (they share one .tmp path — interleaved writers would corrupt it).
  def persist_queue!
    data = @console_mutex.synchronize do
      d = session_data
      d['console_queue'] = d['console_queue'].dup
      d
    end
    write_session(data)
  end

  def write_session(data)
    persist_mutex.synchronize do
      tmp = "#{@session_path}.tmp"
      File.write(tmp, JSON.generate(data))
      File.rename(tmp, @session_path)
    end
  rescue StandardError => e
    log_error('session persist failed', e)
  end

  # Conversation as role/content pairs plus the data needed to rebuild a
  # valid tool round-trip after a restart: assistant tool_calls messages
  # keep their call ids/names/arguments (JSON-encoded), tool messages keep
  # their tool_call_id (the provider rejects a bare tool message without
  # one). The static system prompt is not persisted (re-added on load);
  # empty tool results carry nothing the model needs and are skipped.
  def serialize_messages
    return [] unless @chat
    @chat.messages.filter_map do |m|
      next if m.role == :system
      case m.role
      when :tool
        c = m.content.to_s
        next if c.empty? || m.tool_call_id.to_s.empty?
        { 'role' => 'tool', 'content' => c, 'tool_call_id' => m.tool_call_id }
      when :assistant
        if m.tool_call?
          # Live assistant messages carry tool_calls as {call_id => ToolCall}
          # (RubyLLM::Chat#handle_tool_calls runs tool_calls.each_value);
          # tolerate plain arrays too.
          calls = m.tool_calls.is_a?(Hash) ? m.tool_calls.values : m.tool_calls
          msg = { 'role' => 'assistant',
                  'tool_calls' => calls.map do |tc|
                    { 'id' => tc.id, 'name' => tc.name,
                      'arguments' => JSON.generate(tc.arguments || {}) }
                  end }
          c = m.content.to_s
          msg['content'] = c unless c.empty?
          msg
        else
          c = m.content.to_s
          next if c.empty?
          { 'role' => 'assistant', 'content' => c }
        end
      else # user
        c = m.content.to_s
        next if c.empty?
        { 'role' => 'user', 'content' => c }
      end
    end
  end
end
