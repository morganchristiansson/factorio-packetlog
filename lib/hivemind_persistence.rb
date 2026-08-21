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
    if data['recent_console'].is_a?(Array)
      @recent_console = data['recent_console'].map { |e| [e[0], e[1].to_s] }
    end
    # Re-arm pending follow-ups their absolute unix deadlines. An entry
    # that came DUE during downtime gets a past-due monotonic time and the
    # scheduler fires it on its first tick (correct: the task was already
    # due). Skipped entries (bad data / empty task) are simply dropped.
    n_rearmed = 0
    if data['followups'].is_a?(Array)
      data['followups'].each do |id, due_at, task|
        next unless due_at.is_a?(Numeric)
        task_text = clean_text(task)
        next if task_text.empty?
        id = id.to_i
        next if id <= 0 || @followups.any? { |f| f[:id] == id }
        @followup_seq = id if id > @followup_seq
        now_mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        @followups << { id: id,
                        due: now_mono + (due_at.to_f - Time.now.to_f),
                        due_at: due_at.to_f,
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
         "#{n_rearmed.positive? ? ", #{n_rearmed} follow-ups re-armed" : ''}"
  rescue JSON::ParserError, StandardError => e
    log_error('session load failed — starting fresh', e)
    @console_queue = []
    @recent_console = []
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
      'recent_console' => @recent_console,
      'followups' => @followup_mutex.synchronize { @followups.map { |f| [f[:id], f[:due_at], f[:task]] } },
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
  def persist_queue!
    @console_mutex.synchronize do
      write_session(session_data)
    end
  end

  def write_session(data)
    tmp = "#{@session_path}.tmp"
    File.write(tmp, JSON.generate(data))
    File.rename(tmp, @session_path)
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
