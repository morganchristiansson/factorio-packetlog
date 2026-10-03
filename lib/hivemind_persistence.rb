# frozen_string_literal: true

# Hivemind feature `persistence` — the file is lib/hivemind_persistence.rb
# (the plugin set's `hivemind_` prefix), the class takes its CamelCase name.
# Listed in config-hivemind.yaml `plugins:` and built by the agent's own
# Plugins::PluginSet with the agent as its owner. Restart-safe session
# persistence: console queue + LLM conversation + pending follow-ups
# serialized to a JSON session file (atomic tmp+rename).
#
# This feature OWNS the file: its path, the write lock, the serialized-
# message cache, and every read/write of it. The agent owns the state the
# file is built from and publishes two seams — #session_snapshot (what to
# write) and #restore_session_state (what a loaded file replaces) — so
# nothing outside this file knows a session file exists. Compaction trims
# the conversation, so it calls #messages_changed! to drop the cached
# serialization; the agent and the followups feature just call #persist!.
class HivemindPersistence
  # Where the session file lives: next to the process (cwd), like
  # players-cache.json. NOT a constructor argument — the agent has no
  # session-path knob; tests stub this class method instead
  # (HivemindPersistence.stub(:default_path, tmp) { new_hive_agent(...) }),
  # and a nil stub is the "no session file" case. Captured in the
  # constructor, so the path survives a hot reload of this file.
  def self.default_path = 'hivemind-session.json'

  # The agent, as its owner: this feature reaches the session state through
  # the two published seams, and the log/chat interface, and nothing else.
  def initialize(host)
    @host = host
    @path = self.class.default_path
    @mutex = Mutex.new      # serializes writes (all paths share one .tmp)
    @messages = nil         # serialized conversation cache (see #messages_changed!)
  end

  attr_reader :host, :path

  # No path = no session file (a `persistence` plugin that is switched off
  # is simply never built; this covers a nil default too). Every call below
  # is a no-op then, so no call site needs a guard.
  def enabled? = !@path.nil?

  # The conversation changed under us (a compaction trim): the cached
  # serialization is stale and the next write must rebuild it.
  def messages_changed! = (@messages = nil)

  # Restore console history + LLM conversation from the session file so a
  # RESTART (not just Ctrl-C) can resume. A corrupt/missing file starts
  # fresh. Tool round-trips are restored WITH their links: assistant
  # tool_calls messages carry their call ids + arguments, tool messages
  # their tool_call_id — a tool message without its call would be rejected
  # by the provider ("missing field tool_call_id"). Tool results whose
  # call was dropped (old/corrupt file) are skipped so the conversation
  # never dangles.
  def load!
    return false unless enabled? && File.exist?(@path)
    data = JSON.parse(File.read(@path))
    host.restore_session_state(data)
    chat = host.chat
    host.apply_request_headers(chat)
    # Re-arm pending follow-ups from their absolute unix deadlines. Format:
    #   { "prowl" => { "due_at" => ..., "task" => ... } }
    # An entry that came DUE during downtime gets a past-due monotonic time
    # and the scheduler fires it on its first tick (correct: the task was
    # already due). Anything else (older formats, bad data, empty task) is
    # simply DISCARDED — no legacy fallbacks.
    n_rearmed = host.plugins[:followups]&.restore(data['followups']) || 0
    messages = data['messages'] || []
    # Keep tool results linked to the current session's assistant calls.
    call_ids = messages.select { |m| m['role'] == 'assistant' && m['tool_calls'].is_a?(Array) }
                       .flat_map { |m| m['tool_calls'].map { |tc| tc['id'] } }.to_set
    messages.each do |m|
      case m['role']
      when 'tool'
        next unless call_ids.include?(m['tool_call_id']) && m['content']
        chat.add_message(role: :tool, content: m['content'], tool_call_id: m['tool_call_id'])
      when 'assistant'
        if m['tool_calls'].is_a?(Array) && !m['tool_calls'].empty?
          calls = m['tool_calls'].filter_map do |tc|
            next unless tc['id'] && tc['name']
            [tc['id'], RubyLLM::ToolCall.new(id: tc['id'], name: tc['name'],
                                             arguments: parse_tool_arguments(tc['arguments']))]
          end.to_h
          next if calls.empty?
          chat.add_message(role: :assistant, content: m['content'], tool_calls: calls)
        elsif m['content']
          chat.add_message(role: :assistant, content: m['content'])
        end
      when 'user'
        next unless m['content']
        chat.add_message(role: :user, content: m['content'])
      end
    end
    puts "[hivemind] session resumed: #{host.console_queue.size} queued console lines, " \
         "#{messages.size} conversation messages" \
         "#{n_rearmed.positive? ? ", #{n_rearmed} follow-ups re-armed" : ''}"
    true
  rescue JSON::ParserError, StandardError => e
    host.log_error('session load failed — starting fresh', e)
    host.clear_console_queue
    false
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

  # The full snapshot: the agent's session state plus what only this file
  # knows (the serialized conversation) and what the followups feature owns.
  # BOTH persist paths must write ALL keys — a partial rewrite (queue-only)
  # used to clobber the persisted conversation whenever a chat line arrived
  # after an ask, losing the session on restart (nothing left for /compact
  # to distill).
  def session_data
    host.session_snapshot.merge(
      'version' => 1,
      # JSON object keyed by timer name — the followups feature owns the
      # entries and hands them over in this shape (the file is ours).
      'followups' => (host.plugins[:followups]&.pending || [])
        .to_h { |f| [f[:name], { 'due_at' => f[:due_at], 'task' => f[:task] }] },
      'messages' => (@messages ||= serialize_messages)
    )
  end

  # Full persist: called after each completion (conversation changed) and
  # from schedule/cancel so a crash between triggers can't lose a scheduled
  # timer. Re-serializes the conversation into the cache reused by
  # persist_queue! (the cheap path must never fall back to stale messages).
  def persist!
    return false unless enabled?
    @messages = serialize_messages
    write_session(session_data)
    true
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
    return false unless enabled?
    # session_data already dups the console queue under its lock (see
    # HivemindAgent#session_snapshot), so there is nothing to unwrap here:
    # the disk write happens OUTSIDE that lock, keeping the packet thread's
    # hold down to a microsecond.
    write_session(session_data)
    true
  end

  def write_session(data)
    @mutex.synchronize do
      tmp = "#{@path}.tmp"
      File.write(tmp, JSON.generate(data))
      File.rename(tmp, @path)
    end
  rescue StandardError => e
    host.log_error('session persist failed', e)
  end

  # Conversation as role/content pairs plus the data needed to rebuild a
  # valid tool round-trip after a restart: assistant tool_calls messages
  # keep their call ids/names/arguments (JSON-encoded), tool messages keep
  # their tool_call_id (the provider rejects a bare tool message without
  # one). The static system prompt is not persisted (re-added on load).
  # Empty tool results (the reply tool halts with '') are KEPT: dropping
  # them orphans the assistant's tool_calls message, and the Responses API
  # rejects the next request ("No tool output found for function call").
  def serialize_messages
    chat = host.chat
    return [] unless chat
    chat.messages.filter_map do |m|
      next if m.role == :system
      case m.role
      when :tool
        c = m.content.to_s
        next if m.tool_call_id.to_s.empty?
        { 'role' => 'tool', 'content' => c, 'tool_call_id' => m.tool_call_id }
      when :assistant
        if m.tool_call?
          # Live assistant messages carry tool_calls as {call_id => ToolCall}.
          calls = m.tool_calls.values
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
