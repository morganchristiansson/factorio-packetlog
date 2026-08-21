#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the Hivemind AI agent (chat history, tools, context).
# Run: ruby -Ilib spec/hivemind_spec.rb

require 'minitest/autorun'
require 'hivemind'

class FakeRcon
  attr_reader :sent
  def initialize
    @sent = []
  end
  def say(text)
    @sent << text
  end
  def player_attributes = []
  def connected_players = []
end

class TestHiveMindAgent < Minitest::Test
  def setup
    @agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: "sk-test", session_path: false, memory_dir: false)
    @agent.online_provider = -> { [] }
    @agent.player_stats_provider = -> { [] }
    # Join greetings are LLM calls; stub so tests don't hit the network.
    @agent.define_singleton_method(:complete) { |_prompt| '' }
  end

  # ── Rolling chat history ──────────────────────────────────────

  def test_on_chat_appends_to_history
    @agent.on_chat('alice', 'hey hivemind')
    @agent.on_chat('bob', 'nice base')
    history = @agent.instance_variable_get(:@console_queue)
    assert_equal [['alice', 'hey hivemind'], ['bob', 'nice base']], history
  end

  # Slash-prefixed lines are commands, not chat: they must not reach the
  # console queue (context) and must not trigger the agent either.
  def test_on_chat_excludes_slash_commands
    @agent.on_chat('alice', '/shout build the mall')
    @agent.on_chat('bob', '/admin')
    @agent.on_chat('carol', ' /give iron-plate')
    assert_empty @agent.instance_variable_get(:@console_queue)

    triggered = @agent.on_chat('dave', '/hivemind what do you see?')
    refute triggered, 'slash commands must not trigger the agent'
  end

  def test_history_ignores_blank_messages
    @agent.send(:append_history, 'alice', '   ')
    assert_empty @agent.instance_variable_get(:@console_queue)
  end

  def test_history_caps_unread_lines_with_eviction
    (HiveMindAgent::HISTORY_SIZE + 5).times { |i| @agent.send(:append_history, 'p', "msg #{i}") }
    history = @agent.instance_variable_get(:@console_queue)
    assert_equal HiveMindAgent::HISTORY_SIZE, history.size
    assert_equal 'msg 5', history.first[1]  # oldest 5 dropped
  end

  def test_reply_tool_appends_history
    tool = HivemindReply.new(rcon: FakeRcon.new,
                           on_sent: ->(t) { @agent.send(:append_history, 'hivemind', t) })
    tool.call('text' => 'bus is at 1k spm')
    assert_equal ['hivemind', 'bus is at 1k spm'], @agent.instance_variable_get(:@console_queue).last
  end

  # ── Encoding hardening (binary-flagged Unicode names) ──────────

  # Regression: a player name decoded from the wire as ASCII-8BIT with
  # high bytes used to taint the context snapshot, then collide with the
  # UTF-8 instruction at prompt assembly (`prompt << instruction`) →
  # Encoding::CompatibilityError, agent aborts mid-ask.
  def test_turn_prompt_survives_binary_flagged_unicode_names
    @agent.online_provider = -> { [{ name: "sévérin".b }] }
    @agent.player_stats_provider = -> { [{ name: "émoji".b, online_time_ticks: 3600, connected: false }] }
    @agent.send(:append_history, "sévérin".b, "talking to the other machine".b)
    @agent.send(:append_history, 'alice', 'another line')

    prompt = @agent.send(:turn_prompt, "In-game chat from morganc: hi\n\nAnswer. Plain text only — no markdown.")
    assert prompt.valid_encoding?, 'assembled prompt must be valid UTF-8'
    assert_equal Encoding::UTF_8, prompt.encoding
    assert_includes prompt, 'sévérin'
    assert_includes prompt, 'émoji'
  end

  def test_on_chat_cleans_binary_flagged_player_name
    @agent.on_chat("sévérin".b, 'hey hivemind')
    player, _msg = @agent.instance_variable_get(:@console_queue).last
    assert_equal Encoding::UTF_8, player.encoding
    assert_equal 'sévérin', player
  end

  def test_unread_console_cleans_persisted_binary_names
    # Entries written by an OLD build (before boundary cleaning) survive
    # hot reloads — unread_console must still produce UTF-8 lines.
    @agent.send(:append_history, "sévérin".b, "legacy binary entry".b)
    lines = @agent.send(:unread_console)
    assert_equal Encoding::UTF_8, lines.first.encoding
    assert_includes lines.first, 'sévérin'
  end

  def test_send_reply_fallback_appends_reply
    @agent.send(:send_reply, 'fallback reply')
    assert_equal ['hivemind', 'fallback reply'], @agent.instance_variable_get(:@console_queue).last
  end

  def test_register_tools_wires_on_sent_callback
    tool = @agent.instance_variable_get(:@chat).tools[:reply]
    assert_kind_of Proc, tool.instance_variable_get(:@on_sent)
  end

  def test_register_tools_includes_followup_tools
    tools = @agent.instance_variable_get(:@chat).tools
    assert tools.key?(:schedule_follow_up), 'schedule_followup tool registered'
    assert tools.key?(:cancel_follow_up), 'cancel_followup tool registered'
  end

  # ── Scheduled follow-ups (timeout tool) ────────────────────────

  def test_schedule_followup_stores_entry_and_returns_id
    result = @agent.schedule_followup(delay_seconds: 60, task: 'check spawn defense')
    assert_match(/Follow-up #\d+ scheduled for \+60s/, result)
    entries = @agent.instance_variable_get(:@followups)
    assert_equal 1, entries.size
    assert_equal 'check spawn defense', entries.first[:task]
    assert_operator entries.first[:due_at], :>, Time.now.to_f, 'absolute unix deadline (for restart re-arm)'
    assert_operator entries.first[:due], :>, Process.clock_gettime(Process::CLOCK_MONOTONIC), 'monotonic due (for firing)'
  end

  def test_schedule_followup_validates_delay_and_task
    assert_match(/minimum delay/, @agent.schedule_followup(delay_seconds: 1, task: 'too soon'))
    assert_match(/positive number/, @agent.schedule_followup(delay_seconds: 0, task: 'zero'))
    assert_match(/empty/, @agent.schedule_followup(delay_seconds: 60, task: '   '))
    assert_empty @agent.instance_variable_get(:@followups)
  end

  def test_schedule_followup_caps_pending
    max = HiveMindAgent::MAX_PENDING_FOLLOWUPS
    max.times { |i| @agent.schedule_followup(delay_seconds: 60, task: "t#{i}") }
    result = @agent.schedule_followup(delay_seconds: 60, task: 'overflow')
    assert_match(/max #{max}/, result)
    assert_equal max, @agent.instance_variable_get(:@followups).size
  end

  def test_cancel_followup_removes_entry
    @agent.schedule_followup(delay_seconds: 60, task: 'check')
    id = @agent.instance_variable_get(:@followups).first[:id]
    assert_match(/cancelled/, @agent.cancel_followup(followup_id: id))
    assert_empty @agent.instance_variable_get(:@followups)
    assert_match(/not found/, @agent.cancel_followup(followup_id: id))
  end

  def test_schedule_tool_wires_into_agent
    tool = ScheduleFollowUp.new(agent: @agent)
    result = tool.call('delay_seconds' => 60, 'task' => 'remind players')
    assert_match(/Follow-up #\d+ scheduled/, result)
    assert_equal 'remind players', @agent.instance_variable_get(:@followups).first[:task]
    # invalid args never reach the agent
    err = ScheduleFollowUp.new(agent: @agent).call('delay_seconds' => -5, 'task' => 'x')
    assert err.is_a?(Hash) || err.to_s.include?('Error') || err.to_s.include?('Invalid')
  end

  def test_fire_followup_runs_turn_with_task_and_fresh_context
    @agent.schedule_followup(delay_seconds: 60, task: 'remind spawn defense')
    @agent.send(:append_history, 'bob', 'biters at the wall!')  # queued since last prompt
    entry = @agent.instance_variable_get(:@followups).first
    prompts = []
    @agent.define_singleton_method(:complete) { |p| prompts << p; 'hold the line' }
    @agent.send(:fire_followup, entry)
    assert_includes prompts.first, 'SCHEDULED FOLLOW-UP'
    assert_includes prompts.first, 'remind spawn defense'
    assert_includes prompts.first, 'biters at the wall!', 'follow-up sees console lines queued since the last prompt'
    assert_includes @agent.instance_variable_get(:@rcon).sent.last, 'hold the line', 'model reply is broadcast'
  end

  def test_fire_followup_stays_silent_when_model_returns_nothing
    @agent.schedule_followup(delay_seconds: 60, task: 'check')
    entry = @agent.instance_variable_get(:@followups).first
    @agent.define_singleton_method(:complete) { |_p| '' }  # model decides nothing needs doing
    @agent.send(:fire_followup, entry)
    assert_empty @agent.instance_variable_get(:@rcon).sent, 'no chat spam when the model stays silent'
  end

  def test_followups_survive_restart
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      a1.online_provider = -> { [] }
      a1.player_stats_provider = -> { [] }
      a1.schedule_followup(delay_seconds: 60, task: 'remind spawn defense')
      a1.send(:persist!)
      data = JSON.parse(File.read(sess))
      assert_equal 1, data['followups'].size, 'follow-up persisted with its deadline'

      a2 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      a2.online_provider = -> { [] }
      a2.player_stats_provider = -> { [] }
      a2.define_singleton_method(:complete) { |_p| '' }
      fups = a2.instance_variable_get(:@followups)
      assert_equal 1, fups.size
      assert_equal 'remind spawn defense', fups.first[:task]
      assert_equal a1.instance_variable_get(:@followups).first[:id], fups.first[:id], 'id preserved'
      assert_operator fups.first[:due], :>, Process.clock_gettime(Process::CLOCK_MONOTONIC), 'remaining delay kept'
    end
  end

  def test_overdue_followup_fires_after_restart
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      a1.online_provider = -> { [] }
      a1.player_stats_provider = -> { [] }
      a1.schedule_followup(delay_seconds: 60, task: 'ping')
      # Rewrite the persisted deadline to the near future (simulates downtime)
      data = JSON.parse(File.read(sess))
      data['followups'] = [[1, Time.now.to_f + 0.4, 'ping']]
      File.write(sess, JSON.generate(data))

      a2 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      a2.online_provider = -> { [] }
      a2.player_stats_provider = -> { [] }
      a2.define_singleton_method(:complete) { |_p| '' }
      deadline = Time.now + 3
      sleep 0.05 until a2.instance_variable_get(:@followups).empty? || Time.now > deadline
      assert_empty a2.instance_variable_get(:@followups), 're-armed follow-up fired by the scheduler'
    end
  end

  def test_clear_session_cancels_pending_followups
    @agent.schedule_followup(delay_seconds: 60, task: 'remind')
    assert @agent.clear_session!
    assert_empty @agent.instance_variable_get(:@followups)
  end

  # The follow-up scheduler thread must survive hot reloads: the agent
  # object persists while code is reloaded, but a thread that died (or was
  # never started) is revived at the sniffer's reconstruction seam via
  # ensure_followup_scheduler.
  def test_hot_reloaded_agent_gets_scheduler_revived_at_seam
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.instance_variable_get(:@scheduler)&.kill
    agent.instance_variable_get(:@scheduler)&.join(0.1)

    agent.ensure_followup_scheduler
    assert agent.instance_variable_get(:@scheduler)&.alive?, 'scheduler started at the seam'

    class << agent
      def complete(_p) = '' # never hit the network
    end
    result = agent.schedule_followup(delay_seconds: 30, task: 'post-reload check')
    assert_match(/scheduled/, result)
    assert_equal 'post-reload check', agent.instance_variable_get(:@followups).first[:task]
    agent.send(:persist!)  # the exact crash from the live run
    assert agent.send(:compaction_material).include?('Pending scheduled follow-ups:')
    assert agent.clear_session!
    assert_empty agent.instance_variable_get(:@followups)
  end

  def test_compaction_material_lists_pending_followups
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.online_provider = -> { [] }
      agent.player_stats_provider = -> { [] }
      agent.schedule_followup(delay_seconds: 60, task: 'check the mall')
      material = agent.send(:compaction_material)
      assert_includes material, 'Pending scheduled follow-ups:'
      assert_includes material, 'check the mall'
    end
  end

  # ── Session persistence (restart-safe) ─────────────────────────

  def test_session_persists_and_restores_across_restart
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      a1.online_provider = -> { [] }
      a1.player_stats_provider = -> { [] }
      a1.on_chat('alice', 'goals: build the bus first')
      a1.on_player_event(:joined, 'bob')
      a1.instance_variable_get(:@chat).add_message(role: :user, content: 'turn: what is the bus?')
      a1.instance_variable_get(:@chat).add_message(role: :assistant, content: 'the bus is at 1k spm')
      a1.send(:persist!)
      assert File.exist?(sess), 'session file written'

      # fresh agent = a restart
      a2 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      assert_equal [['alice', 'goals: build the bus first'], [nil, 'bob joined the game']],
                   a2.instance_variable_get(:@console_queue)
      texts = a2.instance_variable_get(:@chat).messages.map { |m| [m.role, m.content.to_s] }
      assert_includes texts, [:user, 'turn: what is the bus?']
      assert_includes texts, [:assistant, 'the bus is at 1k spm']
      assert a2.instance_variable_get(:@chat).messages.any? { |m| m.role == :system }
    end
  end

  def test_corrupt_session_starts_fresh
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      File.write(sess, '{broken json')
      a = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      assert_empty a.instance_variable_get(:@console_queue)
    end
  end

  # Regression: tool messages persisted without their link to the assistant
  # tool_calls message were restored bare, and the provider rejected the
  # next request (“missing field tool_call_id”). The round-trip must
  # preserve tool_calls ids/arguments and tool_call_id.
  def test_session_roundtrips_tool_calls
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      chat = a1.instance_variable_get(:@chat)
      chat.add_message(role: :user, content: 'turn: how many players?')
      # Live assistant messages carry tool_calls as {call_id => ToolCall}.
      chat.add_message(role: :assistant, content: nil,
                       tool_calls: { 'call_1' => RubyLLM::ToolCall.new(id: 'call_1', name: 'rcon_query',
                                                                       arguments: { 'cmd' => '/players' }) })
      chat.add_message(role: :tool, content: 'morganc, Petricko93', tool_call_id: 'call_1')
      chat.add_message(role: :assistant, content: 'nine players')
      a1.send(:persist!)
      assert File.exist?(sess), 'session file written'

      # Restart: the assistant tool_calls message and the tool result must
      # come back LINKED (tool_call_id → the tool_calls id).
      a2 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      msgs = a2.instance_variable_get(:@chat).messages
      asst = msgs.find { |m| m.tool_call? }
      refute_nil asst, 'assistant tool_calls message restored'
      assert asst.tool_calls.is_a?(Hash), 'tool_calls restored in gem shape (hash keyed by id)'
      assert_equal 'call_1', asst.tool_calls['call_1'].id
      assert_equal 'rcon_query', asst.tool_calls['call_1'].name
      assert_equal({ 'cmd' => '/players' }, asst.tool_calls['call_1'].arguments)
      tool = msgs.find { |m| m.role == :tool }
      refute_nil tool, 'tool result restored'
      assert_equal 'call_1', tool.tool_call_id
      assert_equal 'morganc, Petricko93', tool.content.to_s
      assert_includes msgs.map { |m| [m.role, m.content.to_s] }, [:assistant, 'nine players']

      # persist → restore → persist is byte-stable (no drift on reload).
      file_after = JSON.parse(File.read(sess))
      assert_equal file_after['messages'], a2.send(:serialize_messages),
                   'round-trip is stable'
    end
  end

  # Regression: invalid UTF-8 from the wire crashed strip/regex
  # (ArgumentError / Encoding::CompatibilityError). Must be scrubbed.
  def test_invalid_utf8_chat_does_not_crash
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    agent.on_chat('alice', "hivemind ".b + "\xFF\xFE".b + "testing".b)            # binary-flagged
    agent.on_chat('bob', ("hi".b + "\xFF".b).force_encoding('UTF-8'))              # utf8-flagged invalid
    queue = agent.instance_variable_get(:@console_queue)
    assert queue.all? { |_, m| m.valid_encoding? }, 'queued messages are valid UTF-8'
    assert_includes queue.first[1], 'hivemind'
  end

  # ── Context ───────────────────────────────────────────────────

  def test_system_prompt_is_static
    # The system prompt is personality/rules only — dynamic context lives
    # in the per-turn user prompt (turn_prompt).
    sp = HiveMindAgent::SYSTEM_PROMPT
    refute_includes sp, 'Current context:'
    refute_includes sp, 'Currently online players:'
  end

  def test_system_prompt_enforces_gps_rich_text
    # Coordinates must always be Factorio rich-text GPS tags ([gps=x,y]) —
    # clickable in game — never bare numbers, and never with a label or
    # extra parameters.
    sp = HiveMindAgent::SYSTEM_PROMPT.gsub(/\s+/, ' ')  # heredoc line-wrap tolerant
    assert_includes sp, '[gps=x,y]'
    assert_includes sp, 'clickable'
    assert_includes sp, 'Never write coordinates as bare numbers'
    assert_includes sp, 'no label, no surface, no extra parameters'
  end

  def test_turn_prompt_includes_snapshot_and_console
    @agent.on_player_event(:joined, 'alice')
    @agent.on_player_event(:left, 'bob')
    prompt = @agent.send(:turn_prompt, 'INSTRUCTION')
    assert_includes prompt, 'INSTRUCTION'
    assert_includes prompt, 'alice joined the game'
    assert_includes prompt, 'bob left the game'
  end

  def test_context_snapshot_includes_online_and_stats
    @agent.online_provider = -> { ['alice'] }
    @agent.player_stats_provider = -> { [{ name: 'alice', index: 1, connected: true, admin: true, online_time_ticks: 5_040_000 }] }
    snap = @agent.send(:context_snapshot)
    assert_includes snap, 'Currently online players: alice (1 players).'
    assert_includes snap, 'alice: 23h20m (admin)'
  end

  def test_context_snapshot_empty_without_providers
    assert_empty @agent.send(:context_snapshot)
  end

  def test_on_player_event_appends_join_and_leave
    @agent.on_player_event(:joined, 'alice')
    @agent.on_player_event(:left, 'bob')
    history = @agent.instance_variable_get(:@console_queue)
    # join event, then the leave (greeting is stubbed to send nothing)
    assert_equal [nil, 'alice joined the game'], history[0]
    assert_equal [nil, 'bob left the game'], history[1]
    lines = @agent.send(:unread_console)
    assert_includes lines, 'alice joined the game'
    assert_includes lines, 'bob left the game'
  end

  # Join lines carry the player's total play time from RCON (online_time,
  # ticks) — formatted as days/hours like the context snapshot.
  def test_on_player_event_includes_playtime_from_rcon
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 2, name: 'alice', connected: true, admin: false, online_time: 11_016_000, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    agent.define_singleton_method(:complete) { |_p| '' }
    agent.on_player_event(:joined, 'alice')
    assert_equal [nil, 'alice joined the game (2d3h played)'],
                 agent.instance_variable_get(:@console_queue)[0]
  end

  # No RCON attrs for the player (fresh server / query miss): fall back to
  # the mirrored provider snapshot.
  def test_on_player_event_playtime_falls_back_to_provider
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [{ name: 'bob', index: 3, connected: true, admin: false, online_time_ticks: 5_184_000 }] }
    agent.define_singleton_method(:complete) { |_p| '' }
    agent.on_player_event(:joined, 'bob')
    assert_equal [nil, 'bob joined the game (1d0h played)'],
                 agent.instance_variable_get(:@console_queue)[0]
  end

  def test_format_ticks_compact_human_durations
    assert_equal '12m', @agent.send(:format_ticks, 43_200)
    assert_equal '2m', @agent.send(:format_ticks, 7_200)
    assert_equal '8h30m', @agent.send(:format_ticks, 1_836_000)
    assert_equal '10h', @agent.send(:format_ticks, 2_160_000)   # trailing 0m dropped
    assert_equal '1d0h', @agent.send(:format_ticks, 5_184_000)  # exactly one day
    assert_equal '2d3h', @agent.send(:format_ticks, 11_016_000) # zero minutes dropped
    assert_equal '0m', @agent.send(:format_ticks, 0)
  end

  def test_on_player_event_ignores_blank_name
    @agent.on_player_event(:joined, '  ')
    assert_empty @agent.instance_variable_get(:@console_queue)
  end

  # ── Incremental console lines in prompts ──────────────────────

  def capture_prompt(agent, &block)
    seen = nil
    agent.define_singleton_method(:complete) { |p| seen = p; '' }
    block.call
    seen
  end

  def test_ask_llm_includes_new_console_lines
    @agent.on_chat('bob', 'nice rail setup')
    prompt = capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind what is the bus?') }
    assert_includes prompt, 'bob: nice rail setup'
    assert_includes prompt, 'In-game chat from alice: hivemind what is the bus?'
  end

  def test_ask_llm_does_not_repeat_previous_prompt_lines
    @agent.on_chat('bob', 'nice rail setup')
    capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind first?') }
    @agent.on_chat('carol', 'anyone have iron?')
    prompt2 = capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind second?') }
    assert_includes prompt2, 'carol: anyone have iron?'
    refute_includes prompt2, 'nice rail setup'   # already sent in the first prompt
    refute_includes prompt2, 'hivemind first?'   # the first trigger
  end

  def test_ask_llm_excludes_trigger_line_from_console_list
    prompt = capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind the bus?') }
    # the trigger is stated explicitly, not repeated in the console list
    refute_includes prompt, 'New console lines'
    assert_equal 1, prompt.scan('hivemind the bus?').size
  end

  def test_unread_console_excludes_hivemind_replies
    @agent.on_chat('alice', 'hey')
    @agent.send(:append_history, 'hivemind', 'greetings')
    lines = @agent.send(:unread_console)
    assert_includes lines, 'alice: hey'
    refute_includes lines, 'hivemind: greetings'  # lives in the conversation
  end

  def test_unread_console_advances_pointer
    @agent.send(:append_history, 'alice', 'one')
    first = @agent.send(:unread_console)
    assert_equal ['alice: one'], first
    assert_empty @agent.send(:unread_console)  # queue drained
    @agent.send(:append_history, 'bob', 'two')
    assert_equal ['bob: two'], @agent.send(:unread_console)
  end

  def test_lines_survive_across_prompts_and_eviction
    # Regression: a ring buffer with a sent-pointer silently LOST the
    # newest lines once eviction from the front desynchronized the pointer
    # — goals written in console never reached Hivemind. The queue drains
    # on send, so every line reaches the model exactly once, in order.
    20.times { |i| @agent.send(:append_history, 'p', "before #{i}") }
    prompt1 = @agent.send(:unread_console)  # drains 20
    assert_equal 20, prompt1.size
    assert_includes prompt1, 'p: before 0'

    10.times { |i| @agent.send(:append_history, 'p', "goal #{i}") }
    prompt2 = @agent.send(:unread_console)  # must include ALL 10 new lines
    assert_equal 10, prompt2.size
    assert_includes prompt2, 'p: goal 0'
    assert_includes prompt2, 'p: goal 9'
    assert_empty @agent.send(:unread_console)
  end

  def test_unread_console_clips_long_lines
    @agent.send(:append_history, 'alice', 'x' * 500)
    line = @agent.send(:unread_console).first
    assert_operator line.length, :<=, HiveMindAgent::HISTORY_LINE_LEN + 20
  end

  def test_ask_llm_includes_events
    @agent.on_player_event(:joined, 'alice')
    prompt = capture_prompt(@agent) { @agent.send(:ask_llm, 'bob', 'hivemind hi') }
    assert_includes prompt, 'alice joined the game'
  end

  # ── Join greeting (LLM-generated) ─────────────────────────────

  def test_join_greeting_uses_llm_and_sends
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome, alice. The belts are quiet without you.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2  # greeting runs off-thread
    assert_includes seen_prompt, 'alice just joined'
    assert_includes rcon.sent, 'Hivemind> Welcome, alice. The belts are quiet without you.'
  end

  # Joins present the RCON playtime to the model twice: in the console
  # line (excluded from the per-turn feed since the instruction states it)
  # and explicitly in the greeting instruction.
  def test_join_greeting_prompt_includes_playtime
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 2, name: 'alice', connected: true, admin: false, online_time: 11_016_000, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome, alice.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_includes seen_prompt, 'alice just joined'
    assert_includes seen_prompt, 'they have played 2d3h in total'
    # The console line itself is excluded: the event must reach the model
    # ONLY through the instruction, never twice.
    refute_includes seen_prompt, 'alice joined the game (2d3h played)'
  end

  def test_join_greeting_prompt_omits_playtime_when_unknown
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome, alice.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    refute_includes seen_prompt, ' they have played '
  end

  def test_join_greeting_recorded_in_history
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.define_singleton_method(:complete) do |_prompt|
      clean_reply('Welcome, alice. The factory is watching.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_equal ['hivemind', 'Welcome, alice. The factory is watching.'],
                 agent.instance_variable_get(:@console_queue).last
  end

  def test_join_greeting_respects_greet_interval
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.define_singleton_method(:complete) { |_p| clean_reply('hi') }
    agent.instance_variable_set(:@last_greet, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_empty rcon.sent
  end

  def test_leave_does_not_greet
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.on_player_event(:left, 'alice')
    assert_empty rcon.sent
  end

  # ── Extra trigger: "good bot" ───────────────────────────────────
  # Production replies are LLM-generated in character (same ask_llm path as
  # "hivemind" mentions) — NEVER a canned/template string. The tests below
  # stub the model and assert the trigger reaches the LLM with the message.

  def test_good_bot_triggers_reply
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    asked = nil
    agent.define_singleton_method(:complete) { |p| asked = p; '' }
    agent.on_chat('alice', 'good bot')
    sleep 0.2  # LLM call runs off-thread
    refute_nil asked, 'good bot should reach the LLM'
    assert_includes asked, 'In-game chat from alice: good bot'
  end

  def test_good_bot_variants_are_triggers
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    asks = 0
    agent.define_singleton_method(:complete) { |_p| asks += 1; '' }
    ['Good bot!', 'goodbot', 'GOOD BOT'].each { |m| agent.on_chat('bob', m); sleep 0.2 }
    assert_equal 1, asks, 'each variant pings (rate limiter collapses rapid-fire to one)'
  end

  def test_different_players_not_rate_limited_sequential_turns
    # The rate limiter is PER-PLAYER: another player triggering right after
    # a reply must get their own turn (queued on the complete mutex, so
    # sequential and seeing the prior Q&A) — never dropped just because
    # someone else asked recently.
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    asked = []
    agent.define_singleton_method(:complete) do |p|
      asked << p
      sleep 0.05            # simulate the slow LLM call so ordering shows
      ''
    end
    agent.on_chat('alice', 'hivemind hi')
    agent.on_chat('bob', 'hivemind hello')
    sleep 0.4
    assert_equal 2, asked.size, 'different players each get a turn'
    assert_includes asked.join, 'In-game chat from alice: hivemind hi'
    assert_includes asked.join, 'In-game chat from bob: hivemind hello'

    # same player again within the window is still collapsed (anti-spam),
    # using a fresh player so the first trigger is outside any old window
    asks2 = 0
    agent.define_singleton_method(:complete) { |_p| asks2 += 1; '' }
    agent.on_chat('carol', 'hivemind again')
    agent.on_chat('carol', 'hivemind stop')
    sleep 0.4
    assert_equal 1, asks2, 'same-player spam still collapses to one ask'
  end

  def test_triggers_constant_lists_all_phrases
    %w[hivemind good\ bot goodbot hm].each do |t|
      assert_includes HiveMindAgent::TRIGGERS, t
    end
  end

  # ── Word-boundary trigger: "hm" ────────────────────────────────
  # "hm" is too short for the substring match used for "hivemind"/"good
  # bot" (it would page on "shmoose"), so it fires only as a standalone
  # word, case-insensitively: "hm, hello", "HM: hello", "wdyt? hm".
  def test_hm_word_trigger_matches_standalone_word
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    ['hm', 'hm, hello', 'HM, hello', 'HM: hello', 'wdyt? hm', 'hi hm here',
     'hello-hm', 'hm!', 'say hm.', "[hm]"].each do |m|
      assert agent.send(:trigger_match?, m), "expected #{m.inspect} to trigger"
    end
  end

  def test_hm_does_not_trigger_on_substrings
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    ['shmoose', 'shmoo', 'hmm', 'hmm, hello', 'ahm', 'hmx', 's-h-m-oose'].each do |m|
      refute agent.send(:trigger_match?, m), "expected #{m.inspect} NOT to trigger"
    end
  end

  def test_hm_trigger_reaches_llm
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    asked = nil
    agent.define_singleton_method(:complete) { |p| asked = p; '' }
    agent.on_chat('alice', 'wdyt? hm')
    sleep 0.2
    refute_nil asked, 'standalone "hm" should reach the LLM'
  end

  def test_shmoose_does_not_trigger
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    called = false
    agent.define_singleton_method(:complete) { |_p| called = true; '' }
    agent.on_chat('alice', 'shmoose is back')
    sleep 0.2
    refute called, '"shmoose" must not page the agent'
  end

  # ── Long-term memory (keyed blobs, compaction) ─────────────────

  def test_soal_seeded_on_first_run_only
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      store = agent.instance_variable_get(:@memory_store)
      assert_equal HiveMindAgent::DEFAULT_SOUL, store.soul, 'SOUL seeded from the default personality'
      # An existing/edited SOUL is never overwritten by a new process.
      store.write_soul('the factory regained its voice')
      HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      assert_equal 'the factory regained its voice', store.soul
    end
  end

  def test_system_prompt_includes_soul_and_knowledge
    Dir.mktmpdir do |dir|
      # Seed BEFORE init so the applied system prompt (built at configure_llm)
      # reflects the store at conversation creation.
      store = MemoryStore.new(dir)
      store.seed('soul', 'my custom soul')
      store.write_knowledge('the bus feeds the mall')
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      sys = agent.instance_variable_get(:@chat).messages.find { |m| m.role == :system }
      content = sys.content.to_s
      # SOUL (personality) and KNOWLEDGE (facts) live in the SYSTEM prompt
      # (not the per-turn user prompt) — cached once per conversation.
      assert_includes content, 'my custom soul'
      assert_includes content, '=== SOUL ==='
      assert_includes content, 'the bus feeds the mall'
      assert_includes content, '=== KNOWLEDGE ==='
      # the static mechanics are still there too
      assert_includes content, 'rcon_query'
    end
  end

  def test_turn_prompt_injects_player_memory_with_dedup
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.online_provider = -> { [] }
      agent.player_stats_provider = -> { [] }
      store = agent.instance_variable_get(:@memory_store)
      store.write_player('alice', 'alice is building the mall')

      p1 = agent.send(:turn_prompt, 'INSTRUCTION ONE', player: 'alice')
      assert_includes p1, 'Persistent player memories:'
      assert_includes p1, '=== memory of alice ==='
      assert_includes p1, 'alice is building the mall'
      assert_equal 1, p1.scan('alice is building the mall').size
      refute_includes p1, '=== SOUL ==='  # globals ride in the system prompt, not per turn

      # Same player again this session: their memory was already delivered
      # (it sits in the conversation now) — no repeat.
      p2 = agent.send(:turn_prompt, 'INSTRUCTION TWO', player: 'alice')
      refute_includes p2, '=== memory of alice ==='

      # A different player still gets their own memory.
      store.write_player('bob', 'bob guards the iron')
      p3 = agent.send(:turn_prompt, 'INSTRUCTION THREE', player: 'bob')
      assert_includes p3, '=== memory of bob ==='
      assert_includes p3, 'bob guards the iron'
    end
  end

  # Already-online players never fire a join event, so a fresh session must
  # seed their memories from the roster — otherwise they'd be unreachable.
  def test_fresh_session_seeds_online_players_memories
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.online_provider = -> { ['alice', 'carol'] }
      agent.player_stats_provider = -> { [] }
      store = agent.instance_variable_get(:@memory_store)
      store.write_player('alice', 'alice builds malls')
      store.write_player('carol', 'carol hoards circuits')
      store.write_player('bob', 'bob is offline')  # not online — not seeded

      prompt = agent.send(:turn_prompt, 'INSTRUCTION')
      assert_includes prompt, '=== memory of alice ==='
      assert_includes prompt, '=== memory of carol ==='
      refute_includes prompt, 'bob is offline'

      # second turn: the roster was already delivered — no repeats
      prompt2 = agent.send(:turn_prompt, 'INSTRUCTION 2')
      refute_includes prompt2, '=== memory of'
    end
  end

  def test_ask_llm_injects_triggering_players_memory
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.online_provider = -> { [] }
      agent.player_stats_provider = -> { [] }
      agent.instance_variable_get(:@memory_store).write_player('alice', 'alice owes the factory a rocket')
      prompt = capture_prompt(agent) { agent.send(:ask_llm, 'alice', 'hivemind whats my build plan?') }
      assert_includes prompt, '=== memory of alice ==='
      assert_includes prompt, 'alice owes the factory a rocket'
    end
  end

  def test_join_greeting_includes_player_memory
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.online_provider = -> { [] }
      agent.player_stats_provider = -> { [] }
      agent.instance_variable_get(:@memory_store).write_player('alice', 'alice once nuked the bus on purpose')
      seen_prompt = nil
      agent.define_singleton_method(:complete) do |prompt|
        seen_prompt = prompt
        clean_reply('Welcome.')
      end
      agent.on_player_event(:joined, 'alice')
      sleep 0.2
      assert_includes seen_prompt, 'alice just joined'
      assert_includes seen_prompt, '=== memory of alice ==='
      assert_includes seen_prompt, 'alice once nuked the bus on purpose'
    end
  end

  def test_join_greeting_includes_admin_status
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 2, name: 'alice', connected: true, admin: true, online_time: 11_016_000, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_includes seen_prompt, 'they have played 2d3h in total and are an admin'
  end

  def test_join_greeting_states_non_admin
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 3, name: 'bob', connected: true, admin: false, online_time: 7_200, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome.')
    end
    agent.on_player_event(:joined, 'bob')
    sleep 0.2
    assert_includes seen_prompt, 'they have played 2m in total and are not an admin'
  end

  def test_write_memories_tool_batches_all_keys
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      tool = WriteMemories.new(store: store)
      result = tool.call('memories' => [
        { 'key' => 'soul', 'content' => 'new soul' },
        { 'key' => 'knowledge', 'content' => 'the mall was built' },
        { 'key' => 'alice', 'content' => 'alice built the mall' },
        { 'key' => 'bob', 'content' => 'bob stomped the belts' }
      ])
      assert_kind_of RubyLLM::Tool::Halt, result
      assert_equal 'new soul', store.soul
      assert_equal 'the mall was built', store.knowledge
      assert_equal 'alice built the mall', store.player('alice')
      assert_equal 'bob stomped the belts', store.player('bob')
      assert_equal [['soul', 'new soul'], ['knowledge', 'the mall was built'],
                    ['alice', 'alice built the mall'], ['bob', 'bob stomped the belts']],
                   tool.written
    end
  end

  def test_write_memories_tool_skips_bad_entries
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      tool = WriteMemories.new(store: store)
      result = tool.call('memories' => [
        { 'key' => '', 'content' => 'no key' },
        { 'key' => 'soul', 'content' => 'fine' },
        { 'key' => 'alice', 'content' => 'player fine' }
      ])
      assert_equal [['soul', 'fine'], ['alice', 'player fine']], tool.written
      assert_equal 'fine', store.soul
      assert_equal 'player fine', store.player('alice')
    end
  end

  def test_players_seen_covers_every_source_including_join_leave_only
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.online_provider = -> { [{ name: 'zoe' }] }
    agent.player_stats_provider = -> { [] }
    # chat lines (player field set)
    agent.send(:append_history, 'alice', 'hello')
    agent.send(:append_history, 'bob', 'i will build a mall')
    # join/leave lines: name lives in the MESSAGE text, player field nil
    agent.send(:append_history, nil, 'carol joined the game')
    agent.send(:append_history, nil, 'dave left the game')
    # memory injected this session
    agent.instance_variable_get(:@memories_sent) << 'erin'
    # existing on-disk player memory
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      store.write_player('frank', 'frank likes trains')
      agent.instance_variable_set(:@memory_store, store)
      seen = agent.send(:players_seen)
      %w[alice bob carol dave erin frank zoe].each do |name|
        assert_includes seen, name, "expected #{name} to be seen"
      end
    end
  end

  def test_compact_memory_runs_inside_live_chat_with_batched_tool
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.online_provider = -> { [] }
      agent.player_stats_provider = -> { [] }
      chat = agent.instance_variable_get(:@chat)
      chat.add_message(role: :user, content: 'turn: alice wants to build a mall')
      chat.add_message(role: :assistant, content: 'the mall will feed the factory')
      agent.send(:append_history, 'alice', 'i will build the mall')
      pre_size = chat.messages.size

      # Compaction reuses the LIVE chat (input-token cache); stub only the
      # parts that would hit the network, and simulate the tool-call + result
      # messages the real ask would append (which compaction must strip).
      seen = { instructions: [], tools: [], material: nil }
      chat.define_singleton_method(:with_instructions) { |t| seen[:instructions] << t; self }
      chat.define_singleton_method(:with_tool) { |t| seen[:tools] << t; self }
      chat.define_singleton_method(:ask) do |material|
        seen[:material] = material
        add_message(role: :user, content: material)         # compaction material
        add_message(role: :assistant, content: nil, tool_calls: {}) # tool-call turn
        add_message(role: :tool, content: 'soul updated', tool_call_id: 'c1')
      end

      assert agent.compact_memory!('quit'), 'compaction runs'

      assert_equal 1, seen[:tools].size, 'only write_memories — never say/rcon_query'
      assert_kind_of WriteMemories, seen[:tools].first
      # compaction swapped its own system prompt in, then restored the live one
      assert_includes seen[:instructions].first, 'write_memories'
      assert_includes seen[:instructions].first, 'Batch ALL updates into ONE'
      assert_includes seen[:instructions].last, 'Persistent memories'  # restored live prompt
      # material = current memories + console + context; the conversation
      # thread itself is already in the chat (not duplicated in the material)
      assert_includes seen[:material], 'Current memories:'
      assert_includes seen[:material], '=== soul ==='
      assert_includes seen[:material], 'Console lines:'
      assert_includes seen[:material], 'alice: i will build the mall'
      assert_includes seen[:material], 'Players encountered this session'
      assert_includes seen[:material], 'alice'          # from the console line
      refute_includes seen[:material], 'Session conversation:'
      # compaction stripped its own messages: the live thread is unchanged
      assert_equal pre_size, chat.messages.size
      # and write_memories is gone from the live toolset
      refute_includes chat.tools.keys, :write_memories
      assert chat.tools.key?(:reply)
      assert chat.tools.key?(:rcon_query)
    end
  end

  def test_compact_skips_empty_session
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      refute agent.compact_memory!, 'nothing to compact'
      refute agent.send(:compactable?)
    end
  end

  # ── Token usage logging ──────────────────────────────────────

  def test_usage_line_formats_cache_metrics
    msg = RubyLLM::Message.new(role: :assistant, content: 'ok',
                               tokens: RubyLLM::Tokens.build(input: 2400, cached: 1800,
                                                              cache_creation: 200, output: 400,
                                                              thinking: 30))
    assert_equal ' (2400 in, 1800 cached, 200 written, 400 out, 30 think)', @agent.send(:usage_line, msg)
  end

  def test_usage_line_omits_absent_and_zero_metrics
    msg = RubyLLM::Message.new(role: :assistant, content: 'hi',
                               tokens: RubyLLM::Tokens.build(input: 100, output: 20, cached: 0))
    assert_equal ' (100 in, 20 out)', @agent.send(:usage_line, msg)
    assert_equal '', @agent.send(:usage_line, RubyLLM::Message.new(role: :assistant, content: 'no tokens'))
  end

  def test_clear_session_forgets_but_keeps_memories
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: dir)
      agent.online_provider = -> { [] }
      agent.player_stats_provider = -> { [] }
      store = agent.instance_variable_get(:@memory_store)
      store.write_player('alice', 'alice loves belts')
      agent.send(:append_history, 'alice', 'hello hivemind')
      agent.instance_variable_get(:@chat).add_message(role: :user, content: 'turn: one')

      assert agent.clear_session!
      chat = agent.instance_variable_get(:@chat)
      assert_empty chat.messages.reject { |m| m.role == :system }, 'conversation wiped'
      assert_empty agent.instance_variable_get(:@console_queue)
      assert_empty agent.instance_variable_get(:@recent_console)
      assert_equal 'alice loves belts', store.player('alice'), 'memories kept'
      # persisted session file is wiped too
      assert_empty JSON.parse(File.read(sess))['messages']
    end
  end
end
