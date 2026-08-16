#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the Hivemind AI agent (chat history, tools, context).
# Run: ruby -Ilib spec/ai_agent_spec.rb

require 'minitest/autorun'
require 'ai_agent'

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
    @agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: "sk-test", session_path: false)
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

  def test_hivemind_say_tool_appends_reply
    tool = HivemindSay.new(rcon: FakeRcon.new,
                           on_sent: ->(t) { @agent.send(:append_history, 'hivemind', t) })
    tool.call('text' => 'bus is at 1k spm')
    assert_equal ['hivemind', 'bus is at 1k spm'], @agent.instance_variable_get(:@console_queue).last
  end

  def test_send_reply_fallback_appends_reply
    @agent.send(:send_reply, 'fallback reply')
    assert_equal ['hivemind', 'fallback reply'], @agent.instance_variable_get(:@console_queue).last
  end

  def test_register_tools_wires_on_sent_callback
    tool = @agent.instance_variable_get(:@chat).tools[:hivemind_say]
    assert_kind_of Proc, tool.instance_variable_get(:@on_sent)
  end

  # ── Session persistence (restart-safe) ─────────────────────────

  def test_session_persists_and_restores_across_restart
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess)
      a1.online_provider = -> { [] }
      a1.player_stats_provider = -> { [] }
      a1.on_chat('alice', 'goals: build the bus first')
      a1.on_player_event(:joined, 'bob')
      a1.instance_variable_get(:@chat).add_message(role: :user, content: 'turn: what is the bus?')
      a1.instance_variable_get(:@chat).add_message(role: :assistant, content: 'the bus is at 1k spm')
      a1.instance_variable_set(:@exchanges, 3)
      a1.send(:persist!)
      assert File.exist?(sess), 'session file written'

      # fresh agent = a restart
      a2 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess)
      assert_equal [['alice', 'goals: build the bus first'], [nil, 'bob joined the game']],
                   a2.instance_variable_get(:@console_queue)
      assert_equal 3, a2.instance_variable_get(:@exchanges)
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
      a = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess)
      assert_empty a.instance_variable_get(:@console_queue)
      assert_equal 0, a.instance_variable_get(:@exchanges)
    end
  end

  # Regression: invalid UTF-8 from the wire crashed strip/regex
  # (ArgumentError / Encoding::CompatibilityError). Must be scrubbed.
  def test_invalid_utf8_chat_does_not_crash
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false)
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
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false)
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

  def test_join_greeting_recorded_in_history
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false)
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
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false)
    agent.define_singleton_method(:complete) { |_p| clean_reply('hi') }
    agent.instance_variable_set(:@last_greet, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_empty rcon.sent
  end

  def test_leave_does_not_greet
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false)
    agent.on_player_event(:left, 'alice')
    assert_empty rcon.sent
  end

  # ── Extra trigger: "good bot" ───────────────────────────────────
  # Production replies are LLM-generated in character (same ask_llm path as
  # "hivemind" mentions) — NEVER a canned/template string. The tests below
  # stub the model and assert the trigger reaches the LLM with the message.

  def test_good_bot_triggers_reply
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false)
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
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false)
    agent.online_provider = -> { [] }
    agent.player_stats_provider = -> { [] }
    asks = 0
    agent.define_singleton_method(:complete) { |_p| asks += 1; '' }
    ['Good bot!', 'goodbot', 'GOOD BOT'].each { |m| agent.on_chat('bob', m); sleep 0.2 }
    assert_equal 1, asks, 'each variant pings (rate limiter collapses rapid-fire to one)'
  end

  def test_trigger_label_includes_extras
    assert_includes @agent.trigger_label, 'hivemind'
    assert_includes @agent.trigger_label, 'good bot'
  end
end
