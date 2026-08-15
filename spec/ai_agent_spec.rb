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
    @agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test')
    @agent.online_provider = -> { [] }
    @agent.player_stats_provider = -> { [] }
    # Join greetings are LLM calls; stub so tests don't hit the network.
    @agent.define_singleton_method(:complete) { |_prompt| '' }
  end

  # ── Rolling chat history ──────────────────────────────────────

  def test_on_chat_appends_to_history
    @agent.on_chat('alice', 'hey hivemind')
    @agent.on_chat('bob', 'nice base')
    history = @agent.instance_variable_get(:@chat_history)
    assert_equal [['alice', 'hey hivemind'], ['bob', 'nice base']], history
  end

  def test_history_ignores_blank_messages
    @agent.send(:append_history, 'alice', '   ')
    assert_empty @agent.instance_variable_get(:@chat_history)
  end

  def test_history_is_a_ring_buffer
    HiveMindAgent::HISTORY_SIZE.times { |i| @agent.send(:append_history, 'p', "msg #{i}") }
    history = @agent.instance_variable_get(:@chat_history)
    assert_equal HiveMindAgent::HISTORY_SIZE, history.size
    assert_equal 'msg 0', history.first[1]
  end

  def test_hivemind_say_tool_appends_reply
    tool = HivemindSay.new(rcon: FakeRcon.new,
                           on_sent: ->(t) { @agent.send(:append_history, 'hivemind', t) })
    tool.call('text' => 'bus is at 1k spm')
    assert_equal ['hivemind', 'bus is at 1k spm'], @agent.instance_variable_get(:@chat_history).last
  end

  def test_send_reply_fallback_appends_reply
    @agent.send(:send_reply, 'fallback reply')
    assert_equal ['hivemind', 'fallback reply'], @agent.instance_variable_get(:@chat_history).last
  end

  def test_register_tools_wires_on_sent_callback
    tool = @agent.instance_variable_get(:@chat).tools[:hivemind_say]
    assert_kind_of Proc, tool.instance_variable_get(:@on_sent)
  end

  # ── Context ───────────────────────────────────────────────────

  def test_system_prompt_includes_recent_chat
    @agent.on_chat('alice', 'hey hivemind, whats the bus?')
    sp = @agent.send(:system_prompt)
    assert_includes sp, 'Recent console (hivemind = you; joins/leaves included):'
    assert_includes sp, 'alice: hey hivemind, whats the bus?'
  end

  def test_system_prompt_omits_history_when_empty
    refute_includes @agent.send(:system_prompt), 'Recent console (hivemind = you'
  end

  def test_on_player_event_appends_join_and_leave
    @agent.on_player_event(:joined, 'alice')
    @agent.on_player_event(:left, 'bob')
    history = @agent.instance_variable_get(:@chat_history)
    # join event, then the leave (greeting is stubbed to send nothing)
    assert_equal [nil, 'alice joined the game'], history[0]
    assert_equal [nil, 'bob left the game'], history[1]
    lines = @agent.send(:chat_history_lines)
    assert_includes lines, '  alice joined the game'
    assert_includes lines, '  bob left the game'
  end

  def test_on_player_event_ignores_blank_name
    @agent.on_player_event(:joined, '  ')
    assert_empty @agent.instance_variable_get(:@chat_history)
  end

  def test_system_prompt_includes_events
    @agent.on_player_event(:joined, 'alice')
    sp = @agent.send(:system_prompt)
    assert_includes sp, 'alice joined the game'
  end

  # ── Join greeting (LLM-generated) ─────────────────────────────

  def test_join_greeting_uses_llm_and_sends
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test')
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
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test')
    agent.define_singleton_method(:complete) do |_prompt|
      clean_reply('Welcome, alice. The factory is watching.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_equal ['hivemind', 'Welcome, alice. The factory is watching.'],
                 agent.instance_variable_get(:@chat_history).last
  end

  def test_join_greeting_respects_greet_interval
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test')
    agent.define_singleton_method(:complete) { |_p| clean_reply('hi') }
    agent.instance_variable_set(:@last_greet, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_empty rcon.sent
  end

  def test_leave_does_not_greet
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test')
    agent.on_player_event(:left, 'alice')
    assert_empty rcon.sent
  end

  def test_greeting_disabled_with_greet_on_join_false
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test')
    agent.instance_variable_set(:@greet_on_join, false)
    agent.on_player_event(:joined, 'alice')
    assert_empty rcon.sent
  end

  def test_system_prompt_clips_long_lines
    @agent.send(:append_history, 'alice', 'x' * 500)
    line = @agent.send(:chat_history_lines)
    assert_operator line.length, :<=, HiveMindAgent::HISTORY_LINE_LEN + 20
  end
end
