#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for session persistence (hivemind_persistence.rb): save/restore, corrupt files, tool-call round-trips.
# Run: ruby -Ilib spec/hivemind_persistence_spec.rb

require_relative 'hivemind_helper'

class TestHivemindPersistence < Minitest::Test
  include HivemindSpecHelpers

  def setup
    @agent = make_agent
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

  # Regression: persist_queue! (fired by append_history on every chat line)
  # used to rewrite the session file WITHOUT the messages/followups keys,
  # clobbering the conversation persisted moments earlier by persist! — a
  # restart then resumed empty and /compact had nothing to distill. The
  # cheap path must write the FULL snapshot (messages from the cache).
  def test_queue_persist_never_clobbers_conversation
    Dir.mktmpdir do |dir|
      sess = File.join(dir, 'session.json')
      a1 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      a1.online_provider = -> { [] }
      a1.player_stats_provider = -> { [] }
      a1.instance_variable_get(:@chat).add_message(role: :user, content: 'turn: what is the bus?')
      a1.instance_variable_get(:@chat).add_message(role: :assistant, content: 'the bus is at 1k spm')
      a1.send(:persist!)

      # a chat line arrives after the ask → append_history → persist_queue!
      a1.send(:append_history, 'alice', 'hello hivemind')
      data = JSON.parse(File.read(sess))
      assert data['messages'].is_a?(Array) && data['messages'].size >= 2,
             'queue persist must keep the conversation in the file'

      # restart restores both conversation and console queue
      a2 = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: sess, memory_dir: false)
      texts = a2.instance_variable_get(:@chat).messages.map(&:content).map(&:to_s)
      assert_includes texts, 'the bus is at 1k spm'
      assert_equal [['alice', 'hello hivemind']], a2.instance_variable_get(:@console_queue)
    end
  end

end
