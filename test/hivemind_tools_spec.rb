#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the RubyLLM tool classes (hivemind_tools.rb): reply, rcon query, memory writes, registration.
# Run: ruby -Ilib test/hivemind_tools_spec.rb

require 'bundler/setup' # FIRST: vendored gems (rcon), same as factorio-sniffer.rb
require 'rcon_client'
require_relative 'hivemind_helper'

class TestHivemindTools < Minitest::Test
  include HivemindSpecHelpers

  def setup
    @agent = make_agent
  end


  def test_reply_tool_appends_history
    tool = HivemindReply.new(rcon: FakeRcon.new,
                           on_sent: ->(t) { @agent.send(:append_history, 'hivemind', t) })
    tool.call('text' => 'bus is at 1k spm')
    assert_equal ['hivemind', 'bus is at 1k spm'], @agent.instance_variable_get(:@console_queue).last
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


  def test_schedule_tool_wires_into_agent
    tool = ScheduleFollowUp.new(agent: @agent)
    result = tool.call('delay_seconds' => 60, 'task' => 'remind players', 'name' => 'remind')
    assert_match(/Follow-up 'remind' scheduled/, result)
    assert_equal 'remind players', @agent.instance_variable_get(:@followups).first[:task]
    # invalid args never reach the agent
    err = ScheduleFollowUp.new(agent: @agent).call('delay_seconds' => -5, 'task' => 'x', 'name' => 'bad')
    assert err.is_a?(Hash) || err.to_s.include?('Error') || err.to_s.include?('Invalid')
  end


  def test_set_player_tag_tool_sets_tag
    rcon = FakeRcon.new
    result = SetPlayerTag.new(rcon: rcon).call('player' => 'alice', 'tag' => 'Builder')
    assert_match(/Tag set for alice/, result.to_s)
    assert_equal [['alice', 'Builder']], rcon.tag_sets
  end

  def test_set_player_tag_tool_unknown_player_errors
    rcon = FakeRcon.new
    rcon.define_singleton_method(:set_player_tag) { |_p, _t| false }
    result = SetPlayerTag.new(rcon: rcon).call('player' => 'ghost', 'tag' => 'x')
    assert_match(/unknown player 'ghost'/, result.to_s)
  end

  def test_register_tools_includes_set_player_tag
    tools = @agent.instance_variable_get(:@chat).tools
    assert tools.key?(:set_player_tag), 'set_player_tag tool registered'
  end

  # RconClient Lua construction (no server needed — stub #execute):
  # quoting must hold quotes AND backslashes inside the string, the tag
  # write targets exactly game.players[name].tag, and the rcon.print
  # existence check drives the return value.
  def test_rcon_set_player_tag_lua
    captured = nil
    client = RconClient.allocate
    client.instance_variable_set(:@mutex, Mutex.new)
    client.define_singleton_method(:execute) { |cmd| captured = cmd; "true\n" }
    assert client.set_player_tag('alice', 'Builder')
    assert_includes captured, 'game.players["alice"]'
    assert_includes captured, 'p.tag = "Builder"'
    assert_includes captured, 'rcon.print(p ~= nil)'
    # breakout attempts stay inside the Lua string
    client.set_player_tag('x"]; game.print("PWN', 't')
    refute_includes captured, 'game.players["x"]'
    client.set_player_tag('\\"; game.print("PWN', 't')
    refute_match(/[^\\]"; game/, captured)
    # unknown player / failure
    client.define_singleton_method(:execute) { |_cmd| "false\n" }
    refute client.set_player_tag('ghost', 'x')
    refute client.set_player_tag('  ', 'x'), 'blank name rejected'
  end

  def test_write_memories_tool_removed
    # write_memories was removed entirely: this gateway drops tool-call
    # arguments for compaction-scale payloads, so compaction parses a
    # fenced JSON block from the model's plain-text reply instead
    # (see compact_memory! / extract_memory_content).
    assert !defined?(WriteMemories), 'WriteMemories must stay removed'
  end

end
