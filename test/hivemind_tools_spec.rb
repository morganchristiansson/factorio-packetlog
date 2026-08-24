#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the RubyLLM tool classes (hivemind_tools.rb): reply, rcon query, memory writes, registration.
# Run: ruby -Ilib test/hivemind_tools_spec.rb

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


  def test_write_memories_tool_removed
    # write_memories was removed entirely: this gateway drops tool-call
    # arguments for compaction-scale payloads, so compaction parses a
    # fenced JSON block from the model's plain-text reply instead
    # (see compact_memory! / extract_memory_content).
    assert !defined?(WriteMemories), 'WriteMemories must stay removed'
  end

end
