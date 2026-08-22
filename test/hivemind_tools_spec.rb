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
    result = tool.call('delay_seconds' => 60, 'task' => 'remind players')
    assert_match(/Follow-up #\d+ scheduled/, result)
    assert_equal 'remind players', @agent.instance_variable_get(:@followups).first[:task]
    # invalid args never reach the agent
    err = ScheduleFollowUp.new(agent: @agent).call('delay_seconds' => -5, 'task' => 'x')
    assert err.is_a?(Hash) || err.to_s.include?('Error') || err.to_s.include?('Invalid')
  end


  def test_write_memories_tool_writes_one_memory_per_call
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      tool = WriteMemories.new(store: store)
      result = tool.call('key' => 'soul', 'content' => 'new soul')
      assert_equal 'soul updated', result
      tool.call('key' => 'knowledge', 'content' => 'the mall was built')
      tool.call('key' => 'alice', 'content' => 'alice built the mall')
      tool.call('key' => 'bob', 'content' => 'bob stomped the belts')
      assert_equal 'new soul', store.soul
      assert_equal 'the mall was built', store.knowledge
      assert_equal 'alice built the mall', store.player('alice')
      assert_equal 'bob stomped the belts', store.player('bob')
      assert_equal [['soul', 'new soul'], ['knowledge', 'the mall was built'],
                    ['alice', 'alice built the mall'], ['bob', 'bob stomped the belts']],
                   tool.written
    end
  end


  def test_write_memories_tool_skips_empty_key
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      tool = WriteMemories.new(store: store)
      result = tool.call('key' => '', 'content' => 'no key')
      assert_includes result.to_s, 'SKIPPED'
      assert_empty tool.written
      tool.call('key' => 'soul', 'content' => 'fine')
      tool.call('key' => 'alice', 'content' => 'player fine')
      assert_equal [['soul', 'fine'], ['alice', 'player fine']], tool.written
      assert_equal 'fine', store.soul
      assert_equal 'player fine', store.player('alice')
    end
  end

end
