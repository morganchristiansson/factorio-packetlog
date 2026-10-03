#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the `tags` Hivemind plugin (lib/hivemind_tags.rb): the
# set_player_tag tool it offers, the Lua it builds, and that the agent hands
# the model nothing when the plugin is not in config-hivemind.yaml `plugins:`.
# Run: ruby -Ilib test/hivemind_tags_test.rb

require 'bundler/setup' # FIRST: vendored gems (rcon), same as factorio-packettools.rb
require 'rcon_client'
require 'hivemind_tags'
require_relative 'hivemind_helper'

class TestHivemindTags < Minitest::Test
  include HivemindSpecHelpers

  def setup
    @agent = make_agent
  end

  def test_set_player_tag_tool_sets_tag
    rcon = FakeRcon.new
    result = SetPlayerTag.new(rcon: rcon).call('player' => 'alice', 'tag' => 'Builder')
    assert_match(/Tag set for alice/, result.to_s)
    assert_equal [['alice', 'Builder']], rcon.tag_sets
  end

  def test_set_player_tag_tool_unknown_player_errors
    rcon = FakeRcon.new
    rcon.stub(:set_player_tag, ->(_p, _t) { false }) do
      result = SetPlayerTag.new(rcon: rcon).call('player' => 'ghost', 'tag' => 'x')
      assert_match(/unknown player 'ghost'/, result.to_s)
    end
  end

  def test_register_tools_includes_set_player_tag
    tools = @agent.instance_variable_get(:@chat).tools
    assert tools.key?(:set_player_tag), 'set_player_tag tool registered'
  end

  # The tool must tell the model to KEEP tags current — set them once it
  # knows a player, revise as their role changes — not just write one.
  def test_tool_description_asks_for_ongoing_tags
    desc = SetPlayerTag.new(rcon: FakeRcon.new).description.to_s
    assert_match(/keep tags current as you learn about a player/i, desc)
    assert_match(/revise it when that changes/i, desc)
  end

  # RconClient Lua construction (no server needed — stub #execute):
  # quoting must hold quotes AND backslashes inside the string, the tag
  # write targets exactly game.players[name].tag, and the rcon.print
  # existence check drives the return value.
  def test_rcon_set_player_tag_lua
    captured = nil
    client = RconClient.allocate
    client.instance_variable_set(:@mutex, Mutex.new)
    client.stub(:execute, ->(cmd) { captured = cmd; "true\n" }) do
      assert client.set_player_tag('alice', 'Builder')
      assert_includes captured, 'game.players["alice"]'
      assert_includes captured, 'p.tag = "Builder"'
      assert_includes captured, 'rcon.print(p ~= nil)'
      # breakout attempts stay inside the Lua string
      client.set_player_tag('x"]; game.print("PWN', 't')
      refute_includes captured, 'game.players["x"]'
      client.set_player_tag('\\"; game.print("PWN', 't')
      refute_match(/[^\\]"; game/, captured)
    end
    # unknown player / failure — a second, SEQUENTIAL stub block: minitest
    # aliases the original per stub, so the same method cannot be stubbed
    # twice at once.
    client.stub(:execute, ->(_cmd) { "false\n" }) do
      refute client.set_player_tag('ghost', 'x')
      refute client.set_player_tag('  ', 'x'), 'blank name rejected'
    end
  end

  # The switch is the plugin list: with `tags` in it the plugin builds and
  # the tool is offered...
  def test_tag_tool_is_offered_when_the_plugin_is_listed
    assert @agent.plugin?('tags')
    assert_kind_of HivemindTags, @agent.plugins[:tags]
    assert @agent.instance_variable_get(:@chat).tools.key?(:set_player_tag)
  end

  # ...and without it there is no feature, so nothing registers the only tool
  # that writes to the game. The list is class-level (own_plugins, read once
  # per load), so this checks the plugin set directly.
  def test_no_tag_feature_when_the_name_is_not_listed
    off = Plugins::PluginSet.new(%w[logwatcher], @agent,
                                 dir: File.expand_path('../lib', __dir__), owner: 'hivemind')
    assert_nil off[:tags]
  end
end