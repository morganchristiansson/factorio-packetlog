# frozen_string_literal: true

# Shared helpers for the Hivemind test files:
#   hivemind_test.rb             agent core (triggers, context, greetings)
#   hivemind_tools_test.rb       RubyLLM tool classes
#   hivemind_persistence_test.rb session file round-trips
#   hivemind_compaction_test.rb  long-term memory + /compact
#   hivemind_followups_test.rb   scheduled follow-ups + scheduler

require 'minitest/autorun'
require 'hivemind'

class FakeRcon
  attr_reader :sent, :tag_sets
  # connected: player names (or {name:} hashes) for connected_players;
  # attrs: rows for player_attributes (LuaPlayer attr shape).
  def initialize(connected: [], attrs: [])
    @sent = []
    @tag_sets = []
    @connected = connected
    @attrs = attrs
  end
  def set_player_tag(player, tag)
    @tag_sets << [player, tag]
    true
  end
  def say(text)
    @sent << text
  end
  def player_attributes = @attrs
  def connected_players = @connected.map { |p| p.is_a?(Hash) ? p : { name: p } }
end

module HivemindSpecHelpers
  # A standard offline agent: no session file, no memory dir, empty
  # rosters, LLM calls stubbed so tests never hit the network.
  def make_agent(**overrides)
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test',
                              session_path: false, memory_dir: false, **overrides)
    agent.define_singleton_method(:complete) { |_prompt| '' }
    agent
  end

  # Capture the per-turn prompt an ask/greet/follow-up builds, without
  # hitting the network.
  def capture_prompt(agent, &block)
    seen = nil
    agent.define_singleton_method(:complete) { |p| seen = p; '' }
    block.call
    seen
  end
end
