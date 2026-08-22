# frozen_string_literal: true

# Shared helpers for the Hivemind spec files:
#   hivemind_spec.rb             agent core (triggers, context, greetings)
#   hivemind_tools_spec.rb       RubyLLM tool classes
#   hivemind_persistence_spec.rb session file round-trips
#   hivemind_compaction_spec.rb  long-term memory + /compact
#   hivemind_followups_spec.rb   scheduled follow-ups + scheduler

require 'minitest/autorun'
require 'hivemind'

class FakeRcon
  attr_reader :sent
  # connected: player names (or {name:} hashes) for connected_players;
  # attrs: rows for player_attributes (LuaPlayer attr shape).
  def initialize(connected: [], attrs: [])
    @sent = []
    @connected = connected
    @attrs = attrs
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
