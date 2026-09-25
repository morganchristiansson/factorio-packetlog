# frozen_string_literal: true

# Shared helpers for the Hivemind test files:
#   hivemind_test.rb             agent core (triggers, context, greetings)
#   hivemind_tools_test.rb       RubyLLM tool classes
#   hivemind_persistence_test.rb session file round-trips
#   hivemind_compaction_test.rb  long-term memory + /compact
#   hivemind_followups_test.rb   scheduled follow-ups + scheduler

require 'minitest/autorun'
require 'hivemind'
require 'player_attrs'
require 'player_db'

HIVE_TEST_CONFIG = File.expand_path('../config-hivemind.yaml.example', __dir__)
ENV['HIVE_API_KEY'] ||= 'sk-test'

class FakeRcon
  attr_reader :sent, :tag_sets, :connected
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
  def player_attributes_for(name)
    @attrs&.find { |a| a[:name] == name }
  end
end

# Production always supplies packet-derived context. Tests do the same,
# seeded from their fake RCON data, and load the checked-in example config.
def new_hive_agent(rcon: FakeRcon.new, attrs: nil, current_tick: -> { 0 },
                   player_db: nil, **kwargs)
  if !attrs.is_a?(PlayerAttrs)
    rows = attrs || rcon.player_attributes
    rows = rcon.connected.map { |name| { name: name } } if rows.empty? && rcon.connected.any?
    attrs = PlayerAttrs.new
    rows.each_with_index do |row, i|
      attrs.seed(row[:name], index: row[:index] || i + 1,
                 connected: row.fetch(:connected, true),
                 online_time: row[:online_time] || 0,
                 afk_time: row[:afk_time] || 0)
    end
  end
  player_db ||= PlayerDatabase.new(nil)
  Array(rows).each_with_index do |row, i|
    player_db[row[:index] || i + 1] = { name: row[:name], admin: row[:admin] }
  end
  HiveMindAgent.new(rcon: rcon, attrs: attrs, current_tick: current_tick,
                    player_db: player_db, config_file: HIVE_TEST_CONFIG, **kwargs)
end

module HivemindSpecHelpers
  # A standard offline agent: no session file, no memory dir, empty
  # rosters, LLM calls stubbed so tests never hit the network.
  def make_agent(**overrides)
    agent = new_hive_agent(session_path: false, memory_dir: false, **overrides)
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
