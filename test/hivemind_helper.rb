# frozen_string_literal: true

# Shared helpers for the Hivemind test files:
#   hivemind_test.rb             agent core (triggers, context, greetings)
#   hivemind_tools_test.rb       RubyLLM tool classes
#   hivemind_persistence_test.rb session file round-trips
#   hivemind_compaction_test.rb  long-term memory + /compact
#   hivemind_followups_test.rb   scheduled follow-ups + scheduler

require 'fileutils'
require 'minitest/autorun'
require 'mocha/minitest'
require 'tmpdir'
require 'plugins'

HIVE_TEST_CONFIG = File.expand_path('../config-hivemind.yaml.example', __dir__)

# Hivemind reads its OWN `plugins:` list in its class body, so the require
# happens in a temp cwd holding the test config: the features under test must
# not depend on whatever config-hivemind.yaml this checkout happens to have.
# (The SNIFFER's list needs nothing here: hivemind is a class the sniffer
# instantiates itself, not a feature it builds from that list.)
Dir.mktmpdir('hivemind-test') do |dir|
  FileUtils.cp(HIVE_TEST_CONFIG, File.join(dir, 'config-hivemind.yaml'))
  Dir.chdir(dir) { require 'hivemind' }
end
require 'player_attrs'
require 'player_db'
require 'hivemind_persistence' # the feature whose default_path tests stub
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
# `session:` is where the persistence feature should keep its file — nil
# (the default here) means NO session file, the way most tests want it. The
# agent has no session-path argument: the feature reads its own
# `default_path`, and this stubs it around the construction (the feature
# captures the path once, so later persists keep writing there).
def new_hive_agent(rcon: FakeRcon.new, attrs: nil, current_tick: -> { 0 },
                   player_db: nil, session: nil, **kwargs)
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
  HivemindPersistence.stub(:default_path, session) do
    HivemindAgent.new(rcon: rcon, attrs: attrs, current_tick: current_tick,
                      player_db: player_db, config_file: HIVE_TEST_CONFIG, **kwargs)
  end
end

module HivemindSpecHelpers
  # A standard offline agent: no session file, no memory dir, empty
  # rosters, LLM calls silenced so tests never hit the network.
  #
  # define_singleton_method, not stub: the agent is RETURNED, so the silent
  # model has to outlive this method's block. (A block turned into a method
  # runs with self = the receiver, so this body could call the agent's own
  # privates — a lambda passed to #stub could not.)
  def make_agent(**overrides)
    agent = new_hive_agent(memory_dir: false, **overrides)
    agent.define_singleton_method(:complete) { |_prompt| '' }
    agent
  end

  # Capture the per-turn prompt an ask/greet/follow-up builds, without
  # hitting the network. Scoped: the agent keeps its real #complete after.
  def capture_prompt(agent, &block)
    seen = nil
    agent.stub(:complete, ->(p) { seen = p; '' }) { block.call }
    seen
  end
end
