# frozen_string_literal: true
require 'bundler/setup'
require 'minitest/autorun'
require 'mocha/minitest'
require 'timeout'
require 'tmpdir'
require 'agent_events'
require_relative '../factorio-packettools'

class TestAgentEvents < Minitest::Test
  class Recorder
    include AgentEvents
    attr_reader :events
    def initialize
      @events = []
      initialize_events
    end
    def on_chat(*args, **kwargs) = @events << args
    def on_player_event(*args, **kwargs) = @events << args
    def fail_event = raise('expected test error')
  end

  # The sniffer's PluginSet dispatches the emit(:on_chat) bus to features;
  # this fake does the same for the injected features (a real PluginSet
  # can't build the real classes here — the feature configs are absent).
  class PluginsDouble
    def initialize(translation: nil, hivemind: nil)
      @translation = translation
      @hivemind = hivemind
    end
    def [](name) = name == :translation ? @translation : (name == :hivemind ? @hivemind : nil)
    def emit(event, *args)
      [@translation, @hivemind].compact.each { |f| f.public_send(event, *args) if f.respond_to?(event) }
    end
  end

  def test_blocked_agents_do_not_block_packets_and_workers_preserve_fifo
    # Both chat features (translation + hivemind) ride the same emit(:on_chat)
    # bus. Each on_chat is SYNC-LIGHT (emit runs on the capture thread): it
    # records the dispatch args and defers the blocking relay to handle_chat
    # on ITS OWN worker — so a blocked feature never blocks the capture
    # thread, and each worker preserves FIFO.
    features = [Recorder.new, Recorder.new]
    entered, release = Queue.new, Queue.new
    features.each do |feature|
      feature.define_singleton_method(:on_chat) do |source, author, text, player_id = nil|
        @events << [:emit, source, author, text, player_id]
        enqueue(:handle_chat, author, text) if source == :factorio
      end
      feature.define_singleton_method(:handle_chat) do |*|
        entered << true
        release.pop
        @events << [:handle]
      end
    end
    translation, hivemind = features
    Dir.mktmpdir do |dir|
      sniffer = FactorioPacketTools.new({player_db: nil}, pcap_writer: PcapWriter.new("#{dir}/capture.pcap"))
      sniffer.instance_variable_set(:@plugins, PluginsDouble.new(translation: translation, hivemind: hivemind))
      action = {name: 'write_to_console', game_player: 1, type: 1, data: "\x01\x02hi".b}
      capture_io do
        Timeout.timeout(1) do
          sniffer.send(:log_action, Time.now.to_f, action, false)
          2.times { entered.pop }  # both features' first handle_chat in flight (blocked)
          sniffer.send(:log_action, Time.now.to_f, action, false)
        end
        # emit reached BOTH sync-light subscribers with the relay args
        expected = [[:emit, :factorio, 'Player_1', 'hi', 1], [:emit, :factorio, 'Player_1', 'hi', 1]]
        assert_equal expected, translation.events.select { |e| e.first == :emit }
        assert_equal expected, hivemind.events.select { |e| e.first == :emit }
        4.times { release << true }
        translation.close_events
        hivemind.close_events
        # handle_chat preserved FIFO on each feature's own worker
        assert_equal [[:handle], [:handle]], translation.events.select { |e| e.first == :handle }
        assert_equal [[:handle], [:handle]], hivemind.events.select { |e| e.first == :handle }
        sniffer.finish
      end
    end
  ensure
    4.times { release << true } if release
    Array(features).each(&:close_events)
  end

  def test_legacy_agent_without_queue_self_heals_and_never_crashes_shutdown
    legacy = Recorder.allocate
    legacy.instance_variable_set(:@events, [])
    capture_io do
      # enqueue lazily creates the worker (old hot-reloaded objects)
      assert legacy.enqueue(:on_chat, 'late')
      legacy.close_events
      assert_equal [['late']], legacy.events
      # a never-initialized object shuts down cleanly too
      Recorder.allocate.tap(&:close_events)
    end
  end

  def test_overflow_is_nonblocking_errors_do_not_kill_worker_and_close_drains
    agent = Recorder.new
    entered, release = Queue.new, Queue.new
    agent.define_singleton_method(:block_event) { entered << true; release.pop }
    agent.enqueue(:block_event)
    Timeout.timeout(1) { entered.pop }
    100.times { |n| assert agent.enqueue(:on_chat, n) }
    capture_io { Timeout.timeout(1) { refute agent.enqueue(:on_chat, :overflow) } }
    release << true
    agent.close_events
    assert_equal (0...100).map { |n| [n] }, agent.events
    refute agent.instance_variable_get(:@event_worker).alive?
    capture_io { refute agent.enqueue(:on_chat, :closed) }
    agent2 = Recorder.new
    capture_io do
      agent2.enqueue(:fail_event)
      agent2.enqueue(:on_chat, :after_error)
      agent2.close_events
    end
    assert_equal [[:after_error]], agent2.events
  ensure
    release << true if release
    agent&.close_events
    agent2&.close_events
  end

  def test_lazy_timeouts_run_after_packet_liveness_refresh_and_not_for_replay
    Dir.mktmpdir do |dir|
      sniffer = FactorioPacketTools.new({server: true, host_ips: ['10.0.0.1'], interface: 'fake'},
                                    pcap_writer: PcapWriter.new("#{dir}/capture.pcap"))
      attrs = sniffer.instance_variable_get(:@attrs)
      attrs.roster_online('active', 1)
      attrs.roster_online('silent', 2)
      attrs.instance_variable_get(:@players).each_value { |p| p[:hb] -= 100 }
      sniffer.instance_variable_get(:@ip_names)['10.0.0.2'] = ['active', true]
      capture_io do
        sniffer.send(:process_packet, 1, 0.0, '10.0.0.2', '10.0.0.1', 34197, 34197, "\x06\x0e\x00\x00\x00\x00".b)
        assert_equal ['active'], sniffer.online_players
        calls = 0
        sniffer.define_singleton_method(:check_heartbeat_timeouts) { calls += 1 }
        sniffer.send(:check_timeouts_if_due)
        assert_equal 0, calls
        sniffer.instance_variable_set(:@last_timeout_check, 0)
        sniffer.instance_variable_get(:@options)[:pcap] = 'replay.pcap'
        sniffer.send(:check_timeouts_if_due)
        assert_equal 0, calls
        sniffer.finish
      end
    end
  end
end
