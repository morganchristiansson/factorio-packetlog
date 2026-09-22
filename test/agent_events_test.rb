# frozen_string_literal: true
require 'bundler/setup'
require 'minitest/autorun'
require 'timeout'
require 'tmpdir'
require_relative '../factorio-sniffer'

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

  def test_blocked_agents_do_not_block_packets_and_workers_preserve_fifo
    hive = Recorder.new
    translation = Recorder.new
    entered, release = Queue.new, Queue.new
    translation.define_singleton_method(:on_chat) do |*args, **kwargs|
      entered << true
      release.pop
      @events << args
    end
    Dir.mktmpdir do |dir|
      sniffer = FactorioSniffer.new({player_db: nil}, pcap_writer: PcapWriter.new("#{dir}/capture.pcap"))
      sniffer.instance_variable_set(:@agent, hive)
      sniffer.instance_variable_set(:@translation_agent, translation)
      action = {name: 'write_to_console', game_player: 1, type: 1, data: "\x01\x02hi".b}
      capture_io do
        Timeout.timeout(1) do
          sniffer.send(:log_action, Time.now.to_f, action, false)
          entered.pop
          sniffer.send(:log_action, Time.now.to_f, action, false)
          hive.close_events
        end
        assert_equal [['Player_1', 'hi'], ['Player_1', 'hi']], hive.events
        assert_empty translation.events
        2.times { release << true }
        translation.close_events
        assert_equal 2, translation.events.size
        sniffer.finish
      end
    end
  ensure
    2.times { release << true } if release
    hive&.close_events
    translation&.close_events
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
      sniffer = FactorioSniffer.new({server: true, server_ip: '10.0.0.1', interface: 'fake'},
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
