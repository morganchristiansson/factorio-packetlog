#!/usr/bin/env ruby
# frozen_string_literal: true

# Fixture-driven regression tests.
# Run: ruby -Ilib test/packet_fixtures_spec.rb
#
# Tests the REAL FactorioProtocol implementation against:
#  1. REAL packets captured from live sessions (test/fixtures/packets.rb)
#  2. Synthetic variations of write_to_console payloads (test/fixtures/chat_variations.rb)

require 'minitest/autorun'
require 'factorio_protocol'
require_relative 'fixtures/packets'
require_relative 'fixtures/chat_variations'

class TestPacketFixtures < Minitest::Test
  def teardown
    # Never leak version-dependent tables into the following tests.
    FactorioProtocol.reset_version
  end

  # Simulate FactorioSniffer#chat_action_data reassembly: merge segments of
  # a split write_to_console (keyed by player, ordered by seg_no) and return
  # the full payload. Mirrors the sniffer so the reassembly path is tested
  # end-to-end.
  def reassemble(split_actions)
    by_player = Hash.new { |h, k| h[k] = {} }
    split_actions.each { |act| by_player[act[:player]][act[:seg_no]] = act[:data] }
    by_player.map { |_player, parts| parts.keys.sort.map { |n| parts[n] }.join }
  end

  # Each real packet must parse to exactly the expected actions.
  REAL_PACKET_FIXTURES.each do |fx|
    define_method("test_fixture_#{fx[:name]}") do
      FactorioProtocol.select_version(fx[:version] || '2.1')
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      refute_nil result, "#{fx[:name]}: parse_udp_payload returned nil"
      hb = result[:heartbeat]
      actions = (hb[:tick_closures] || []).flat_map { |tc| tc[:actions] }

      assert_equal fx[:actions].size, actions.size,
                   "#{fx[:name]}: expected #{fx[:actions].size} actions, got #{actions.size}"

      fx[:actions].each_with_index do |exp, i|
        act = actions[i]
        refute_nil act, "#{fx[:name]}: action #{i} missing"
        assert_equal exp[:type], act[:type], "#{fx[:name]} action #{i} type"
        assert_equal exp[:name], act[:name], "#{fx[:name]} action #{i} name"
        assert_equal exp[:player], act[:player], "#{fx[:name]} action #{i} player"
        assert_equal exp[:game_player], act[:game_player], "#{fx[:name]} action #{i} game_player"
        got_data = act[:data] ? act[:data].unpack1('H*') : nil
        assert_equal exp[:data], got_data, "#{fx[:name]} action #{i} data"
        assert_equal exp[:total_segs], act[:total_segs], "#{fx[:name]} action #{i} total_segs" if exp.key?(:total_segs)
        assert_equal exp[:seg_no], act[:seg_no], "#{fx[:name]} action #{i} seg_no" if exp.key?(:seg_no)
        if exp.key?(:chat)
          msg = FactorioProtocol.decode_chat(act[:data])
          if exp[:chat].nil?
            assert_nil msg, "#{fx[:name]} action #{i} chat decode"
          else
            assert_equal exp[:chat], msg, "#{fx[:name]} action #{i} chat decode"
          end
        end
      end
    end
  end

  # Split-chat reassembly: the two messages above are replayed as the sniffer
  # would reassemble them (segments keyed by player, merged by seg_no), and
  # decode_chat must return the FULL message — NOT a fragment truncated when a
  # player byte >= 0x40 was misread as a length, and NOT cut at the segment
  # boundary.
  def test_split_chat_reassembled_full_text_p66
    %w[client_split_chat_2seg_p66_seg0 client_split_chat_2seg_p66_seg1].each do |name|
      fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
      FactorioProtocol.select_version(fx[:version])
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      @split ||= []
      @split.concat((result[:heartbeat][:tick_closures] || []).flat_map { |tc| tc[:actions] })
    end
    joined = reassemble(@split)
    assert_equal 1, joined.size
    msg = FactorioProtocol.decode_chat(joined.first)
    assert_equal 'hivemind what are your personal, deep, and hidden feelings towards the player morganc, the kind you would never tell...', msg
  end

  def test_split_chat_reassembled_long_4seg_p54
    %w[client_split_chat_4seg_p54_seg0 client_split_chat_4seg_p54_seg1 client_split_chat_4seg_p54_seg2 client_split_chat_4seg_p54_seg3].each do |name|
      fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
      FactorioProtocol.select_version(fx[:version])
      result = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*'))
      @split ||= []
      @split.concat((result[:heartbeat][:tick_closures] || []).flat_map { |tc| tc[:actions] })
    end
    joined = reassemble(@split)
    assert_equal 1, joined.size
    msg = FactorioProtocol.decode_chat(joined.first)
    assert_equal 298, msg.bytesize, 'long message must be returned in full (uint32v LONG-form length)'
    assert msg.start_with?('Hivemind, the definition of consensus is not equal to being unanimous: Consensus means a general or')
    assert msg.end_with?('even if they do not all fully agree on every single detail.')
  end

  # Each chat payload variation must decode to the expected text.
  CHAT_DECODE_FIXTURES.each do |fx|
    define_method("test_chat_variation_#{fx[:name]}") do
      data = fx[:data].pack('C*')
      msg = FactorioProtocol.decode_chat(data)
      if fx[:expected].nil?
        assert_nil msg, "decode_chat for #{fx[:name]} should be nil"
      else
        assert_equal fx[:expected], msg, "decode_chat for #{fx[:name]}"
      end
    end
  end
end
