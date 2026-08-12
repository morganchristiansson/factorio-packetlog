#!/usr/bin/env ruby
# frozen_string_literal: true

# Fixture-driven regression tests.
# Run: ruby -Ilib spec/packet_fixtures_spec.rb
#
# Tests the REAL FactorioProtocol implementation against:
#  1. REAL packets captured from live sessions (spec/fixtures/packets.rb)
#  2. Synthetic variations of write_to_console payloads (spec/fixtures/chat_variations.rb)

require 'minitest/autorun'
require 'factorio_protocol'
require_relative 'fixtures/packets'
require_relative 'fixtures/chat_variations'

class TestPacketFixtures < Minitest::Test
  # Each real packet must parse to exactly the expected actions.
  REAL_PACKET_FIXTURES.each do |fx|
    define_method("test_fixture_#{fx[:name]}") do
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
