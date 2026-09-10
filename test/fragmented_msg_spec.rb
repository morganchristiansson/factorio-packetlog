# frozen_string_literal: true

# Fragmented messages: a modded client's msg-4 confirm carries the mod
# list/settings blob (KBs, so every client runs the same deterministic
# sim) and arrives as frags 0..N under one message_id. Only frag 0 holds
# the leading fields; frags 1+ are mid-payload slices that must never
# parse as whole messages — they used to decode windows of the mod blob
# as phantom "usernames", stealing the confirm binding and player slot.
# Ground truth: test/fixtures/frag_confirm_{0..5}.bin (morganc's join,
# 2026-09-10; see frag_confirm.txt).
# Run: ruby -Ilib test/fragmented_msg_spec.rb

require 'minitest/autorun'
require 'factorio_protocol'

class TestFragmentedMessages < Minitest::Test
  def frag(n)
    File.binread(File.join(__dir__, 'fixtures', "frag_confirm_#{n}.bin"))
  end

  def test_frag0_parses_username
    parsed = FactorioProtocol.parse_udp_payload(frag(0))
    assert_equal 'morganc', parsed[:connection_confirm][:username]
  end

  # Frags 1-5 are mid-blob slices: header parses, but no username may
  # come out (frag 1 is even short/empty, frags 2-5 hold printable mod
  # text that the old code printed as "X connected").
  def test_frags1plus_yield_no_username
    (1..5).each do |n|
      parsed = FactorioProtocol.parse_udp_payload(frag(n))
      refute_nil parsed, "frag #{n}: header should still parse"
      assert_nil parsed[:connection_confirm], "frag #{n}: mid-blob slice must not decode as a username"
    end
  end

  def test_unfragmented_confirm_unaffected
    pkt = "\x04".b + [0x0002].pack('v') + ("\x00" * 12) + [7].pack('C') + 'morganc'
    assert_equal 'morganc', FactorioProtocol.parse_udp_payload(pkt)[:connection_confirm][:username]
  end

  def test_truncated_fragment_header_no_crash
    parsed = FactorioProtocol.parse_udp_payload("\x44\x02".b)
    assert_nil parsed && parsed[:connection_confirm]
  end

  def test_fragmented_heartbeat_has_no_actions
    # Later frags skip with header only (was: nil); frag 0 still hits the
    # heartbeat path's own not-a-full-message guard (unchanged: nil).
    frag1 = "\x46\x02\x00\x01".b + ('A' * 20)
    parsed = FactorioProtocol.parse_udp_payload(frag1)
    refute_nil parsed
    assert_nil parsed[:heartbeat]
    frag0 = "\x46\x02\x00\x00".b + ('A' * 20)
    assert_nil FactorioProtocol.parse_udp_payload(frag0)
  end
end
