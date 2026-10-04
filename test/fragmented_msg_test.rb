# frozen_string_literal: true

# Fragmented messages: a modded client's msg-4 confirm carries the mod
# list/settings blob (KBs, so every client runs the same deterministic
# sim) and arrives as frags 0..N under one message_id. Only frag 0 holds
# the leading fields; frags 1+ are mid-payload slices that must never
# parse as whole messages — they used to decode windows of the mod blob
# as phantom "usernames", stealing the confirm binding and player slot.
# Ground truth: test/fixtures/frag_confirm_{0..5}.bin (morganc's join,
# 2026-09-10; see frag_confirm.txt).
# Run: ruby -Ilib test/fragmented_msg_test.rb

require 'minitest/autorun'
require 'mocha/minitest'
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
    # header + 3 ids + the username + an EMPTY session block (no token, no
    # timestamp — the LAN / first join shape) + no mods
    pkt = "\x04".b + [0x0002].pack('v') + ("\x00" * 12) + [7].pack('C') + 'morganc' +
          "\x00\x00\x00" + ("\x00" * 8) + "\x00"
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

  # ── Reassembly (FactorioProtocol, with the rest of the wire format) ──

  # The other half of the story: put the frags back together and the whole
  # message parses — morganc's username AND his mod list, which frag 0 alone
  # truncates.
  def test_reassembles_a_fragmented_message
    out = FactorioProtocol.reassemble_fragments((0..5).map { |n| frag(n) })
    refute_nil out, 'all six fragments present'
    assert_equal (0..5).sum { |n| frag(n).bytesize - 4 }, out.bytesize, 'headers stripped, order kept'
    assert_includes out, 'morganc'
    assert_includes out, 'base'
  end

  def test_reassembly_is_order_independent_and_needs_every_fragment
    frags = (0..5).map { |n| frag(n) }
    assert_equal FactorioProtocol.reassemble_fragments(frags),
                 FactorioProtocol.reassemble_fragments(frags.shuffle)
    assert_nil FactorioProtocol.reassemble_fragments(frags[0..3]), 'a gap is not a message'
    assert_nil FactorioProtocol.reassemble_fragments([]), 'nothing to join'
  end

  # The request that starts it all is one byte, and it belongs with the wire
  # format (FactorioServerProbe only opens the socket).
  def test_game_information_request_is_one_byte
    assert_equal "\x10".b, FactorioProtocol::GAME_INFO_REQUEST
    assert_equal 0x10 & 0x1F, FactorioProtocol::GAME_INFO_REQUEST.getbyte(0) & 0x1F
  end

  # What the real join actually carries: morganc's 11 mods, decoded from
  # fragment 0 with the packet parser (that is all the live path ever sees).
  def test_the_real_join_fragment_decodes_the_mod_list
    parsed = FactorioProtocol.parse_udp_payload(frag(0))[:connection_confirm]
    assert_equal 'morganc', parsed[:username]
    assert_equal 11, parsed[:mods].size
    assert_equal %w[base AutoDeconstruct Better-TrainHorn custom-spawn-rates elevated-rails
                    flib no-wall-repair quality RateCalculator space-age], parsed[:mods].map(&:first).first(10)
    assert_equal ['base', '0.2', 94_144_077, 112], parsed[:mods].first
    assert parsed[:settings_truncated], 'the settings blob spans fragments 1..5'
  end

  # A whole (unfragmented) join WITH the auth session token — the second of
  # the joins every client makes (the first carries neither token nor
  # timestamp: see frag_confirm_0.bin for that shape). The fixture is
  # synthetic, built to the shape a real capture had, so no live name, token
  # or address is in the repo.
  def test_the_session_block_decodes_a_token_join
    cc = FactorioProtocol.parse_udp_payload(
      File.binread(File.join(__dir__, 'fixtures', 'msg4_confirm_token.bin'))
    )[:connection_confirm]
    assert_equal 'somePlayer', cc[:username]
    assert_equal '0123456789abcdefghijkl', cc[:session][:token], '24-ish chars of base64 in a real one'
    assert_equal '260925030027', cc[:session][:client_time], 'the client clock, to the second'
    assert_equal '1122334455667788', cc[:session][:connection_id]
    assert_equal 2, cc[:mods].size
    refute cc[:mods_truncated]
    refute cc[:settings_truncated], 'an unfragmented join decodes completely'
    assert_equal({ 'value' => false }, cc[:settings])
  end

  def test_the_first_join_carries_no_session_token
    cc = FactorioProtocol.parse_udp_payload(frag(0))[:connection_confirm]
    assert_equal '', cc[:session][:token]
    assert_equal '', cc[:session][:client_time]
    assert_match(/\A[0-9a-f]{16}\z/, cc[:session][:connection_id])
  end
end
