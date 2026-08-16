#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests using real packet blobs and synthetic fixtures.
# Run: ruby -Ilib spec/fixture_tests.rb

require 'minitest/autorun'
require 'factorio_protocol'
require 'factorio_types'

FIXTURE_DIR = File.join(__dir__, 'fixtures')

class FixtureTests < Minitest::Test
  def teardown
    # Never leak the version-dependent tables into other tests.
    FactorioProtocol.actions = FactorioProtocol::ACTIONS
    FactorioProtocol.segment_types = FactorioProtocol::ACTIONS
  end

  def parse_fixture(name)
    path = File.join(FIXTURE_DIR, "#{name}.bin")
    refute_nil path, "Fixture #{name}.bin not found"
    udp_data = File.binread(path)
    refute_nil udp_data
    result = FactorioProtocol.parse_udp_payload(udp_data)
    refute_nil result
    result
  end

  def extract_actions(result)
    return [] unless result&.dig(:heartbeat, :tick_closures)
    result[:heartbeat][:tick_closures].flat_map { |tc| tc[:actions] || [] }
  end

  # ── Build fixture ──────────────────────────────────────────

  def test_build_from_fixture
    result = parse_fixture('build')
    actions = extract_actions(result)
    assert actions.size >= 1
  end

  # ── Chat 0x05 fixture ──────────────────────────────────────

  def test_chat_05_from_fixture
    result = parse_fixture('chat_05')
    actions = extract_actions(result)
    act = actions.find { |a| a[:type] == 106 }
    refute_nil act, 'Expected write_to_console action'
    d = act[:data]
    refute_nil d
    assert d.bytesize >= 3
    assert_equal 0x05, d.getbyte(0)
    msg = FactorioProtocol.decode_chat(d)
    refute_nil msg
    refute msg.empty?
  end

  # ── Open GUI fixture ───────────────────────────────────────

  def test_open_gui_from_fixture
    result = parse_fixture('open_gui')
    actions = extract_actions(result)
    act = actions.find { |a| a[:type] == 5 }
    refute_nil act, 'Expected open_gui action'
    d = act[:data]
    assert_equal 14, d.bytesize
    assert_equal 0x30, d.getbyte(0)
    tok = d.unpack1('V', offset: 6)
    assert tok > 0
    tick = d.unpack1('V', offset: 10) + 1
    assert tick > 0
  end

  # ── ChangePickingState (type 265) fixture ─────────────────────
  # Captured as type 265 (was misidentified as selected_entity_changed_*);
  # live defines: 265 = change_picking_state.

  def test_change_picking_state_from_fixture
    result = parse_fixture('change_picking_state')
    actions = extract_actions(result)
    act = actions.find { |a| a[:type] == 265 }
    refute_nil act, 'Expected change_picking_state action'
    d = act[:data]
    # client form: [payload(1)][tick(4)][pad(4)]
    assert_equal 9, d.bytesize
    tick = d.unpack1('V', offset: 1)
    assert tick > 0
  end

  # ── SelectedEntityCleared (type 9) fixture ──────────────────────

  def test_selected_entity_cleared_from_fixture
    result = parse_fixture('selected_entity_cleared')
    actions = extract_actions(result)
    act = actions.find { |a| a[:type] == 9 }
    refute_nil act, 'Expected selected_entity_cleared action'
    d = act[:data]
    assert_equal 8, d.bytesize
    tick = d.unpack1('V', offset: 0)
    assert tick > 0
  end

  # ── Player join (NewPeerInfo) synthetic fixture ────────────

  def test_player_join_from_fixture
    result = parse_fixture('player_join')
    hb = result[:heartbeat]
    syncs = hb[:sync_actions]
    refute_nil syncs

    npi = syncs.find { |s| s[:type] == 0x02 }
    refute_nil npi, 'Expected NewPeerInfo sync action'
    assert_equal 'hellwarr', npi[:username]
    assert_equal 42, npi[:peer_id]
  end

  # ── Player quit (C→S PeerDisconnect) real fixture ──────────
  # gameReseter's final heartbeat (factorio.pcap pkt 51944, 2026-08-16): a
  # clean quit arrives as a C→S heartbeat whose ONLY content is a
  # PeerDisconnect sync action (reason=0, NO peer_id — the peer_id form is
  # the S→C broadcast) + ClientChangedState state=8. Server mode treats
  # this as the leave signal. Regression: the old code required peer_id, so
  # C→S quits were never seen.

  def test_player_quit_from_fixture
    result = parse_fixture('player_quit')
    hb = result[:heartbeat]
    syncs = hb[:sync_actions]
    refute_nil syncs
    assert_equal [], hb[:tick_closures], 'quit heartbeat carries no tick closures'

    pd = syncs.find { |s| s[:type] == 0x01 }
    refute_nil pd, 'Expected PeerDisconnect sync action'
    assert_equal 'PeerDisconnect', pd[:name]
    assert_equal 0, pd[:reason]
    assert_nil pd[:peer_id], 'C→S PeerDisconnect has no peer_id (S→C broadcast form only)'

    st = syncs.find { |s| s[:type] == 0x03 }
    refute_nil st, 'Expected ClientChangedState sync action'
    assert_equal 8, st[:state]
  end

  # ── Chat decode unit tests ─────────────────────────────────
  # These test the REAL FactorioProtocol.decode_chat, not a private copy.

  # A 2.0.77 live capture of the player typing "hivemind, are you there?"
  # (extracted from factorio.pcap). Chat arrives as an input-action SEGMENT
  # whose type follows the server version's defines.input_action:
  # 2.0 → 104, 2.1 → 106. Main action types are version-stable.
  def test_chat_20_segment_decodes_under_2_0_mapping
    FactorioProtocol.select_version('2.0.77')
    result = parse_fixture('chat_20_segment')
    actions = extract_actions(result)
    act = actions.find { |a| a[:name] == 'write_to_console' }
    refute_nil act, "expected write_to_console action, got: #{actions.map { |a| a[:name] }.inspect}"
    assert_equal 'hivemind, are you there?', FactorioProtocol.decode_chat(act[:data])
  end

  def test_chat_20_segment_is_gui_click_under_2_1_default
    # Regression: with the 2.1 segment map (the tool's original default),
    # the 2.0 chat segment type 104 resolves to gui_click, so the sniffer's
    # log_action chat branch (act[:name] == 'write_to_console') never fires
    # and the message is never treated as chat.
    FactorioProtocol.segment_types = FactorioProtocol::ACTIONS
    result = parse_fixture('chat_20_segment')
    act = extract_actions(result).first
    assert_equal 'gui_click', act[:name]
    refute_equal 'write_to_console', act[:name]
  end

  def test_segment_type_names_per_version
    FactorioProtocol.select_version('2.0.77')
    assert_equal 'write_to_console', FactorioProtocol.segment_action_name(104)
    assert_equal 'gui_click', FactorioProtocol.segment_action_name(102)
    FactorioProtocol.select_version('2.1')
    assert_equal 'write_to_console', FactorioProtocol.segment_action_name(106)
    assert_equal 'gui_click', FactorioProtocol.segment_action_name(104)
  end

  def test_select_version_bare_2_0
    FactorioProtocol.select_version('2.0')
    assert_equal 'write_to_console', FactorioProtocol.segment_action_name(104)
  end

  def test_select_version_unknown_keeps_2_1
    FactorioProtocol.select_version('9.9')
    assert_equal 'gui_click', FactorioProtocol.segment_action_name(104)
  end

  # ── Chat decode unit tests (2.1 fixtures) ───────────────────

  def test_chat_05_segment
    assert_equal 'hello', FactorioProtocol.decode_chat(([0x05, 5] + 'hello'.bytes).pack('C*'))
  end

  def test_chat_localized_literal
    text = 'It is perfectly fitting Pong'
    data = [text.bytesize] + text.bytes + [0x02, 0x00]
    assert_equal text, FactorioProtocol.decode_chat(data.pack('C*'))
  end

  def test_chat_localized_translation_key
    text = 'some.translation.key'
    data = [text.bytesize] + text.bytes + [0x01, 0x00]
    assert_equal "[#{text}]", FactorioProtocol.decode_chat(data.pack('C*'))
  end

  def test_chat_3d_server_echo
    assert_equal 'hello', FactorioProtocol.decode_chat(([0x3d, 5] + 'hello'.bytes).pack('C*'))
  end

  def test_chat_01_server_echo
    assert_equal 'hello', FactorioProtocol.decode_chat(([0x01, 5] + 'hello'.bytes).pack('C*'))
  end

  def test_chat_04_non_segment
    assert_equal 'hello', FactorioProtocol.decode_chat(([0x04] + 'hello'.bytes).pack('C*'))
  end

  def test_chat_uint32v
    # length byte must not collide with a prefix byte (0x04/0x05/0x0b/0x00/0x3d/0x01)
    assert_equal 'hi', FactorioProtocol.decode_chat(([2] + 'hi'.bytes).pack('C*'))
  end

  def test_chat_raw
    assert_equal 'hello', FactorioProtocol.decode_chat('hello'.b)
  end
end
