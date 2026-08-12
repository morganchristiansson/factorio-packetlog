#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests using real packet blobs and synthetic fixtures.
# Run: ruby -Ilib spec/fixture_tests.rb

require 'minitest/autorun'
require 'factorio_protocol'
require 'factorio_types'

FIXTURE_DIR = File.join(__dir__, 'fixtures')

class FixtureTests < Minitest::Test
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

  # ── Cursor hover (type 265) fixture ────────────────────────

  def test_cursor_hover_from_fixture
    result = parse_fixture('cursor_hover')
    actions = extract_actions(result)
    act = actions.find { |a| a[:type] == 265 }
    refute_nil act, 'Expected cursor_hover action'
    d = act[:data]
    assert_equal 8, d.bytesize
    tick = d.unpack1('V', offset: 1)
    assert tick > 0
  end

  # ── Cursor click (type 9) fixture ──────────────────────────

  def test_cursor_click_from_fixture
    result = parse_fixture('cursor_click_select')
    actions = extract_actions(result)
    act = actions.find { |a| a[:type] == 9 }
    refute_nil act, 'Expected cursor_click_select action'
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

  # ── Chat decode unit tests ─────────────────────────────────
  # These test the REAL FactorioProtocol.decode_chat, not a private copy.

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
