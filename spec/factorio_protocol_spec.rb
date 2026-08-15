#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for Factorio protocol parsing using known byte sequences.
# Run: ruby -Ilib spec/factorio_protocol_spec.rb

require 'minitest/autorun'
require 'factorio_protocol'
require 'factorio_types'

class TestFactorioProtocol < Minitest::Test
  def setup
    @item_db = nil
  end

  # ── TilePos / TileRect ─────────────────────────────────────────

  def test_tile_pos_parses_8_bytes
    data = [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00].pack('C*')
    pos = FactorioTypes::TilePos.from_data(data)
    refute_nil pos
    assert_equal(-90211, pos.x)  # int32 LE
    assert_equal(110108, pos.y)
    tx, ty = pos.to_tiles
    assert_in_delta(-352.387, tx, 0.001)
    assert_in_delta(430.109, ty, 0.001)
  end

  def test_tile_rect_parses_16_bytes
    data = [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
            0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00].pack('C*')
    rect = FactorioTypes::TileRect.from_data(data)
    refute_nil rect
    assert_equal(-90211, rect.top_left.x)
    assert_equal(118732, rect.bottom_right.y)
    assert_in_delta(3.34, rect.width_tiles, 0.01)
    assert_in_delta(33.69, rect.height_tiles, 0.01)
  end

  # ── Deconstruct (type 131) ─────────────────────────────────────

  def test_deconstruct_data_length
    entry = FactorioProtocol::ACTIONS[131]
    refute_nil entry
    assert_equal 'deconstruct', entry[0]
    assert_equal 16, entry[1], 'deconstruct should be 16 bytes (area selection)'
  end

  def test_deconstruct_decodes_area
    # Simulate a server heartbeat action: count_flagged=0x04 (2 elems),
    # type=131 (deconstruct), delta=2, data=16 bytes
    pkt = build_server_tc_packet([
      { type: 131, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size, 'metadata after first action should be filtered'
    assert_equal 'deconstruct', actions[0][:name]
    assert_equal 2, actions[0][:game_player]

    d = actions[0][:data]
    assert_equal 16, d.bytesize
    rect = FactorioTypes::TileRect.from_data(d)
    refute_nil rect
    tx1, ty1 = rect.top_left.to_tiles
    tx2, ty2 = rect.bottom_right.to_tiles
    assert_in_delta(-352.387, tx1, 0.001)
    assert_in_delta(-349.043, tx2, 0.001)
  end

  # ── Server metadata filtering ──────────────────────────────────

  def test_server_echo_only_first_action_kept
    # count_flagged=0x04 (2 elems), first is real action, second is metadata
    pkt = build_server_tc_packet([
      { type: 131, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00] },
      { type: 245, delta: 162, data: [0xfe, 0xff] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size, 'second element should be filtered as metadata'
    assert_equal 'deconstruct', actions[0][:name]
  end

  def test_server_echo_with_tick_info_wrapper_keeps_real_action
    # Layout: [server_tick_info(84)][real action(131)][metadata]. The wrapper
    # must be kept (player delta chain) but the REAL action must survive too.
    pkt = build_server_tc_packet([
      { type: 84, delta: 1, data: [0x12, 0x8c, 0x19, 0xc8, 0x6b, 0xc4, 0xb1, 0x00, 0x00, 0x00, 0x00, 0x00] },
      { type: 131, delta: 33, data: [0] * 16 },
      { type: 245, delta: 162, data: [0xfe, 0xff] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 2, actions.size, 'wrapper + real action kept, metadata dropped'
    assert_equal 84, actions[0][:type]
    assert_equal 'deconstruct', actions[1][:name]
    assert_equal 33, actions[1][:player]   # delta 33 relative to wrapper player 0
    assert_equal 34, actions[1][:game_player]
  end

  def test_client_heartbeat_keeps_all_actions
    # Client heartbeat should NOT filter metadata (is_server=false)
    pkt = build_client_tc_packet([
      { type: 131, delta: 2, data: [0x9d, 0x9f, 0xfe, 0xff, 0x1c, 0xae, 0x01, 0x00,
                                      0xf5, 0xa2, 0xfe, 0xff, 0xcc, 0xcf, 0x01, 0x00] },
      { type: 245, delta: 162, data: [0xfe, 0xff] }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 2, actions.size, 'client heartbeat should keep all actions'
  end

  # ── C→S closure [tick][pad] trailer (phantom-player regressions) ──
  #
  # Client tick closures carry ONE 8-byte [tick(4)][pad(4)] trailer after the
  # LAST action. Previously the parser added +8 to EVERY hover/zoom/pan action
  # (60/128/129/262/265-268/310) and treated selected_entity_cleared (9) as
  # 8 bytes of data, so with 2+ actions it swallowed the next action's header
  # and re-parsed leftover payload bytes as phantom actions with bogus player
  # deltas (live captures: Player_192 swap_tile_slots, Player_64
  # drag_train_wait_condition). Only the last action may consume the trailer.

  def test_client_zoom_x2_no_phantom
    # Two zoom_around_point actions in one C→S closure. The first (intermediate)
    # action must NOT get the +8 trailer, or it eats the second zoom's header
    # (80 00) and the tail of its payload (f0 bf) becomes swap_tile_slots with a
    # bogus delta.
    data24 = [0] * 24
    pkt = build_client_tc_packet([
      { type: 128, delta: 1, data: data24 },
      { type: 128, delta: 0, data: data24 },
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 2, actions.size
    actions.each_with_index do |a, i|
      assert_equal 128, a[:type], "action #{i} type"
      assert_equal 0, a[:player], "action #{i} must stay on player 0 (no phantom delta)"
    end
    assert_equal 24, actions[0][:data].bytesize, 'intermediate zoom: payload only, no +8'
  end

  def test_client_selected_entity_cleared_intermediate_has_no_data
    # selected_entity_cleared (9) has no data of its own in C→S — the 8 bytes
    # ACTIONS lists are the closure [tick][pad] trailer, which only belongs to
    # the last action. As an intermediate action it must consume 0 bytes or it
    # swallows the following action's header.
    pkt = build_client_tc_packet([
      { type: 9, delta: 1, data: [] },
      { type: 69, delta: 0, data: [0] * 16 },  # start_walking
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal [9, 69], actions.map { |a| a[:type] }
    assert_equal '', actions[0][:data].unpack1('H*'), 'intermediate cleared has no data'
    assert actions.all? { |a| a[:player] == 0 }
  end

  def test_client_266_followed_by_start_walking
    # selected_entity_changed_very_close (1B payload) + start_walking in one
    # closure. The 266 must not consume +8 or it eats start_walking's header.
    pkt = build_client_tc_packet([
      { type: 266, delta: 1, data: [0x84] },
      { type: 69, delta: 0, data: [0] * 16 },
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal [266, 69], actions.map { |a| a[:type] }
    assert_equal '84', actions[0][:data].unpack1('H*')
    assert_equal 16, actions[1][:data].bytesize
    assert actions.all? { |a| a[:player] == 0 }
  end

  def test_client_drag_build_carries_position
    # C→S drag build: 21-byte data = 9B pos + 01 01 marker + 10B headerless
    # drag position. Reading only 11B left the position to be re-parsed as a
    # phantom action (zoom Player_252 from the position's x-byte 0x80).
    pkt = build_client_tc_packet([
      { type: 68, delta: 2, data: [0x80, 0xfb, 0xff, 0xff, 0x80, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01,
                                    0x80, 0xfb, 0xff, 0xff, 0x80, 0x04, 0x00, 0x00, 0x00, 0x10] },
      { type: 9, delta: 0, data: [] },
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal [68, 9], actions.map { |a| a[:type] }
    assert_equal 21, actions[0][:data].bytesize, 'drag build carries both positions'
    assert actions.all? { |a| a[:player] == 1 }
  end

  # ── Build action (type 68) ─────────────────────────────────────

  def test_build_data_length
    entry = FactorioProtocol::ACTIONS[68]
    assert_equal ['build', 9], entry
  end

  def test_build_decodes_position_and_dir
    # build data: x= -656.5 * 256 = -168064, y= -99.5 * 256 = -25472, dir=0 (north)
    x = (-656.5 * 256).to_i
    y = (-99.5 * 256).to_i
    data = [x].pack('i') + [y].pack('i') + [0].pack('C')
    assert_equal 9, data.bytesize

    pkt = build_client_tc_packet([
      { type: 68, delta: 2, data: data.bytes }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size
    assert_equal 'build', actions[0][:name]

    d = actions[0][:data]
    bx = d.unpack1('i', offset: 0)
    by = d.unpack1('i', offset: 4)
    dir = d.getbyte(8)
    assert_in_delta(-656.5, bx / 256.0, 0.01)
    assert_in_delta(-99.5, by / 256.0, 0.01)
    assert_equal 0, dir
  end

  # ── Chat message decoding (write_to_console) ──────────────────
  # These test the REAL implementation (FactorioProtocol.decode_chat),
  # not a private copy — regression guards against truncation bugs.

  def test_chat_segment_format
    # [0x05][meta][text...]
    data = [0x05, 0x2b] + 'missing some turret coverage in the middle?'.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal 'missing some turret coverage in the middle?', msg
  end

  def test_chat_long_message_split
    # First segment: [0x05][total_len=163][first 98 bytes]
    # meta is the TOTAL message length; text runs to end of payload.
    first = 'I was also thinking of mod to unlock all qualities from start so there is more focus on quality. an'
    second = "d there's mods that add additional quality tiers after legendary."
    total_len = first.bytesize + second.bytesize
    assert_equal 164, total_len

    data = [0x05, total_len] + first.bytes.to_a
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal first, msg

    # Second segment: raw continuation text (no prefix)
    msg2 = FactorioProtocol.decode_chat(second.bytes.to_a.pack('C*'))
    assert_equal second, msg2
  end

  def test_chat_0x0b_format
    # [0x0b][meta][text...] — observed live on 2026-08-11.
    # Truncation bug: 0x0b was unhandled, fell through to uint32v which
    # read 0x0b=11 as text length → ",that nuke " instead of full message.
    text = 'that nuke is not gonna be finished this hour'
    data = [0x0b, text.bytesize] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_0x15_and_0x2d_prefixes
    # Live-observed chat tones: [0x15]/[0x2d][meta][text...] — previously
    # unhandled (returned raw bytes incl. the prefix).
    assert_equal 'i get the reference',
                 FactorioProtocol.decode_chat(([0x15, 19] + 'i get the reference'.bytes).pack('C*'))
    assert_equal 'good', FactorioProtocol.decode_chat(([0x2d, 4] + 'good'.bytes).pack('C*'))
  end

  def test_chat_0x1f_and_0x30_prefixes
    # More live-observed tones: GPS pings use 0x1f; 0x30 is '0'.
    assert_equal '[gps=-64.6,93.2]',
                 FactorioProtocol.decode_chat(([0x1f, 16] + '[gps=-64.6,93.2]'.bytes).pack('C*'))
    assert_equal 'hey', FactorioProtocol.decode_chat(([0x30, 3] + 'hey'.bytes).pack('C*'))
    # 0x30 is '0' — a raw message starting with '0' must NOT be stripped
    # unless byte1 is a plausible length.
    assert_equal "0\x00raw", FactorioProtocol.decode_chat("0\x00raw".b)
  end

  def test_chat_0x30_empty_message
    assert_nil FactorioProtocol.decode_chat("0\x00".b)
  end

  def test_chat_server_echo_3d_format
    # [0x3d][meta][text...]
    text = 'Do we need the legendary insect eggs?'
    data = [0x3d, text.bytesize] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_server_echo_01_format
    # [0x01][meta][text...]
    text = 'spoilage may break the system'
    data = [0x01, text.bytesize] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_uint32v_prefixed
    # Main action list format (not from segments): uint32v length + text
    text = 'short message'
    len = text.bytesize
    data = [len] + text.bytes
    msg = FactorioProtocol.decode_chat(data.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_raw_text
    # No prefix at all
    text = 'raw text here'
    msg = FactorioProtocol.decode_chat(text.bytes.to_a.pack('C*'))
    assert_equal text, msg
  end

  def test_chat_nil_on_empty
    assert_nil FactorioProtocol.decode_chat(''.b)
    assert_nil FactorioProtocol.decode_chat(nil)
  end

  # ── Player delta calculation ───────────────────────────────────

  def test_player_delta_calculation
    # last_index starts at 0xFFFF, delta=2 → raw=1, game=2
    pkt = build_client_tc_packet([
      { type: 131, delta: 2, data: [0] * 16 }
    ])
    result = FactorioProtocol.parse_udp_payload(pkt)
    actions = extract_actions(result)
    assert_equal 1, actions.size
    assert_equal 1, actions[0][:player]   # raw
    assert_equal 2, actions[0][:game_player]  # game (1-indexed)

    # Second action with delta=11: raw = 1+11 = 12, game = 13
    pkt2 = build_client_tc_packet([
      { type: 131, delta: 2, data: [0] * 16 },
      { type: 83, delta: 11, data: [0] * 5 }
    ])
    result2 = FactorioProtocol.parse_udp_payload(pkt2)
    actions2 = extract_actions(result2)
    assert_equal 2, actions2.size
    assert_equal 12, actions2[1][:player]   # raw
    assert_equal 13, actions2[1][:game_player]  # game
  end

  # ── Network header parsing ─────────────────────────────────────

  def test_network_header_parsing
    # 0x07 = msg_type 7 (ServerToClientHeartbeat), no flags
    data = [0x07].pack('C')
    hdr = FactorioProtocol.parse_network_header(data)
    refute_nil hdr
    assert_equal 7, hdr[:msg_type]
    assert_equal 'ServerToClientHeartbeat', hdr[:msg_name]
    refute hdr[:has_random]
    refute hdr[:fragmented]
  end

  def test_network_header_with_random
    # 0x27 = msg_type 7 (ServerToClientHeartbeat), has_random=true
    data = [0x27].pack('C')
    hdr = FactorioProtocol.parse_network_header(data)
    refute_nil hdr
    assert_equal 7, hdr[:msg_type]
    assert hdr[:has_random]
  end

  # ── Action name / len lookup ───────────────────────────────────

  def test_action_name_known
    assert_equal 'deconstruct', FactorioProtocol.action_name(131)
    assert_equal 'build', FactorioProtocol.action_name(68)
    assert_equal 'write_to_console', FactorioProtocol.action_name(106)
  end

  def test_action_name_unknown
    assert_equal 'Unknown(999)', FactorioProtocol.action_name(999)
  end

  def test_action_len_known
    assert_equal 16, FactorioProtocol.action_len(131)  # deconstruct (fixed to 16)
    assert_equal 9, FactorioProtocol.action_len(68)    # build
    assert_nil FactorioProtocol.action_len(106)         # write_to_console (variable)
  end

  # ── uint16v / uint32v decoding ────────────────────────────────

  def test_decode_uint16v_single_byte
    data = [0x2a].pack('C')
    off, val = FactorioProtocol.decode_uint16v(data, 0)
    assert_equal 1, off
    assert_equal 0x2a, val
  end

  def test_decode_uint16v_escape
    data = [0xff, 0x34, 0x12].pack('C*')
    off, val = FactorioProtocol.decode_uint16v(data, 0)
    assert_equal 3, off
    assert_equal 0x1234, val
  end

  def test_decode_uint32v_single_byte
    data = [0x7f].pack('C')
    off, val = FactorioProtocol.decode_uint32v(data, 0)
    assert_equal 1, off
    assert_equal 0x7f, val
  end

  def test_decode_uint32v_escape
    data = [0xff, 0x78, 0x56, 0x34, 0x12].pack('C*')
    off, val = FactorioProtocol.decode_uint32v(data, 0)
    assert_equal 5, off
    assert_equal 0x12345678, val
  end

  private

  # Build a complete server-to-client heartbeat UDP packet with the given actions.
  # Returns the raw UDP payload bytes.
  def build_server_tc_packet(actions)
    build_heartbeat_packet(actions, is_server: true)
  end

  # Build a complete client-to-server heartbeat UDP packet with the given actions.
  def build_client_tc_packet(actions)
    build_heartbeat_packet(actions, is_server: false)
  end

  def build_heartbeat_packet(actions, is_server:)
    # Net header: 0x07 = msg_type 7 (S2C) or 0x06 = msg_type 6 (C2S)
    net_type = is_server ? 0x07 : 0x06
    parts = [].pack('C*')

    # Assemble the tick closure with actions
    tc_parts = []
    actions.each do |act|
      type_bytes = act[:type] < 0xFF ? [act[:type]].pack('C') : [0xFF].pack('C') + [act[:type]].pack('v')
      delta_bytes = act[:delta] < 0xFF ? [act[:delta]].pack('C') : [0xFF].pack('C') + [act[:delta]].pack('v')
      data_bytes = act[:data].pack('C*')
      tc_parts << type_bytes << delta_bytes << data_bytes
    end

    # count_flagged: count = actions.size, segments = 0
    count_flagged = (actions.size << 1) | 0
    cflag_byte = count_flagged < 0xFF ? [count_flagged].pack('C') : [0xFF].pack('C') + [count_flagged].pack('V')

    # Tick closure: tick (8 bytes) + count_flagged + actions
    tick = [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')  # tick = 0
    tc = tick + cflag_byte + tc_parts.join

    # Heartbeat flags: has_tick_closures=true, has_single_tick_closure=true
    hb_flags = 0x02 | 0x04  # has_tc + single_tc
    # For client: also set has_synchronizer_action? No.
    hb_flags_byte = [hb_flags].pack('C')

    # seq (4 bytes)
    seq = [1, 0, 0, 0].pack('V')

    hb_data = hb_flags_byte + seq + tc

    # For client heartbeat, append next_receive (8 bytes)
    unless is_server
      hb_data += [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')
    end

    # Net header + heartbeat data
    net_hdr = [net_type].pack('C')
    net_hdr + hb_data
  end

  # Extract actions from a parsed UDP payload result
  def extract_actions(result)
    return [] unless result && result[:heartbeat]
    hb = result[:heartbeat]
    hb[:tick_closures]&.flat_map { |tc| tc[:actions] } || []
  end
end
