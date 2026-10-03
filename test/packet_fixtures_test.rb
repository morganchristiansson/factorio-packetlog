#!/usr/bin/env ruby
# frozen_string_literal: true

# Fixture-driven regression tests.
# Run: ruby -Ilib test/packet_fixtures_test.rb
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

  # Simulate FactorioPacketTools#chat_action_data reassembly: merge segments of
  # a split write_to_console (keyed by player, ordered by seg_no) and return
  # the full payload. Mirrors the sniffer so the reassembly path is tested
  # end-to-end.
  def reassemble(split_actions)
    by_player = Hash.new { |h, k| h[k] = {} }
    split_actions.each { |act| by_player[act[:game_player]][act[:seg_no]] = act[:data] }
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
      refute hb[:hit_unknown], "#{fx[:name]}: heartbeat reported hit_unknown"
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
  # Every MEASURED C→S length (C2S_LENS_20) should be pinned by a real packet,
  # so regenerating the table from a smaller capture cannot silently drop a fix
  # and desync live traffic again. Zero-length entries are exempt: there is no
  # payload to distinguish "0" from "absent", so no packet can pin them.
  #
  # The rest are acknowledged here, with a reason. That list is the honest
  # state of coverage, not a to-do: each entry is a length whose only evidence
  # is the capture set in captures/, and adding a packet for it means deleting
  # its line here.
  UNPINNED_LENGTHS = {
    63 => 'open_blueprint_library_gui: 6 closures via measure_action_lens.rb --type; the fixture set has no open_blueprint_library_gui packet',
    64 => 'identified later, no single-action packet in the fixture set',
    94 => 'UNIDENTIFIED: 6 closures; length is decided but the NAME still needs /toggle-action-logging',
    246 => 'remote_view_entity: 6 closures; no single-action packet in the fixture set',
    75 => 'open_equipment: only 5 anchorable closures',
    83 => 'craft: 17 closures, later captures disagree (0/8/8 bytes)',
    85 => 'change_shooting_state: 9 vs the inherited 9, no clean packet',
    92 => 'set_filter: content-dependent (8 or 9), majority only',
    93 => 'set_spoil_priority: 3 closures',
    95 => 'set_circuit_condition: 30 closures, no single-action packet',
    99 => 'set_logistic_filter_item: content-dependent (22 or 23)',
    101 => 'set_circuit_mode_of_operation: 19 closures',
    107 => 'change_active_item_group_for_crafting: content-dependent',
    108 => 'change_active_item_group_for_filters: 163 closures, no single-action packet',
    119 => 'use_item: 5 closures',
    120 => 'send_spidertron: 5 closures',
    133 => 'blueprint-record family: 1-16 closures each, no single-action packet',
    134 => 'copy_opened_blueprint: blueprint-record family, 5 closures',
    135 => 'copy_large_opened_blueprint: blueprint-record family, 5 closures',
    136 => 'reassign_blueprint: blueprint-record family, 5 closures',
    137 => 'open_blueprint_record: blueprint-record family, 5 closures',
    139 => 'drop_blueprint_record: blueprint-record family, 5 closures',
    144 => 'set_ghost_cursor: 38 closures via the candidate search (the tool\'s own tally prefers 3 from 6 — the search is the better evidence), no single-action packet',
    151 => 'import_blueprint: 5 closures',
    155 => 'cancel_deconstruct: 51 closures; same shape as upgrade/copy (2x8-byte records + entity ref) and pinned by neither',
    168 => 'change_programmable_speaker_alert_parameters: 5 closures',
    235 => 'unidentified: 13 closures',
    253 => 'selected_entity_changed_relative: 19 closures via the candidate search',
    267 => 'fast_entity_split: 222 closures, never alone in a closure',
    294 => 'render_mode_changed: 683 occurrences, 9 bytes (mode + 4 i16); no single-action packet in the fixture set',
    138 => 'grab_blueprint_record: 13 closures',
    150 => 'export_blueprint: 6 closures',
    152 => 'import_blueprints_filtered: 5 closures',
    160 => 'modify_decider_combinator_condition: 5 closures',
    184 => 'custom_input: SCRIPT-DEFINED, no fixed length; the table value is the majority of what we saw',
    212 => 'unidentified: 5 closures',
    232 => 'quick_bar_set_selected_page: 79 closures, no single-action packet',
    231 => 'quick_bar_pick_slot: 4 bytes ([item][slot][op][pad]) measured by tools/measure_action_lens.rb --type 231 — 1126 single-action closures vs 62 for the runner-up; the 0 this name inherited from 2.1 desynced the rest of every closure containing one',
    239 => 'lua_shortcut: 12 closures',
    269 => 'trash_not_requested_items: 2 closures',
    286 => 'change_active_quick_bar: 2 closures',
    304 => 'set_pump_fluid_filter: 1 closure',
    323 => 'gui_hover: 10 closures',
    324 => 'gui_leave: 10 closures',
    331 => 'unidentified: 2 closures',

    16 => 'name and length both need /toggle-action-logging + more traffic', # ** UNIDENTIFIED **
    34 => 'name and length both need /toggle-action-logging + more traffic', # ** UNIDENTIFIED **
    56 => 'name and length both need /toggle-action-logging + more traffic', # ** UNIDENTIFIED **
    65 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # drop_item
    72 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # open_parent_of_opened_item
    73 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # destroy_item
    76 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # cursor_transfer
    86 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # setup_assembling_machine
    115 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # gui_switch_state_changed
    122 => 'name and length both need /toggle-action-logging + more traffic', # ** UNIDENTIFIED **
    123 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # zoom_around_point
    125 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # start_repair
    126 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # deconstruct
    153 => 'name and length both need /toggle-action-logging + more traffic', # ** UNIDENTIFIED **
    198 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # alt_reverse_select_area
    199 => 'name and length both need /toggle-action-logging + more traffic', # ** UNIDENTIFIED **
    217 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # swap_item_filters
    250 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # change_picking_state
    264 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # fast_entity_transfer
    265 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # rotate_entity
    289 => 'measured by tools/measure_action_lens.rb --type over the full captures; no single-action packet in the fixture set', # set_splitter_priority
  }.freeze

  def test_every_measured_length_is_pinned_or_acknowledged
    FactorioProtocol.select_version('2.0')
    seen = {}
    REAL_PACKET_FIXTURES.each do |fx|
      res = FactorioProtocol.parse_udp_payload([fx[:hex]].pack('H*')) rescue next
      next unless res && res[:heartbeat]
      res[:heartbeat][:tick_closures].to_a.each do |tc|
        (tc[:actions] || []).each { |a| seen[a[:type]] = (seen[a[:type]] || 0) + 1 }
      end
    end
    missing = FactorioProtocol.c2s_lens.reject { |type, len| len.zero? || seen[type].to_i.positive? }
    unpinned = missing.keys.sort
    stale = UNPINNED_LENGTHS.keys.sort - unpinned
    assert_empty stale, "these are pinned by a fixture now — drop them from UNPINNED_LENGTHS: #{stale.inspect}"
    assert_empty unpinned - UNPINNED_LENGTHS.keys,
                 "measured C→S lengths with no fixture and no acknowledgement: #{(unpinned - UNPINNED_LENGTHS.keys).inspect}"
  end

  # The content-defined parsers are code, not data: pin them separately, or a
  # layout change would only show up as "flagged packets", which nobody watches.
  def test_translate_string_layout_is_pinned
    FactorioProtocol.select_version('2.0')
    count = 1
    entry = [3].pack('C') + 'key' + [0x01, 0x00].pack('C2') + [2].pack('C') + 'hi' + ("\x00" * 9)
    payload = [count].pack('C') + entry
    data = [0x26, 0x06, 0, 0, 0, 0].pack('C*') + [0].pack('Q<') + [0x02].pack('C') +
           [240, 0x00].pack('C2') + payload + [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')
    acts = FactorioProtocol.parse_udp_payload(data).dig(:heartbeat, :tick_closures).first[:actions]
    assert_equal 1, acts.size
    assert_equal 240, acts[0][:type]
    refute acts[0][:hit_unknown], 'translate_string must consume exactly count entries + 9-byte argument block'
  end

  # A translate_string whose entries run past the end of the payload used to
  # raise out of the decode (the key length was added to 3 BEFORE the nil
  # check), which killed the whole packet on the capture thread — the
  # operator saw a backtrace and a dead sniffer, not a flagged packet. A
  # truncated one is simply unknown from there on.
  def test_truncated_translate_string_does_not_raise
    FactorioProtocol.select_version('2.0')
    entry = [3].pack('C') + 'key' + [0x01, 0x00].pack('C2') + [2].pack('C') + 'hi' + ("\x00" * 9)
    # count says 2 entries, only one is there — the second read is off the end
    payload = [2].pack('C') + entry
    data = [0x26, 0x06, 0, 0, 0, 0].pack('C*') + [0].pack('Q<') + [0x02].pack('C') +
           [240, 0x00].pack('C2') + payload
    result = nil
    assert_silent { result = FactorioProtocol.parse_udp_payload(data) }
    acts = result.dig(:heartbeat, :tick_closures).first[:actions]
    assert acts.any? { |a| a[:type] == 240 }, 'the action is still seen'
    assert acts.any? { |a| a[:hit_unknown] }, 'and flagged unknown instead of crashing the sniffer'
  end
end
