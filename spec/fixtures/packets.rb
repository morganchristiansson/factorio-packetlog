# frozen_string_literal: true

# Real packets captured from live Factorio sessions (ground truth).
#
# Each fixture is a raw UDP payload (`hex`) plus the EXPECTED parse result:
# the actions produced by FactorioProtocol.parse_udp_payload, in order.
# `data` is the hex of the action's data bytes ('' for empty, nil when the
# parser could not capture data). `chat` (optional) is the expected result of
# FactorioProtocol.decode_chat on that action's data.
#
# These packets come from live captures (2026-08-11, factorio_capture.pcap)
# and their expected output was verified against the actual gameplay session.
#
# NOTE: Client input actions carry an 8-byte trailing [tick(4)][pad(4)] field
# (the local game tick when the action occurred) that the server does not echo.
# For most actions it is left as unparsed trailing bytes; open_gui consumes it as
# part of its 8-byte client payload. Fixtures below lock in the current decoding.

REAL_PACKET_FIXTURES = [
  {
    name: 'client_chat_message_0x0b',
    description: 'Player_12 chat with 0x0b message-type prefix. Regression: was truncated to 11 bytes (",that nuke ")',
    hex: '060634195f3970b6b1000000000001016afc0000000b01002e0b2c74686174206e756b65206973206e6f7420676f6e6e612062652066696e6973686564207468697320686f75726cb6b10000000000',
    actions: [
      { type: 106, name: 'write_to_console', player: 11, game_player: 12,
        data: '0b2c74686174206e756b65206973206e6f7420676f6e6e612062652066696e6973686564207468697320686f7572',
        chat: 'that nuke is not gonna be finished this hour' },
    ],
  },
  {
    name: 'server_chat_echo_segment',
    description: 'Server echo of chat via segment (type 0x05, meta=0x22=34 total length)',
    hex: '0706ef7fb200e934b2000000000003540164ad0dd5e834b20000000000016a5c010000050100240522626172656c792067657420616e792069726f6e20776974682074686174207468656e',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '64ad0dd5e834b20000000000' },
      { type: 106, name: 'write_to_console', player: 5, game_player: 6,
        data: '0522626172656c792067657420616e792069726f6e20776974682074686174207468656e',
        chat: 'barely get any iron with that then' },
    ],
  },
  {
    name: 'server_empty_chat_echo',
    description: 'Server echo of a zero-length chat message [0x05][meta=0] — decodes to nil, not garbage',
    hex: '0706540fb2006cc4b10000000000035401128c19c86bc4b10000000000016a56010000050100020500',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '128c19c86bc4b10000000000' },
      { type: 106, name: 'write_to_console', player: 5, game_player: 6,
        data: '0500', chat: nil },
    ],
  },
  {
    name: 'server_build_echo',
    description: 'Server echo of a drag build (11-byte data) with server_tick_info wrapper',
    hex: '0706cd89b200c73eb20000000000045401d160516ac63eb200000000004439805000008044010000000012',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'd160516ac63eb20000000000' },
      { type: 68, name: 'build', player: 57, game_player: 58,
        data: '8050000080440100000000' },
    ],
  },
  {
    name: 'server_deconstruct_echo',
    description: 'Server echo of deconstruct (16-byte area selection)',
    hex: '0706a89fb2008454b20000000000065401650568b28354b2000000000083055e660100950100006066010097010000000001800000010934',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '650568b28354b20000000000' },
      { type: 131, name: 'deconstruct', player: 5, game_player: 6,
        data: '5e660100950100006066010097010000' },
    ],
  },
  {
    name: 'server_start_walking_echo',
    description: 'Server echo of start_walking (16-byte direction vector)',
    hex: '0706a87fb200a234b20000000000045401e4ec6d55a134b2000000000045390000000000000080000000000000f03f',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'e4ec6d55a134b20000000000' },
      { type: 69, name: 'start_walking', player: 57, game_player: 58,
        data: '0000000000000080000000000000f03f' },
    ],
  },
  {
    name: 'server_pipette_echo',
    description: 'Server echo of pipette (9 bytes: src, ref, quality)',
    hex: '07065e89b200583eb20000000000045401e0fde4de573eb200000000005a05001f0000000000010100',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'e0fde4de573eb20000000000' },
      { type: 90, name: 'pipette', player: 5, game_player: 6,
        data: '001f00000000000101' },
    ],
  },
  {
    name: 'server_cursor_split_echo',
    description: 'Server echo of cursor_split (5 bytes)',
    hex: '07063588b2002f3db2000000000004540187205d652e3db200000000004f0532000100000000000000000001240004',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '87205d652e3db20000000000' },
      { type: 79, name: 'cursor_split', player: 5, game_player: 6,
        data: '3200010000' },
    ],
  },
  {
    name: 'server_cursor_transfer_echo',
    description: 'Server echo of cursor_transfer (9 bytes)',
    hex: '07066b8cb2004741b20000000000045401906c7e924641b200000000004e05000000000000000000000001210004',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '906c7e924641b20000000000' },
      { type: 78, name: 'cursor_transfer', player: 5, game_player: 6,
        data: '000000000000000000' },
    ],
  },
  {
    name: 'server_stop_walking_echo',
    description: 'Server echo of stop_walking (0-byte data)',
    hex: '07065581b2004f36b200000000000454016be411054e36b20000000000013a',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '6be411054e36b20000000000' },
      { type: 1, name: 'stop_walking', player: 58, game_player: 59, data: '' },
    ],
  },
  {
    name: 'server_copy_echo',
    description: 'Server echo of copy (0-byte data)',
    hex: '0706138bb2000d40b20000000000065401b14eb08e0c40b20000000000852978eefdff23a7ffff30f1fdffbbacffff000001800000ff0a01008f',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'b14eb08e0c40b20000000000' },
      { type: 133, name: 'copy', player: 41, game_player: 42, data: '' },
    ],
  },
  {
    name: 'server_upgrade_echo',
    description: 'Server echo of upgrade (0-byte data)',
    hex: '070613b6b200ef6ab20000000000045401e629b394ee6ab200000000008429661d0100e4fd000096390100a400010000000180000000',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'e629b394ee6ab20000000000' },
      { type: 132, name: 'upgrade', player: 41, game_player: 42, data: '' },
    ],
  },
  {
    name: 'server_fast_entity_transfer_echo',
    description: 'Server echo of fast_entity_transfer (1-byte direction). Previously misnamed rotate_entity — live defines confirm 279=fast_entity_transfer',
    hex: '0706c8bdb200a472b200000000000454013e178eb7a372b20000000000ff17012401',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '3e178eb7a372b20000000000' },
      { type: 279, name: 'fast_entity_transfer', player: 36, game_player: 37,
        data: '01' },
    ],
  },
  {
    name: 'server_inventory_transfer_echo',
    description: 'Server echo of inventory_transfer (5 bytes)',
    hex: '0706fdb7b200d96cb200000000000454019b765daed86cb20000000000533900000000000000000000000160000100',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '9b765daed86cb20000000000' },
      { type: 83, name: 'inventory_transfer', player: 57, game_player: 58,
        data: '0000000000' },
    ],
  },
  {
    name: 'server_open_gui_echo_14b',
    description: 'Server echo of open_gui with entity ref appended (14 bytes: gui_type, flags, ref, token, tick)',
    hex: '0706db8eb200b743b20000000000085401b026e95ab643b200000000000505300045240000000000000080000000000000f03f',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'b026e95ab643b20000000000' },
      { type: 5, name: 'open_gui', player: 5, game_player: 6,
        data: '3000452400000000000000800000' },
    ],
  },
  {
    name: 'server_open_gui_echo_2b',
    description: 'Server echo of open_gui, bare 2-byte form [gui_type][flags] (no entity info — client sent empty open_gui)',
    hex: '07068687b200803cb20000000000065401a7fe29067f3cb2000000000005053000',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: 'a7fe29067f3cb20000000000' },
      { type: 5, name: 'open_gui', player: 5, game_player: 6,
        data: '3000' },
    ],
  },
  {
    name: 'server_chat_echo_random_flag_packet',
    description: 'Server heartbeat with random flag (0x27 header). Regression: heartbeat was parsed from byte 5 instead of 1, dropping ALL tick closures — this message was missing entirely',
    hex: '27068781b300e835b300000000000354015db76ddfe735b30000000000016a5e0100000501001a05186d6f6c74656e20737570706c79206e6f7420737461626c65',
    actions: [
      { type: 84, name: 'server_tick_info', player: 0, game_player: 1,
        data: '5db76ddfe735b30000000000' },
      { type: 106, name: 'write_to_console', player: 5, game_player: 6,
        data: '05186d6f6c74656e20737570706c79206e6f7420737461626c65',
        chat: 'molten supply not stable' },
    ],
  },
  {
    name: 'client_open_gui_8b',
    description: 'Client open_gui with 8-byte payload [gui_type][flags][tick][pad], followed by a trailing nothing action. Regression: parser assumed 2 bytes, misread the payload tail as phantom action add_decider_combinator_condition (bogus player 36)',
    hex: '06069060406fa7230400000000000405013000a423040000000000',
    actions: [
      { type: 5, name: 'open_gui', player: 0, game_player: 1,
        data: '3000a42304000000' },
      { type: 0, name: 'nothing', player: 0, game_player: 1, data: '' },
    ],
  },
  {
    name: 'client_open_gui_8b_2',
    description: 'Client open_gui, second capture (phantom action was select_next_valid_gun, bogus player 59)',
    hex: '26060f77406f263a0400000000000405013000233a040000000000',
    actions: [
      { type: 5, name: 'open_gui', player: 0, game_player: 1,
        data: '3000233a04000000' },
      { type: 0, name: 'nothing', player: 0, game_player: 1, data: '' },
    ],
  },
  {
    name: 'client_open_gui_8b_3',
    description: 'Client open_gui, third capture (phantom action was copy_opened_blueprint, bogus player delta)',
    hex: '06067787406f8e4a04000000000004050130008b4a040000000000',
    actions: [
      { type: 5, name: 'open_gui', player: 0, game_player: 1,
        data: '30008b4a04000000' },
      { type: 0, name: 'nothing', player: 0, game_player: 1, data: '' },
    ],
  },
  {
    name: 'client_selected_entity_cleared',
    description: 'Client selected_entity_cleared (8 bytes: tick + padding) — fires when the cursor leaves an entity; confirmed by /toggle-action-logging tick correlation',
    hex: '0606549b5f39ef38b2000000000002090ce738b20000000000',
    actions: [
      { type: 9, name: 'selected_entity_cleared', player: 11, game_player: 12,
        data: 'e738b20000000000' },
    ],
  },
  {
    name: 'client_stop_walking',
    description: 'Client stop_walking (0-byte data)',
    hex: '0606769c5f39113ab2000000000002010c0a3ab20000000000',
    actions: [
      { type: 1, name: 'stop_walking', player: 11, game_player: 12, data: '' },
    ],
  },
  {
    name: 'client_pipette',
    description: 'Client pipette (9 bytes)',
    hex: '060670e15f391a7fb20000000000025a0c041d00000000000101000e7fb20000000000',
    actions: [
      { type: 90, name: 'pipette', player: 11, game_player: 12,
        data: '041d00000000000101' },
    ],
  },
  {
    name: 'client_use_item',
    description: 'Client use_item (8 bytes: entity ref + position)',
    hex: '060672f85f390d96b20000000000027c0c14020000ac84fdff0396b20000000000',
    actions: [
      { type: 124, name: 'use_item', player: 11, game_player: 12,
        data: '14020000ac84fdff' },
    ],
  },
  {
    name: 'client_change_riding_state',
    description: 'Client change_riding_state (2 bytes)',
    hex: '0606eeda5f398a78b2000000000002470c01008378b20000000000',
    actions: [
      { type: 71, name: 'change_riding_state', player: 11, game_player: 12,
        data: '0100' },
    ],
  },
].freeze
