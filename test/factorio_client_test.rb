# frozen_string_literal: true

# Round-trip check for the client-side encoders (lib/factorio_protocol/build.rb):
# every layout is rebuilt from the REAL bytes out of the captures and must come
# back identical. If an encoder drifts from the wire, this fails instead of the
# server silently dropping our session.

require 'minitest/autorun'
require_relative '../lib/factorio_protocol'
require_relative '../lib/factorio_protocol/build'
require_relative '../lib/factorio_wire'

class FactorioClientBuildTest < Minitest::Test
  # Real msg 2, captures/server-34197-20261003-170056.pcap pkt 6353 (Jeff-nf,
  # 2026-10-03): 2.0.77, build field 0x00014a3b. NOTE the build is a full u32
  # and ConnectionRequestPacket masks it to 16 bits when printing (19003), so
  # the value to send is the whole 0x00014a3b.
  MSG2 = ['02000002004d3b4a0100da3edbde'].pack('H*')

  # Real msg 4 with an empty session and 4 mods, pkt 7162 (ruihd's first join,
  # same capture) — the shape a token-less observer client sends, minus the mod
  # list (we claim none until we know a server accepts that).
  MSG4_NO_SESSION = ['040100aa19deb8537deedd0421924a05727569686400000075b59ef968f372c404046261736502004d869c05700e656c6576617465642d7261696c73'].pack('H*')

  # Real msg 4 WITH the session token the server handed back, pkt 7369
  # (ruihd's second join, same capture).
  MSG4_TOKEN = ['040100bcabeab133fa48d7858242f1074a6566662d6e660018436e4b55524c52506f5038463149506d76434c3131773d3d0c32363130303331343530'].pack('H*')

  # Real idle C→S heartbeat, captures/server-34197-20261003-192159.pcap pkt 22:
  # three EMPTY tick closures + a next_receive + one sync action.
  MSG6_IDLE = ['061a1a952d24038015340800000000811534080000000082153408000000008d1534080000000001109215340800000000'].pack('H*')

  # Real client heartbeats with ClientChangedState sync actions from
  # handshake.pcap (port 33291 ↔ 34197). These are the state-machine
  # transitions the server needs to not drop the client.

  # State(2) right after handshake: 06105edd040bf912000000000000010302
  HB_STATE_2 = ['06105edd040bf912000000000000010302'].pack('H*')

  # State(3) + MapDownloading(0): 261064dd040bfa120000000000000203030900
  HB_STATE_3_DL_0 = ['261064dd040bfa120000000000000203030900'].pack('H*')

  # State(4) + MapLoading(0) + MapDownloading(255): 061086dd040b1c13000000000000030304060009ff
  HB_STATE_4 = ['061086dd040b1c13000000000000030304060009ff'].pack('H*')

  # State(6) + CatchUp(255): 26108ddd040b23130000000000000203060aff
  HB_STATE_6 = ['26108ddd040b23130000000000000203060aff'].pack('H*')

  # State(7): 261090dd040b2613000000000000010307
  HB_STATE_7 = ['261090dd040b2613000000000000010307'].pack('H*')

  # Empty closure (0x0E flags): 060e8cdd040b48130000000000002c13000000000000
  HB_EMPTY_CLOSURE = ['060e8cdd040b48130000000000002c13000000000000'].pack('H*')

  def test_connection_request_rebuilds_the_captured_bytes
    got = FactorioProtocol.build_connection_request(version: '2.0.77', build: 0x0001_4a3b,
                                                    client_id: 0xdedb3eda)
    assert_equal MSG2, got
    parsed = FactorioProtocol.parse_udp_payload(got)[:connection_request]
    assert_equal '2.0.77 (build 84539)', parsed[:version]
    assert_equal 0xdedb3eda, parsed[:client_id]
  end

  def test_connection_confirm_without_a_session_rebuilds_the_captured_bytes
    built = FactorioProtocol.build_connection_confirm(
      username: 'ruihd', connection_id: ['75b59ef968f372c4'].pack('H*'), client_id: 0xb8de19aa,
      server_id: 0xddee7d53, instance_id: 0x4a922104
    )
    assert_equal MSG4_NO_SESSION[0, 32], built[0, 32] # through the connection id
    parsed = FactorioProtocol.parse_udp_payload(built)[:connection_confirm]
    assert_equal 'ruihd', parsed[:username]
    assert_equal '', parsed[:session][:token]
    assert_equal '75b59ef968f372c4', parsed[:session][:connection_id]
    assert_empty parsed[:mods]         # we claim no mods; the real client sent 4
    assert_equal({}, parsed[:settings]) # the empty tree is 6 bytes that decode to {}
  end

  def test_connection_confirm_with_a_token_decodes_back
    token = 'CnKURLRPoP8F1IPmvCL11w=='
    built = FactorioProtocol.build_connection_confirm(
      username: 'Jeff-nf', connection_id: ['75b59ef968f372c4'].pack('H*'), client_id: 0xbcabeab1,
      server_id: 0x33fa48d7, instance_id: 0x858242f1, token: token,
      client_time: '261003145007', mods: [['base', '2.0.77', 1879415942]]
    )
    parsed = FactorioProtocol.parse_udp_payload(built)[:connection_confirm]
    assert_equal 'Jeff-nf', parsed[:username]
    assert_equal token, parsed[:session][:token]
    assert_equal '261003145007', parsed[:session][:client_time]
    assert_equal [['base', '2.0.77', 1879415942]], parsed[:mods]
    assert_equal({}, parsed[:settings])
    refute parsed[:settings_truncated]
  end

  def test_idle_heartbeat_rebuilds_the_captured_bytes
    built = FactorioProtocol.build_client_heartbeat(
      seq: 606_967_066, next_receive: 137_631_117,
      closures: [[137_631_104, 0, ''], [137_631_105, 0, ''], [137_631_106, 0, '']],
      requests: []
    )
    # Everything from the sequence number on is identical. Our flags byte is
    # 0x0a where the client's is 0x1a: we send no synchronizer actions.
    assert_equal MSG6_IDLE[2, 37], built[2, 37]
    hb = FactorioProtocol.parse_udp_payload(built)[:heartbeat]
    assert_equal 606_967_066, hb[:seq]
    assert_equal [137_631_104, 137_631_105, 137_631_106], hb[:tick_closures].map { |tc| tc[:tick] }
    assert_equal 137_631_117, hb[:next_receive]
    assert(hb[:all_tick_closures_are_empty])
  end

  def test_a_heartbeat_with_an_action_decodes_back_as_that_action
    # set_player_color (2.0 wire 296): 4 UNORM bytes, so the parser reads the
    # data back whole.
    action = FactorioProtocol.build_input_action(296, 3, "\x01\x02\x03\x04".b) +
             [137_631_110, 0].pack('VV') # the closure trailer
    built = FactorioProtocol.build_client_heartbeat(
      seq: 1, next_receive: 137_631_111, closures: [[137_631_110, 1, action]]
    )
    hb = FactorioProtocol.parse_udp_payload(built)[:heartbeat]
    assert_equal 1, hb[:tick_closures].size
    assert_equal 1, hb[:tick_closures][0][:actions].size
    a = hb[:tick_closures][0][:actions][0]
    assert_equal 296, a[:type]
    assert_equal 'set_player_color', a[:name]
    assert_equal 3, a[:game_player] # (0xFFFF + delta 3) & 0xFFFF = 2, +1 = 3
    assert_equal "\x01\x02\x03\x04".b, a[:data]
  end

  # ── ClientChangedState sync action heartbeats (handshake.pcap) ──

  def test_state_2_sync_action_rebuilds_the_captured_bytes
    sync = [FactorioProtocol.build_sync_action(0x03, [2].pack('C'))]
    built = FactorioProtocol.build_client_heartbeat(
      seq: 0x0b_04_dd_5e, next_receive: 4857, closures: [], sync_actions: sync
    )
    assert_equal HB_STATE_2, built
    hb = FactorioProtocol.parse_udp_payload(built)[:heartbeat]
    assert_equal [{ state: 2 }], hb[:sync_actions].map { |a| { state: a[:state] } }
  end

  def test_state_3_with_download_progress_rebuilds_the_captured_bytes
    sync = [
      FactorioProtocol.build_sync_action(0x03, [3].pack('C')),
      FactorioProtocol.build_sync_action(0x09, [0].pack('C'))
    ]
    built = FactorioProtocol.build_client_heartbeat(
      seq: 0x0b_04_dd_64, next_receive: 4858, closures: [],
      sync_actions: sync, has_random: true
    )
    assert_equal HB_STATE_3_DL_0, built
    hb = FactorioProtocol.parse_udp_payload(built)[:heartbeat]
    assert_equal [{ state: 3 }, { name: 'MapDownloadingProgressUpdate' }],
                 hb[:sync_actions].map { |a| a[:name] == 'ClientChangedState' ? { state: a[:state] } : { name: a[:name] } }
  end

  def test_state_4_with_map_loading_rebuilds_the_captured_bytes
    sync = [
      FactorioProtocol.build_sync_action(0x03, [4].pack('C')),
      FactorioProtocol.map_loading_sync_action(0),
      FactorioProtocol.build_sync_action(0x09, [255].pack('C'))
    ]
    built = FactorioProtocol.build_client_heartbeat(
      seq: 0x0b_04_dd_86, next_receive: 4892, closures: [], sync_actions: sync
    )
    assert_equal HB_STATE_4, built
  end

  def test_state_6_with_catchup_rebuilds_the_captured_bytes
    sync = [
      FactorioProtocol.build_sync_action(0x03, [6].pack('C')),
      FactorioProtocol.build_sync_action(0x0a, [255].pack('C'))
    ]
    built = FactorioProtocol.build_client_heartbeat(
      seq: 0x0b_04_dd_8d, next_receive: 4899, closures: [],
      sync_actions: sync, has_random: true
    )
    assert_equal HB_STATE_6, built
  end

  def test_state_7_rebuilds_the_captured_bytes
    sync = [FactorioProtocol.build_sync_action(0x03, [7].pack('C'))]
    built = FactorioProtocol.build_client_heartbeat(
      seq: 0x0b_04_dd_90, next_receive: 4902, closures: [],
      sync_actions: sync, has_random: true
    )
    assert_equal HB_STATE_7, built
  end

  def test_empty_closure_rebuilds_the_captured_bytes
    built = FactorioProtocol.build_client_heartbeat(
      seq: 0x0b_04_dd_8c, closures: [[4936, 0, '']], next_receive: 4908
    )
    assert_equal HB_EMPTY_CLOSURE, built
    hb = FactorioProtocol.parse_udp_payload(built)[:heartbeat]
    assert_equal 0x0e, hb[:flags]
    refute hb[:has_synchronizer_action]
    assert hb[:all_tick_closures_are_empty]
  end
end
