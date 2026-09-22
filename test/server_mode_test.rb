#!/usr/bin/env ruby
# frozen_string_literal: true

# Test server mode of factorio-sniffer.rb using real packet fixtures.
#
# Verifies:
#  1. Incoming (C→S, msg 6) packets ARE analyzed
#  2. Outgoing (S→C, msg 7) packets are SKIPPED (no broadcast duplicates)
#  3. TransferBlock (msg 13) packets are dropped: no analysis, no capture
#  4. Client mode still processes both directions (regression)
#  5. Server IP auto-detection from local interfaces
#  6. Server-mode banner printed via run() (live + pcap-read paths)
#
# Run: ruby -Ilib test/server_mode_test.rb

require 'minitest/autorun'
require 'tmpdir'
require_relative '../factorio-sniffer'
require_relative 'fixtures/packets'

class TestServerMode < Minitest::Test
  SERVER_IP = '192.168.1.10'
  CLIENT_IP = '192.168.1.50'

  def setup
    FactorioProtocol.reset_version
  end

  def teardown
    FactorioProtocol.reset_version
  end

  def fixture_packet(name)
    fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
    raise "no fixture #{name}" unless fx
    [fx[:hex]].pack('H*')
  end

  def msg13_packet
    # network header(1, msg 13) | block_number(4 LE) | 503 bytes payload
    "\x0d".b + [1234].pack('V') + ('A'.b * 503)
  end

  # Build a C→S heartbeat (msg 6) with a pure-segment closure carrying one
  # input-action segment (e.g. a fragment of a split chat message).
  def build_segment_packet(payload, total:, no:, green:)
    hdr = "\x06".b + "\x06".b        # msg 6 + flags (tick closures, single)
    seq = [1].pack('V')
    tick = [1_700_000_000].pack('Q<')
    count_flagged = [0x01].pack('C')  # count=0, has_segments
    seg_count = [1].pack('C')
    seg = [104].pack('C')              # seg_type = write_to_console (2.0)
    seg += [green].pack('V')           # blue (4 bytes, arbitrary)
    seg += [green].pack('C')           # green (uint16v, player)
    seg += [total].pack('C')           # total_segs (uint32v)
    seg += [no].pack('C')              # seg_no (uint32v)
    seg += [payload.bytesize].pack('C') # pay_len (uint32v)
    seg += payload
    hdr + seq + tick + count_flagged + seg_count + seg
  end

  # In-memory PcapWriter double: the real writer formats + flushes records to
  # disk (and spawns a background flusher thread); tests only care about WHICH
  # frames/packets the capture pipeline decides to write, so they record into a
  # buffer instead. `records` holds the exact bytes the real writer would have
  # framed (the raw Ethernet frame from write_frame, or the rebuilt IP/UDP
  # packet from write_packet). This keeps every capture assertion meaningful
  # while writing nothing — not even to /tmp.
  class FakePcapWriter
    attr_reader :path, :records

    # path is assertion-only (recorded verbatim); no file is ever created.
    def initialize(path = 'fake-capture.pcap')
      @path = path
      @records = []
      @closed = false
    end

    def write_frame(frame, _ts = Time.now)
      @records << frame.b
    end

    def write_packet(ip_payload)
      @records << ip_payload.b
    end

    def close
      @closed = true
    end
  end

  def run_sniffer(opts = {})
    kwargs = if opts[:pcap_writer]
               { pcap_writer: opts[:pcap_writer] }
             elsif opts[:autoname]
               {}
             else
               { pcap_writer: FakePcapWriter.new }
             end
    sniffer = FactorioSniffer.new(opts, **kwargs)
    begin
      output, = capture_io { yield sniffer }
    ensure
      sniffer.instance_variable_get(:@pcap_writer)&.close
    end
    [output, sniffer]
  end

  # Build a sniffer for tests with the auto-named capture replaced by an
  # in-memory FakePcapWriter — no test ever touches the repo's captures/ or
  # spawns a real flusher thread.
  def make_test_sniffer(opts = {})
    # pcap_writer is a KEYWORD param of new — inside the opts hash it is
    # inert, and swapping the ivar post-hoc orphans the real writer (banner +
    # flusher thread + real files). Pass it as the keyword it is.
    FactorioSniffer.new(opts, pcap_writer: FakePcapWriter.new)
  end

  def capture_records(sniffer)
    writer = sniffer.instance_variable_get(:@pcap_writer)
    writer.close
    writer.records.map { |record| record[14, record.bytesize - 14] }
  end

  def recording_agent
    events = []
    agent = Object.new
    agent.define_singleton_method(:events) { events }
    agent.define_singleton_method(:on_player_event) { |kind, name| events << [kind, name] }
    agent.define_singleton_method(:on_chat) { |_player, _message| }
    agent.define_singleton_method(:enqueue) { |method, *args, **_kwargs| public_send(method, *args) }
    agent
  end

  # ── Test 1: server mode, live capture (raw_frame present) ─────────────

  def test_server_mode_live_capture
    output, sniffer = run_sniffer(
      server: true, server_ip: SERVER_IP, player_db: nil
    ) do |sniffer|
      ts = 1_700_000_000.0
      # incoming client chat (msg 6) — should be analyzed
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'), "\x00" * 14 + fixture_packet('client_chat_message_0x0b'))
      # outgoing server echo (msg 7) — should be skipped as broadcast duplicate
      sniffer.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_chat_echo_segment'), "\x00" * 14 + fixture_packet('server_chat_echo_segment'))
      # outgoing TransferBlock (msg 13) — should be dropped entirely
      sniffer.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet, "\x00" * 14 + msg13_packet)
      sniffer.send(:print_summary)
    end

    assert_includes output, 'Player_12: that nuke is not gonna be finished this hour',
                    'incoming client chat decoded and logged'
    refute_includes output, 'barely get any iron', 'OUTGOING server echo NOT logged'
    assert_includes output, 'outgoing broadcasts skipped (server mode)=1',
                    "outgoing counter == 1 (got: #{output[/outgoing broadcasts skipped[^\n]*/].inspect})"
    refute_includes output, '[summary] packets=4', 'no packet 4 expected (all 3 accounted for)'

    # capture: only the incoming client packet is captured — outgoing
    # server broadcasts and msg13 TransferBlocks are excluded from capture in
    # server mode (analysis never reads them; --full-capture keeps everything).
    # The FakePcapWriter records exactly what the real writer would have framed.
    writer = sniffer.instance_variable_get(:@pcap_writer)
    writer.close
    records = writer.records
    # synthetic frames: [eth(14)][udp payload] — strip eth to inspect the payload
    payloads = records.map { |record| record[14, record.bytesize - 14] }
    assert_equal 1, records.size, "capture has 1 record (client only), echo + msg13 excluded (got #{records.size})"
    assert payloads.none? { |payload| payload.bytesize >= 500 }, 'no 503-byte TransferBlock payloads in capture'
  end

  # ── Test 2: server mode, pcap-read path (no raw_frame) ────────────────

  def test_server_mode_pcap_read_path
    output, = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil, debug: true) do |sniffer|
      ts = 1_700_000_000.0
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_selected_entity_cleared'))
      sniffer.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_open_gui_echo_14b'))
      sniffer.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet)
    end

    assert_includes output, 'selected_entity_cleared', 'incoming msg 6 action logged'
    refute_includes output, 'open_gui', 'outgoing msg 7 NOT logged'
  end

  # ── Test 3: client mode regression ────────────────────────────────────

  def test_client_mode_processes_both_directions
    output, = run_sniffer(player_db: nil) do |sniffer|
      ts = 1_700_000_000.0
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
      sniffer.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_chat_echo_segment'))
    end

    assert_includes output, 'that nuke is not gonna be finished this hour', 'client direction processed'
    assert_includes output, 'barely get any iron', 'server echo still processed in client mode'
  end

  # ── Test 4: server mode auto-detection ────────────────────────────────

  def test_server_mode_auto_detects_server_ip
    require 'socket'
    local_ips = Socket.getifaddrs.select { |addr| addr.addr&.ipv4? }.map { |addr| addr.addr.ip_address }
    non_loopback = local_ips.find { |ip| ip != '127.0.0.1' }
    skip 'no non-loopback IPv4 interface found' if non_loopback.nil?

    output, = run_sniffer(server: true, server_ip: nil, player_db: nil, debug: true) do |sniffer|
      sniffer.send(:process_packet, 1, 1.0, CLIENT_IP, non_loopback, 34197, 34197, fixture_packet('client_pipette'))
    end

    assert_includes output, 'pipette', 'auto-detected server IP classified incoming correctly'
  end

  # ── Test 5: banner printed via run() pcap-read path ───────────────────

  def test_server_mode_banner_on_pcap_read_path
    Dir.mktmpdir do |dir|
      run_pcap = File.join(dir, 'srv_banner.pcap')
      writer = PcapWriter.new(run_pcap)
      builder = make_test_sniffer(player_db: nil)
      frame = builder.send(:build_fake_ip_udp, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
      writer.write_frame(frame)
      writer.close

      output, = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil, pcap: run_pcap) do |sniffer|
        sniffer.run
      end
      assert_includes output, 'SERVER MODE', 'server mode banner printed in run()'
      assert_includes output, 'that nuke is not gonna be finished this hour', 'pcap-read path analyzed incoming packet'
    end
  end

  # ── Test 6: dedicated server detection from cmdlines ──────────────────

  def test_dedicated_server_detection
    require_relative '../lib/server_detect'

    # dedicated: rcon flags (what our vanilla server uses)
    # Live-process checks need an ACTUAL factorio binary running (pgrep -x);
    # the /proc cmdline scan in ServerDetect matches any process mentioning
    # "factorio" (test harnesses do), so gate on pgrep to stay skippable
    # off-host.
    has_factorio = system('pgrep -x factorio > /dev/null 2>&1')
    unless has_factorio
      skip 'no factorio process on this host — live-process detection skipped'
    end

    info = ServerDetect.detect
    assert_equal true, info[:dedicated], "current process detected as dedicated (flags: #{info[:dedicated_flags].inspect})"
    assert_operator (info[:dedicated_flags] & %w[--rcon-bind --rcon-password --server-settings]).size, :>=, 2,
                    'rcon/start-server flags are the giveaway'

    # dedicated via --start-server alone
    assert_equal ['--start-server'], ServerDetect.matching_flags('bin/x64/factorio --start-server mysave.zip', ServerDetect::DEDICATED_ONLY_FLAGS),
                 '--start-server alone is dedicated-only'

    # client-compatible hosting flags are NOT dedicated-proof
    info2 = ServerDetect.matching_flags('bin/x64/factorio --start-server-load-scenario scenarios/foo', ServerDetect::DEDICATED_ONLY_FLAGS)
    assert_empty info2, '--start-server-load-scenario is NOT a dedicated-only flag'
    assert_equal ['--start-server-load-scenario'], ServerDetect.matching_flags('bin/x64/factorio --start-server-load-scenario scenarios/foo', ServerDetect::CLIENT_ALSO_FLAGS),
                 'but it IS a hosting flag'

    # plain client has neither
    assert_empty ServerDetect.matching_flags('bin/x64/factorio --join 1.2.3.4', ServerDetect::DEDICATED_ONLY_FLAGS),
                 'plain client has no dedicated-only server flags'
    assert_empty ServerDetect.matching_flags('bin/x64/factorio --join 1.2.3.4', ServerDetect::CLIENT_ALSO_FLAGS),
                 'plain client has no hosting flags'

    # whole-arg matching: --start-server must not match --start-server-load-scenario
    assert_empty ServerDetect.matching_flags('--start-server-load-scenario x', ServerDetect::DEDICATED_ONLY_FLAGS),
                 'whole-arg matching (no prefix collision between --start-server and --start-server-load-scenario)'

    # serving? logic (drives auto-enabling server mode)
    assert ServerDetect.serving?({ dedicated: true, hosting_flags: [], pid: 1 }), 'dedicated ⇒ serving'
    assert ServerDetect.serving?({ dedicated: false, hosting_flags: ['--map-settings'], pid: 1 }), 'hosting flags ⇒ serving'
    refute ServerDetect.serving?({}), 'empty info ⇒ not serving'
    assert ServerDetect.serving?(ServerDetect.detect), 'live process is serving (auto-server would engage)'

    # capture_iface: with a single non-loopback interface there's nothing to choose
    require 'socket'
    non_loopback_ifaces = Socket.getifaddrs.select { |addr| addr.addr&.ipv4? && addr.name != 'lo' }.map(&:name).uniq
    if non_loopback_ifaces.size == 1
      assert_equal non_loopback_ifaces.first, ServerDetect.capture_iface,
                   "capture_iface picks the only non-loopback interface (#{non_loopback_ifaces.first})"
    end
  end

  # ── Test 7: hot reload — in-place, same objects ───────────────────────

  def test_hot_reload_preserves_state
    sniffer = make_test_sniffer(server: true, server_ip: SERVER_IP)
    sniffer.instance_variable_set(:@player_db, PlayerDatabase.new(nil))
    sniffer.instance_variable_get(:@player_db)[7] = {name: 'hotreload_user'}
    sniffer.send(:process_packet, 1, 1_700_000_000.0, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_pipette'))
    stats = sniffer.instance_variable_get(:@stats)
    player_db = sniffer.instance_variable_get(:@player_db)
    assert_equal 1, stats[:packets], 'packet counted before reload'

    # In-place reload: handle_interrupt! is exactly what Ctrl-C triggers
    # inside #run. The SAME object must keep its ivars while the libs reload.
    capture_io { sniffer.handle_interrupt! }
    assert_same stats, sniffer.instance_variable_get(:@stats), 'same instance keeps the SAME stats object'
    assert_same player_db, sniffer.instance_variable_get(:@player_db), 'same instance keeps the SAME player DB object'
    assert_equal 'hotreload_user', sniffer.instance_variable_get(:@player_db).lookup(7),
                 'player names survive reload'
    sniffer.send(:process_packet, 2, 1_700_000_001.0, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
    assert_equal 2, sniffer.instance_variable_get(:@stats)[:packets], 'packets keep counting after reload'

    # double-tap quit: a second interrupt within QUIT_WINDOW re-raises
    assert_raises(Interrupt) { sniffer.handle_interrupt! }
  end

  # ── Test 8: RCON roster parsing + refresh diff ────────────────────────

  def test_rcon_roster_parsing_and_sync
    # JSON payloads (helpers.table_to_json) — parsed with stdlib JSON.parse
    roster = RconClient.parse_roster("[{\"i\":1,\"n\":\"morganc\"},{\"i\":2,\"n\":\"bob\"}]\n")
    assert_equal [{ index: 1, name: 'morganc' }, { index: 2, name: 'bob' }], roster,
                 'parse_roster parses the JSON body'
    # escaped quote in a name (JSON handles escaping natively)
    roster = RconClient.parse_roster("[{\"i\":7,\"n\":\"a \\\"quoted\\\" name\"}]")
    assert_equal [{ index: 7, name: 'a "quoted" name' }], roster,
                 'parse_roster unescapes quotes in names'
    # valid empty roster
    assert_equal [], RconClient.parse_roster("[]\n"), 'empty roster parses to []'
    # non-JSON payload
    assert_nil RconClient.parse_roster('some random error text'), 'non-JSON payload → nil'

    # player attrs parse (JSON). serpent.line was abandoned: it sorts keys
    # alphabetically (a, c, i, k, n, o — NOT insertion order), which silently
    # broke an order-sensitive regex and starved the agent's stats context.
    attrs = RconClient.parse_player_attrs(
      "[{\"a\":true,\"c\":true,\"i\":1,\"k\":722,\"n\":\"morganc\",\"o\":7142576},{\"a\":false,\"c\":false,\"i\":2,\"k\":0,\"n\":\"bob\",\"o\":500}]\n"
    )
    assert_equal [
      { index: 1, name: 'morganc', connected: true, admin: true, online_time: 7_142_576, afk_time: 722, locale: nil },
      { index: 2, name: 'bob', connected: false, admin: false, online_time: 500, afk_time: 0, locale: nil },
    ], attrs, 'parse_player_attrs + afk_time'
    assert_nil RconClient.parse_player_attrs('garbage'), 'non-JSON payload → nil'

    # Hard invariant: helpers.write_file must ALWAYS target the server only.
    # Deterministic mod code runs on server + every client, so a bare call
    # would write everywhere — we pass for_player=0 explicitly (server output;
    # verified live). A non-zero index writes to that player's CLIENT and via
    # /sc runtime is skipped entirely. Guard: every write_file call's LAST
    # argument must be 0 (or absent).
    %w[ROSTER_WRITE_LUA PLAYER_ATTRS_WRITE_LUA DUMP_PROTOTYPES_LUA].each do |const_name|
      lua = RconClient.const_get(const_name).to_s
      # Match each helpers.write_file call, allowing one nested paren level
      # (e.g. helpers.table_to_json(t), table.concat(o,"\n")).
      calls = lua.scan(/helpers\.write_file\((?:[^()]|\([^()]*\))*\)/)
      refute_empty calls, "#{const_name}: expected write_file call"
      ok = calls.all? do |call|
        tail = call.sub(/\Ahelpers\.write_file\(/, '').sub(/\)\z/, '').split(',').last.to_s.strip
        tail == '0' || tail.empty?
      end
      assert ok, "#{const_name}: write_file targets server only (for_player=0, got #{calls.map { |call| call.sub(/\Ahelpers\.write_file\(/, '') }})"
    end

    # refresh_roster → load_roster: initial load only (new players come from
    # the packet stream, no periodic refresh)
    sr = make_test_sniffer(server: true, server_ip: SERVER_IP)
    fake = Object.new
    fake.define_singleton_method(:player_attributes) do
      [{ index: 1, name: 'morganc', connected: true, admin: true, online_time: 0, afk_time: 0, locale: nil },
       { index: 2, name: 'bob', connected: true, admin: true, online_time: 0, afk_time: 0, locale: nil }]
    end
    sr.instance_variable_set(:@rcon, fake)
    roster_output, = capture_io { sr.send(:load_roster) }
    assert_includes roster_output, 'morganc (#1), bob (#2)', 'startup roster printed with indexes'
    assert_equal 'morganc', sr.instance_variable_get(:@player_db).lookup(1), 'roster name bound into player DB'
    assert_equal 'bob', sr.instance_variable_get(:@player_db).lookup(2), 'roster name bound into player DB'

    # empty server / failed query: no crash, no output
    fake2 = Object.new
    fake2.define_singleton_method(:player_attributes) { nil }
    sr2 = make_test_sniffer(server: true, server_ip: SERVER_IP)
    sr2.instance_variable_set(:@rcon, fake2)
    failed_output, = capture_io { sr2.send(:load_roster) }
    assert_empty failed_output, 'failed roster query is silent'

    # one-shot across hot reload: roster is queried exactly once, not again
    # after Ctrl-C reload (snapshot carries state.roster_loaded over)
    queries = 0
    fake3 = Object.new
    fake3.define_singleton_method(:player_attributes) do
      queries += 1
      [{ index: 1, name: 'morganc', connected: true, online_time: 0, afk_time: 0, locale: nil }]
    end
    fake3.define_singleton_method(:server_version) { nil }
    sr3 = make_test_sniffer(server: true, server_ip: SERVER_IP)
    sr3.instance_variable_set(:@rcon, fake3)
    sr3.send(:load_roster)              # startup query
    sr3.send(:load_player_attrs)        # attrs seed — must REUSE the roster dump, not re-query
    capture_io { sr3.handle_interrupt! } # in-place reload (loads libs)
    sr3.send(:load_roster)              # run() resumes → re-seeds
    assert_equal 2, queries, 'roster re-queried after reload; attrs seed reuses the same dump (no 3rd query)'
  end

  # ── Test 7: capture filters (keepalives, directions, full-capture) ────

  def test_capture_filters
    # keepalive-only C→S heartbeat (flags 0x0e: single all-empty closure)
    keepalive = "\x06\x0e\x00\x00\x00\x00".b
    # C→S heartbeat with input action (flags 0x02: closures, not all-empty)
    acting = "\x06\x02\x00\x00\x00\x00".b
    # S→C echoed heartbeat (flags 0x02) — outgoing, dropped in server mode
    s2c = "\x07\x02\x00\x00\x00\x00".b

    _, sniffer = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |sniffer|
      ts = 1_700_000_000.0
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, keepalive, "\x00" * 14 + keepalive)
      sniffer.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, acting, "\x00" * 14 + acting)
      sniffer.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, s2c, "\x00" * 14 + s2c)
    end
    records = capture_records(sniffer)
    assert_equal 1, records.size, "server mode keeps only the incoming action heartbeat (got #{records.size})"
    assert records.first && records.first.bytesize == acting.bytesize && records.first.start_with?("\x06\x02"),
           'kept record is the C→S action heartbeat'

    # full-capture keeps everything (keepalives + outgoing echo + msg13)
    _, sniffer = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil, full_capture: true) do |sniffer|
      ts = 1_700_000_000.0
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, keepalive, "\x00" * 14 + keepalive)
      sniffer.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, acting, "\x00" * 14 + acting)
      sniffer.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, s2c, "\x00" * 14 + s2c)
      sniffer.send(:process_packet, 4, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet, "\x00" * 14 + msg13_packet)
    end
    records = capture_records(sniffer)
    assert_equal 4, records.size, "--full-capture records all 4 packets (got #{records.size})"
  end

  # ── Test 9: C→S join/leave detection feeds the agent ──────────────────

  def test_server_mode_join_and_leave_events
    # Server mode: joins are detected at the msg4 + first-C→S-heartbeat confirm
    # (the S→C NewPeerInfo broadcast is not analyzed), leaves via the C→S
    # PeerDisconnect sync action in the client's final heartbeat (the observed
    # quit signal; msg 14 is kept as a fallback).
    joined = left = nil
    online_after_quit = nil
    result = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |sniffer|
      agent = recording_agent
      sniffer.instance_variable_set(:@agent, agent)
      ts = 1_700_000_000.0
      # msg 4 ConnectionRequestReplyConfirm — connection attempt with username
      msg4 = "\x04".b + [1].pack('v') + [100].pack('V') + [200].pack('V') + [300].pack('V') + [5].pack('C') + 'alice'
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, msg4)
      # first C→S heartbeat with a real action → confirm → :joined
      sniffer.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
      # C→S heartbeat whose ONLY sync action is PeerDisconnect (reason=0, no
      # peer_id) — the clean-quit signal in server mode → :left
      quit_hb = fixture_packet('player_quit')
      sniffer.send(:process_packet, 3, ts, CLIENT_IP, SERVER_IP, 34197, 34197, quit_hb)
      joined, left = agent.events[0], agent.events[1]
      online_after_quit = sniffer.online_players
    end
    sniffer = result[1]
    assert_equal [:joined, 'alice'], joined, "join detected on confirm (got #{joined.inspect})"
    assert_equal [:left, 'alice'], left, "leave detected on C→S PeerDisconnect (got #{left.inspect})"
    refute online_after_quit.include?('alice'), 'leaver removed from online list (bot context is accurate)'

    # msg 14 RequestForHeartbeatWhenDisconnecting — kept fallback, still works.
    left14 = nil
    result = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |sniffer|
      agent = recording_agent
      sniffer.instance_variable_set(:@agent, agent)
      ts = 1_700_000_000.0
      msg4 = "\x04".b + [1].pack('v') + [100].pack('V') + [200].pack('V') + [300].pack('V') + [5].pack('C') + 'alice'
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, msg4)
      sniffer.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
      sniffer.send(:process_packet, 3, ts, CLIENT_IP, SERVER_IP, 34197, 34197, "\x0e".b + [7].pack('V'))
      left14 = agent.events[1]
    end
    sniffer = result[1]
    assert_equal [:left, 'alice'], left14, "leave detected on msg 14 fallback (got #{left14.inspect})"

    # A disconnected-but-never-confirmed src_ip should not produce a leave.
    events = nil
    result = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |sniffer|
      agent = recording_agent
      sniffer.instance_variable_set(:@agent, agent)
      sniffer.send(:process_packet, 1, 1_700_000_000.0, CLIENT_IP, SERVER_IP, 34197, 34197, "\x0e".b + [7].pack('V'))
      events = agent.events
    end
    sniffer = result[1]
    assert_empty events, 'msg 14 from unknown src_ip → no leave event'
  end

  # ── Test 10: split chat messages reassembled across packets ──────────

  def test_split_chat_reassembled_across_packets
    FactorioProtocol.select_version('2.0.77')  # segment 104 = write_to_console
    # Segment metadata: total_segs/seg_no mark messages split across packets.
    # Each packet carries ONE segment; the agent must receive the merged text.
    messages = []
    agent = recording_agent_with_messages
    result = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |sniffer|
      sniffer.instance_variable_set(:@agent, agent)
      ts = 1_700_000_000.0
      # fragment 0: [0x15][29] + first 18 chars
      frag0 = "\x15\x1dwe dont need it to".b
      sniffer.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197,
                   build_segment_packet(frag0, total: 2, no: 0, green: 21))
      # fragment 1: raw continuation (no prefix), next packet
      frag1 = ' be 2 lanes'.b
      sniffer.send(:process_packet, 2, ts + 0.1, CLIENT_IP, SERVER_IP, 34197, 34197,
                   build_segment_packet(frag1, total: 2, no: 1, green: 21))
      messages.replace(agent.msgs)
    end
    sniffer = result[1]
    assert_equal ['we dont need it to be 2 lanes'], messages,
                 "split chat reassembled (got #{messages.inspect})"
  ensure
    FactorioProtocol.reset_version
  end

  # ── Test 11: always-on auto-named captures ────────────────────────────

  def test_always_on_auto_named_captures
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        # server mode: timestamped at init (captures/server-34197-<ts>.pcap) —
        # the file IS the live one, no stable path, no renames
        result = run_sniffer(server: true, server_ip: SERVER_IP, port: 34197, player_db: nil, autoname: true) do |sniffer|
          writer = sniffer.instance_variable_get(:@pcap_writer)
          assert_match %r{captures/server-34197-\d{8}-\d{6}\.pcap\z}, writer&.path,
                       "server auto-name, timestamped directly (got #{writer&.path})"
          writer&.close
        end
        sniffer = result[1]

        # client mode: deferred until the first packet reveals the server
        result = run_sniffer(local_ip: '10.0.0.50', player_db: nil, autoname: true) do |sniffer|
          assert_equal File.join(dir, 'captures'), sniffer.instance_variable_get(:@pending_capture),
                       'client capture pending until first packet'
          pkt = "\x06\x02".b + ([0] * 10).pack('C*')
          sniffer.send(:process_packet, 1, 1_700_000_000.0, '10.0.0.50', '10.0.0.1', 50000, 34197, pkt)
          writer = sniffer.instance_variable_get(:@pcap_writer)
          assert_match %r{captures/client-10\.0\.0\.1-\d{8}-\d{6}\.pcap\z}, writer&.path,
                       "client auto-name from first packet, timestamped directly (got #{writer&.path})"
          writer&.close
        end
      end
    end
  end

  # ── Player DB encoding: legacy binary-flagged names must not kill save ──

  def test_player_db_encoding_hardening
    # A name that arrived binary-flagged (pre-fix decode path / reloaded state)
    # must be sanitized on add — the stored value stays usable and JSON-safe.
    db = PlayerDatabase.new(nil)
    db[1] = {name: "sévérin".b}
    name = db.lookup(1)
    assert_equal 'sévérin', name, 'binary-flagged name sanitized on add'
    assert_equal Encoding::UTF_8, name.encoding, 'stored name is valid UTF-8'
    assert name.valid_encoding?, 'stored name is valid UTF-8'
    assert_equal 1, db.id_for('sévérin'), 'name index works with the sanitized name'

    # Simulate what an old reload could leave behind: a binary entry injected
    # straight into @players (bypassing add). save() must still write valid JSON.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'players-cache.json')
      db2 = PlayerDatabase.new(path)
      db2[1] = {name: 'alice'}
      db2.instance_variable_get(:@players)[2] = { name: "sévérin".b, locale: nil }   # legacy poison
      db2.save
      raw = File.read(path)
      parsed = JSON.parse(raw)
      assert_equal 'sévérin', parsed['2']['name'], 'legacy binary entry sanitized at save (no GeneratorError)'
      assert_equal 'alice', parsed['1']['name'], 'clean entry survives'
    end

    # Concurrent writers: the capture thread (add), the translation-agent
    # event worker (set_locale_by_id via note_joined) and the console thread
    # (set_locale_overrides) all mutate the hashes — the mutex must serialize
    # mutations + disk writes (an @players.each racing a key-add raises
    # "can't add a new key into hash during iteration"; two saves race on the
    # same .tmp file). Ten rounds of interleaved writers, then verify state.
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'players-cache.json')
      cdb = PlayerDatabase.new(path)
      cdb[1] = {name: 'alice'}
      threads = [
        Thread.new { 100.times { |i| cdb[100 + i] = {name: "capture#{i}"} } },
        Thread.new { 100.times { |i| cdb.set_locale_by_id(1, "pt-BR") } },
        Thread.new { 100.times { |i| cdb.set_locale_overrides("bob#{i}", ['en', 'pt']) } },
      ]
      threads.each(&:value)
      reloaded = PlayerDatabase.new(path)
      assert_equal 101, reloaded.players.size, 'concurrent writes persist intact'
      assert_equal cdb.players.transform_values { |p| [p[:name], p[:locale]] }.sort,
                   reloaded.players.transform_values { |p| [p[:name], p[:locale]] }.sort,
                   'concurrent writes persist intact'
    end
  end

  # ── Player DB admin persistence ─────────────────────────────────────

  def test_player_db_admin_persistence
    # explicit admin updates must not be ignored by add()
    db = PlayerDatabase.new(nil)
    db[1] = {name: 'alice', admin: true}
    db[2] = {name: 'bob', admin: false}
    assert db['alice'][:admin], 'admin true is readable'
    refute db['bob'][:admin], 'admin false is readable'
    refute (db['unknown'] || {})[:admin], 'unknown defaults to false'
    db['alice'] = {admin: false}
    refute db['alice'][:admin], 'explicit admin false updates the DB'

    # persisted to disk and reloaded
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'players-cache.json')
      db2 = PlayerDatabase.new(path)
      db2[1] = {name: 'alice', admin: true}
      db2[2] = {name: 'bob', admin: false}
      db2.save
      reloaded = PlayerDatabase.new(path)
      assert_equal [true, false, false], [reloaded['alice'][:admin], reloaded['bob'][:admin], (reloaded['unknown'] || {})[:admin] || false], 'admin survives reload'

      # explicit false persists after update
      db2['alice'] = {admin: false}
      db2.save
      reloaded2 = PlayerDatabase.new(path)
      refute (reloaded2['alice'] || {})[:admin], 'explicit false persists'
      assert_equal [false, false], [(reloaded2['alice'] || {})[:admin] || false, (reloaded2['bob'] || {})[:admin] || false]
    end

    # legacy entries without admin load safely as false
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'players-cache.json')
      legacy = PlayerDatabase.new(path)
      legacy[1] = {name: 'carol'}            # admin defaults to nil (legacy injection)
      legacy.save
      reloaded_legacy = PlayerDatabase.new(path)
      refute (reloaded_legacy['carol'] || {})[:admin], 'missing admin defaults to false'
    end
  end

  # ── Heartbeat timeout: crashed/offline players are dropped ────────────

  def test_heartbeat_watchdog
    # The timeout is server-mode only: client mode gets the server's S→C
    # PeerDisconnect broadcast for crashes. In server mode a player whose
    # heartbeats stop (crash / power / network loss — nothing is sent) must be
    # removed from the live roster (attrs connected records) after
    # HEARTBEAT_TIMEOUT and reported to the agent console queue, instead of
    # lingering undefinedly (prevents the stale-roster forever problem).
    wd_events = []
    # NOTE: no :interface in opts → ensure_timeout_watchdog must NOT start a
    # thread in tests (guarded). We drive check_heartbeat_timeouts directly.
    sniffer = make_test_sniffer(server: true, server_ip: SERVER_IP)
    refute sniffer.instance_variable_get(:@timeout_watchdog),
           'no watchdog thread in tests (no :interface)'
    agent = Object.new
    agent.define_singleton_method(:on_player_event) { |kind, name| wd_events << [kind, name] }
    agent.define_singleton_method(:enqueue) { |method, *args, **_kwargs| public_send(method, *args) }
    sniffer.instance_variable_set(:@agent, agent)
    sniffer.instance_variable_set(:@show_players, [])
    sniffer.instance_variable_set(:@debug, false)
    sniffer.instance_variable_set(:@attrs, PlayerAttrs.new)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    attrs = sniffer.instance_variable_get(:@attrs)
    attrs.roster_online('alive', 1)
    attrs.roster_online('stale', 2)
    players = attrs.instance_variable_get(:@players)   # internals: age hb directly
    players['alive'][:hb] = now - 1         # heartbeat a second ago → fine
    players['stale'][:hb] = now - (FactorioSniffer::HEARTBEAT_TIMEOUT + 5)  # silent for timeout+5s → timeout

    output, = capture_io { sniffer.send(:check_heartbeat_timeouts) }
    refute attrs.online_names.include?('stale'), 'stale player removed from the live roster'
    assert attrs.online_names.include?('alive'), 'recently-heartbeat player kept'
    assert wd_events.include?([:timeout, 'stale']), 'agent got on_player_event(:timeout)'
    refute wd_events.include?([:timeout, 'alive']), 'alive player did not fire timeout'
    assert_includes output, 'stale timed out', 'console prints the timeout line'
    assert_includes output, 'no heartbeat', 'console prints the timeout reason'

    # a heartbeat arriving before the scan must cancel the drop (touch refreshed
    # the timestamp → below the threshold at scan time)
    attrs.roster_online('half', 3)
    players['half'][:hb] = now - (FactorioSniffer::HEARTBEAT_TIMEOUT + 2)
    sniffer.send(:touch_heartbeat_index, 3, '10.0.0.55')   # fresh proof of life by index
    capture_io { sniffer.send(:check_heartbeat_timeouts) }
    assert attrs.online_names.include?('half'), 'refreshed heartbeat cancels the timeout'

    # regression: a record created by connect() (NewPeerInfo join — never
    # RCON-seeded) has no :base_ticks; the watchdog's disconnect fold used to
    # raise `undefined method '+' for nil` BEFORE marking the player offline,
    # so the watchdog re-raised every second. Also covers @game_tick being
    # still nil (no heartbeat carrying a tick observed yet).
    attrs.connect('joiner', 1234)
    assert_equal 0, players['joiner'][:base_ticks],
                 'connect() gives unseeded records a zero base_ticks'
    sniffer.instance_variable_set(:@game_tick, nil)   # tick never observed
    players['joiner'][:hb] = now - (FactorioSniffer::HEARTBEAT_TIMEOUT + 5)
    output, = capture_io { sniffer.send(:check_heartbeat_timeouts) }
    refute attrs.online_names.include?('joiner'), 'unseeded joiner timed out without raising'
    assert wd_events.include?([:timeout, 'joiner']), 'agent got on_player_event(:timeout) for joiner'
    assert_includes output, 'joiner timed out', 'console prints the unseeded joiner timeout'
    assert_includes output, 'no heartbeat', 'console prints the timeout reason'

    # touch_heartbeat stamps by src_ip resolution too (the packet-top path)
    sniffer.instance_variable_get(:@ip_names)['10.0.0.77'] = ['ripe', true]
    attrs.roster_online('ripe', 4)
    players['ripe'][:hb] = now - (FactorioSniffer::HEARTBEAT_TIMEOUT + 4)
    sniffer.send(:touch_heartbeat, '10.0.0.77')
    capture_io { sniffer.send(:check_heartbeat_timeouts) }
    assert attrs.online_names.include?('ripe'), 'src_ip touch keeps the player alive'

    # Liveness is packet-derived, not periodic RCON (load_roster stays
    # as-is on startup/reload): roster-seeded players that never get
    # attributable packets can time out (a false positive forces a
    # rejoin; a false negative only registers late).
    sniffer.instance_variable_set(:@rcon, nil)
    attrs.roster_online('gone', 10)
    players['gone'][:hb] = now - (FactorioSniffer::HEARTBEAT_TIMEOUT + 5)
    wd_events.clear
    output, = capture_io { sniffer.send(:check_heartbeat_timeouts) }
    assert wd_events.include?([:timeout, 'gone']), 'disconnected roster player still fires the timeout'
    refute attrs.online_names.include?('gone'), 'roster player removed from roster'
    assert_includes output, 'gone timed out', 'console prints the timeout'
    assert_includes output, 'no heartbeat', 'console prints the timeout reason'
  ensure
    sniffer&.instance_variable_get(:@pcap_writer)&.close
  end

  def recording_agent_with_messages
    messages = []
    agent = Object.new
    agent.define_singleton_method(:msgs) { messages }
    agent.define_singleton_method(:on_chat) { |_player, message| messages << message }
    agent.define_singleton_method(:on_player_event) { |_kind, _name| }
    agent.define_singleton_method(:enqueue) { |method, *args, **_kwargs| public_send(method, *args) }
    agent
  end
end
