#!/usr/bin/env ruby
# Test server mode of factorio-sniffer.rb using real packet fixtures.
#
# Verifies:
#  1. Incoming (C→S, msg 6) packets ARE analyzed
#  2. Outgoing (S→C, msg 7) packets are SKIPPED (no broadcast duplicates)
#  3. TransferBlock (msg 13) packets are dropped: no analysis, no capture
#  4. Client mode still processes both directions (regression)
#  5. Server IP auto-detection from local interfaces
#  6. Server-mode banner printed via run() (live + pcap-read paths)
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'tmpdir'
require 'stringio'
require_relative '../factorio-sniffer'
require_relative '../spec/fixtures/packets'

SERVER_IP = '192.168.1.10'
CLIENT_IP = '192.168.1.50'

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

def run_sniffer(opts)
  out = StringIO.new
  old = $stdout
  $stdout = out
  # Tests must not write capture artifacts into the repo's captures/ — the
  # sniffer's always-on auto-named capture is stubbed with an in-memory
  # FakePcapWriter via the state's pcap_writer (the exact hot-reload reuse
  # path). The one exception is Test 11 (opts[:autoname]), which asserts the
  # auto-naming itself and runs inside its own tmpdir chdir.
  state = opts[:autoname] ? SnifferState.new : spec_state_with_capture
  sniffer = FactorioSniffer.new(opts, state)
  begin
    yield sniffer
  ensure
    $stdout = old
  end
  [out.string, sniffer]
end

# SnifferState whose pcap_writer is a FakePcapWriter — constructing a
# FactorioSniffer with it reuses the writer (skips auto-naming entirely), so
# no test ever touches the repo's captures/ or spawns a real flusher thread.
def spec_state_with_capture
  st = SnifferState.new
  st.pcap_writer = FakePcapWriter.new
  st
end

$pass = 0
$fail = 0
def check(cond, label)
  if cond
    puts "  PASS: #{label}"
    $pass += 1
  else
    puts "  FAIL: #{label}"
    $fail += 1
  end
end

# ── Test 1: server mode, live capture (raw_frame present) ─────────────

out, sniffer = run_sniffer(
  server: true, server_ip: SERVER_IP, player_db: nil
) do |s|
  ts = 1_700_000_000.0
  # incoming client chat (msg 6) — should be analyzed
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'), "\x00" * 14 + fixture_packet('client_chat_message_0x0b'))
  # outgoing server echo (msg 7) — should be skipped as broadcast duplicate
  s.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_chat_echo_segment'), "\x00" * 14 + fixture_packet('server_chat_echo_segment'))
  # outgoing TransferBlock (msg 13) — should be dropped entirely
  s.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet, "\x00" * 14 + msg13_packet)
  s.send(:print_summary)
end

puts 'Test 1: server mode (live)'
check(out.include?('Player_12: that nuke is not gonna be finished this hour'),
      'incoming client chat decoded and logged')
check(!out.include?('barely get any iron'), 'OUTGOING server echo NOT logged')
check(out.include?('outgoing broadcasts skipped (server mode)=1'),
      "outgoing counter == 1 (got: #{out[/outgoing broadcasts skipped[^\n]*/].inspect})")
check(!out.include?('[summary] packets=4'), 'no packet 4 expected (all 3 accounted for)')

# capture: only the incoming client packet is captured — outgoing
# server broadcasts and msg13 TransferBlocks are excluded from capture in
# server mode (analysis never reads them; --full-capture keeps everything).
# The FakePcapWriter records exactly what the real writer would have framed.
writer = sniffer.instance_variable_get(:@pcap_writer)
writer.close
recs = writer.records
# synthetic frames: [eth(14)][udp payload] — strip eth to inspect the payload
payloads = recs.map { |r| r[14, r.bytesize - 14] }
puts "  INFO: captured #{recs.size} records, #{payloads.count { |p| p.bytesize >= 500 }} large (>=500B) payloads"
check(recs.size == 1, "capture has 1 record (client only), echo + msg13 excluded (got #{recs.size})")
check(payloads.none? { |p| p.bytesize >= 500 }, 'no 503-byte TransferBlock payloads in capture')

# ── Test 2: server mode, pcap-read path (no raw_frame) ────────────────
out, = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil, debug: true) do |s|
  ts = 1_700_000_000.0
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_selected_entity_cleared'))
  s.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_open_gui_echo_14b'))
  s.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet)
end
puts "\nTest 2: server mode (pcap-read path)"
check(out.include?('selected_entity_cleared'), 'incoming msg 6 action logged')
check(!out.include?('open_gui'), 'outgoing msg 7 NOT logged')

# ── Test 3: client mode regression ────────────────────────────────────
out, = run_sniffer(player_db: nil) do |s|
  ts = 1_700_000_000.0
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
  s.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_chat_echo_segment'))
end
puts "\nTest 3: client mode regression (no --server)"
check(out.include?('that nuke is not gonna be finished this hour'), 'client direction processed')
check(out.include?('barely get any iron'), 'server echo still processed in client mode')

# ── Test 4: server mode auto-detection ────────────────────────────────
puts "\nTest 4: server mode auto-detect"
require 'socket'
local_ips = Socket.getifaddrs.select { |a| a.addr&.ipv4? }.map { |a| a.addr.ip_address }
non_loopback = local_ips.reject { |ip| ip.start_with?('127.') }.first
out, = run_sniffer(server: true, server_ip: nil, player_db: nil, debug: true) do |s|
  s.send(:process_packet, 1, 1.0, CLIENT_IP, non_loopback, 34197, 34197, fixture_packet('client_pipette'))
end
puts "  INFO: detected local IPs: #{local_ips.inspect}"
check(out.include?('pipette'), 'auto-detected server IP classified incoming correctly')

# ── Test 5: banner printed via run() pcap-read path ───────────────────
puts "\nTest 5: server mode banner via run()"
run_pcap = File.join(Dir.tmpdir, 'srv_banner.pcap')
File.delete(run_pcap) if File.exist?(run_pcap)
w = PcapWriter.new(run_pcap)
builder = FactorioSniffer.new({ player_db: nil }, spec_state_with_capture)
frame = builder.send(:build_fake_ip_udp, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
w.write_frame(frame)
w.close
out, = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil, pcap: run_pcap) do |s|
  s.run
end
check(out.include?('SERVER MODE'), 'server mode banner printed in run()')
check(out.include?('that nuke is not gonna be finished this hour'), 'pcap-read path analyzed incoming packet')

# ── Test 6: dedicated-server detection from cmdlines ─────────────────
puts "\nTest 6: dedicated server detection"
require_relative '../lib/server_detect'

# dedicated: rcon flags (what our vanilla server uses)
info = ServerDetect.detect
check(info[:dedicated] == true, "current process detected as dedicated (flags: #{info[:dedicated_flags].inspect})")
check((info[:dedicated_flags] & %w[--rcon-bind --rcon-password --server-settings]).size >= 2,
      'rcon/start-server flags are the giveaway')

# dedicated via --start-server alone
check(ServerDetect.matching_flags('bin/x64/factorio --start-server mysave.zip', ServerDetect::DEDICATED_ONLY_FLAGS) == ['--start-server'],
      '--start-server alone is dedicated-only')

# client-compatible hosting flags are NOT dedicated-proof
info2 = ServerDetect.matching_flags('bin/x64/factorio --start-server-load-scenario scenarios/foo', ServerDetect::DEDICATED_ONLY_FLAGS)
check(info2.empty?, '--start-server-load-scenario is NOT a dedicated-only flag')
check(ServerDetect.matching_flags('bin/x64/factorio --start-server-load-scenario scenarios/foo', ServerDetect::CLIENT_ALSO_FLAGS) == ['--start-server-load-scenario'],
      'but it IS a hosting flag')

# plain client has neither
check(ServerDetect.matching_flags('bin/x64/factorio --join 1.2.3.4', ServerDetect::DEDICATED_ONLY_FLAGS).empty? &&
      ServerDetect.matching_flags('bin/x64/factorio --join 1.2.3.4', ServerDetect::CLIENT_ALSO_FLAGS).empty?,
      'plain client has no server flags')

# whole-arg matching: --start-server must not match --start-server-load-scenario
check(ServerDetect.matching_flags('--start-server-load-scenario x', ServerDetect::DEDICATED_ONLY_FLAGS).empty?,
      'whole-arg matching (no prefix collision between --start-server and --start-server-load-scenario)')

# serving? logic (drives auto-enabling server mode)
check(ServerDetect.serving?({ dedicated: true, hosting_flags: [], pid: 1 }), 'dedicated ⇒ serving')
check(ServerDetect.serving?({ dedicated: false, hosting_flags: ['--map-settings'], pid: 1 }), 'hosting flags ⇒ serving')
check(!ServerDetect.serving?({}), 'empty info ⇒ not serving')
real = ServerDetect.detect
check(ServerDetect.serving?(real), 'live process is serving (auto-server would engage)')

# capture_iface: with a single non-loopback interface there's nothing to choose
non_lo = Socket.getifaddrs.select { |a| a.addr&.ipv4? && a.name != 'lo' }.map(&:name).uniq
if non_lo.size == 1
  check(ServerDetect.capture_iface == non_lo.first,
        "capture_iface picks the only non-loopback interface (#{non_lo.first})")
else
  puts "  INFO: #{non_lo.size} non-loopback interfaces; skipping single-iface assertion"
end

# ── Test 7: hot reload — state survives code reload ──────────────────
puts "\nTest 7: hot reload state preservation"
reload_cap = File.join(Dir.tmpdir, 'srv_reload.pcap')
File.delete(reload_cap) if File.exist?(reload_cap)

st = SnifferState.new
st.pcap_writer = PcapWriter.new(reload_cap)
st.player_db = PlayerDatabase.new(nil)
st.player_db.add(7, 'hotreload_user')
st.stats = { packets: 10, factorio_packets: 5, actions: 3, outgoing_skipped: 0 }

s1 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, st)
check(s1.instance_variable_get(:@pcap_writer).equal?(st.pcap_writer),
      'reloaded sniffer reuses the SAME capture writer (file keeps its position)')
check(s1.instance_variable_get(:@player_db).lookup(7) == 'hotreload_user',
      'player names survive reload')
check(s1.instance_variable_get(:@stats)[:packets] == 10, 'stats survive reload')

# snapshot round-trip: process a packet, snapshot, rebuild, verify continuity
s1.send(:process_packet, 1, 1_700_000_000.0, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_pipette'))
st2 = s1.snapshot
s2 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, st2)
check(s2.instance_variable_get(:@stats)[:packets] == 11, 'snapshot carries incremented stats')
check(s2.instance_variable_get(:@stats)[:actions] >= 4, 'snapshot carries action count')
check(s2.instance_variable_get(:@pcap_writer).equal?(st.pcap_writer), 'snapshot reuses capture writer')
check(s2.instance_variable_get(:@player_db).equal?(s1.instance_variable_get(:@player_db)),
      'snapshot shares the player DB object')

# simulate the entry-point reload: `load` all lib files again (fresh code)
libs = %w[factorio_protocol item_db player_db pcap live_capture factorio_sniffer]
begin
  old_verbose = $VERBOSE
  $VERBOSE = nil
  libs.each { |lib| load File.expand_path("lib/#{lib}.rb", File.expand_path('..', __dir__)) }
  $VERBOSE = old_verbose
  check(true, 'libs reload cleanly with load()')
rescue => e
  check(false, "libs reload failed: #{e.class}: #{e.message}")
end

# after reload, a fresh sniffer from the old state still works
s3 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, st2)
check(s3.instance_variable_get(:@player_db).lookup(7) == 'hotreload_user',
      'post-reload sniffer still has the player names')
s3.send(:process_packet, 2, 1_700_000_001.0, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
check(s3.instance_variable_get(:@stats)[:packets] == 12, 'post-reload sniffer continues counting')
s3.instance_variable_get(:@pcap_writer).close
s2.instance_variable_get(:@pcap_writer).close

# ── Test 8: RCON roster parsing + refresh diff ───────────────────────
puts "\nTest 8: RCON roster sync"
require_relative '../lib/rcon_client'

# JSON payloads (helpers.table_to_json) — parsed with stdlib JSON.parse
roster = RconClient.parse_roster("[{\"i\":1,\"n\":\"morganc\"},{\"i\":2,\"n\":\"bob\"}]\n")
check(roster == [{ index: 1, name: 'morganc' }, { index: 2, name: 'bob' }],
      'parse_roster parses the JSON body')
# escaped quote in a name (JSON handles escaping natively)
roster = RconClient.parse_roster("[{\"i\":7,\"n\":\"a \\\"quoted\\\" name\"}]")
check(roster == [{ index: 7, name: 'a "quoted" name' }], 'parse_roster unescapes quotes in names')
# valid empty roster
check(RconClient.parse_roster("[]\n") == [], 'empty roster parses to []')
# non-JSON payload
check(RconClient.parse_roster('some random error text').nil?, 'non-JSON payload → nil')

# player attrs parse (JSON). serpent.line was abandoned: it sorts keys
# alphabetically (a, c, i, k, n, o — NOT insertion order), which silently
# broke an order-sensitive regex and starved the agent's stats context.
attrs = RconClient.parse_player_attrs(
  "[{\"a\":true,\"c\":true,\"i\":1,\"k\":722,\"n\":\"morganc\",\"o\":7142576},{\"a\":false,\"c\":false,\"i\":2,\"k\":0,\"n\":\"bob\",\"o\":500}]\n"
)
check(attrs == [
  { index: 1, name: 'morganc', connected: true, admin: true, online_time: 7_142_576, afk_time: 722 },
  { index: 2, name: 'bob', connected: false, admin: false, online_time: 500, afk_time: 0 },
], 'parse_player_attrs + afk_time')
check(RconClient.parse_player_attrs('garbage').nil?, 'non-JSON payload → nil')

# Hard invariant: helpers.write_file must ALWAYS target the server only.
# Deterministic mod code runs on server + every client, so a bare call
# would write everywhere — we pass for_player=0 explicitly (server output;
# verified live). A non-zero index writes to that player's CLIENT and via
# /sc runtime is skipped entirely. Guard: every write_file call's LAST
# argument must be 0 (or absent).
%w[ROSTER_WRITE_LUA PLAYER_ATTRS_WRITE_LUA DUMP_PROTOTYPES_LUA].each do |const|
  lua = RconClient.const_get(const).to_s
  # Match each helpers.write_file call, allowing one nested paren level
  # (e.g. helpers.table_to_json(t), table.concat(o,"\n")).
  calls = lua.scan(/helpers\.write_file\((?:[^()]|\([^()]*\))*\)/)
  ok = calls.all? do |call|
    tail = call.sub(/\Ahelpers\.write_file\(/, '').sub(/\)\z/, '').split(',').last.to_s.strip
    tail == '0' || tail.empty?
  end
  check(ok, "#{const}: write_file targets server only (for_player=0, got #{calls.map { |c| c.sub(/\Ahelpers\.write_file\(/, '') }})")
end

# refresh_roster → load_roster: initial load only (new players come from
# the packet stream, no periodic refresh)
sr = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, spec_state_with_capture)
fake = Object.new
fake.define_singleton_method(:connected_players) do
  [{ index: 1, name: 'morganc' }, { index: 2, name: 'bob' }]
end
sr.instance_variable_set(:@rcon, fake)
out = StringIO.new
old = $stdout; $stdout = out
sr.send(:load_roster)
$stdout = old
check(out.string.include?('morganc (#1), bob (#2)'), 'startup roster printed with indexes')
check(sr.instance_variable_get(:@player_db).lookup(1) == 'morganc' &&
      sr.instance_variable_get(:@player_db).lookup(2) == 'bob',
      'roster names bound into player DB')

# empty server / failed query: no crash, no output
fake2 = Object.new
fake2.define_singleton_method(:connected_players) { nil }
sr2 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, spec_state_with_capture)
sr2.instance_variable_set(:@rcon, fake2)
out = StringIO.new
old = $stdout; $stdout = out
sr2.send(:load_roster)
$stdout = old
check(out.string.empty?, 'failed roster query is silent')

# one-shot across hot reload: roster is queried exactly once, not again
# after Ctrl-C reload (snapshot carries state.roster_loaded over)
queries = 0
fake3 = Object.new
fake3.define_singleton_method(:connected_players) do
  queries += 1
  [{ index: 1, name: 'morganc' }]
end
sr3 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, spec_state_with_capture)
sr3.instance_variable_set(:@rcon, fake3)
sr3.send(:load_roster)              # startup query
st = sr3.snapshot                   # Ctrl-C reload: state carried over
sr4 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, st)
sr4.instance_variable_set(:@rcon, fake3)
sr4.send(:load_roster)              # reload — must NOT query again
check(queries == 1, 'roster queried exactly once across hot reload')

# ── Test 7: capture filters (keepalives, directions, full-capture) ────
puts "\nTest 7: capture filters"
def capture_records(sniffer)
  w = sniffer.instance_variable_get(:@pcap_writer)
  w.close
  # fake records are the synthetic frames as written ([eth(14)][payload])
  w.records.map { |r| r[14, r.bytesize - 14] }
end

# keepalive-only C→S heartbeat (flags 0x0e: single all-empty closure)
keepalive = "\x06\x0e\x00\x00\x00\x00".b
# C→S heartbeat with input action (flags 0x02: closures, not all-empty)
acting = "\x06\x02\x00\x00\x00\x00".b
# S→C echoed heartbeat (flags 0x02) — outgoing, dropped in server mode
s2c = "\x07\x02\x00\x00\x00\x00".b

f1 = File.join(Dir.tmpdir, 'filt.pcap')
_, sn = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |s|
  ts = 1_700_000_000.0
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, keepalive, "\x00" * 14 + keepalive)
  s.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, acting, "\x00" * 14 + acting)
  s.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, s2c, "\x00" * 14 + s2c)
end
recs = capture_records(sn)
check(recs.size == 1, "server mode keeps only the incoming action heartbeat (got #{recs.size})")
check(recs[0] && recs[0].bytesize == acting.bytesize && recs[0].start_with?("\x06\x02"), 'kept record is the C→S action heartbeat')

# full-capture keeps everything (keepalives + outgoing echo + msg13)
f2 = File.join(Dir.tmpdir, 'full.pcap')
_, sn = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil, full_capture: true) do |s|
  ts = 1_700_000_000.0
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, keepalive, "\x00" * 14 + keepalive)
  s.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, acting, "\x00" * 14 + acting)
  s.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, s2c, "\x00" * 14 + s2c)
  s.send(:process_packet, 4, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet, "\x00" * 14 + msg13_packet)
end
recs = capture_records(sn)
check(recs.size == 4, "--full-capture records all 4 packets (got #{recs.size})")

# ── Test 9: C→S join/leave detection feeds the agent ──────────────────
puts "\nTest 9: C→S join/leave detection (agent events)"

# A fake agent that records join/leave events (no LLM).
fake_agent_class = Class.new do
  attr_reader :events
  define_method(:initialize) { @events = [] }
  define_method(:on_player_event) { |kind, name| @events << [kind, name] }
  define_method(:on_chat) { |_p, _m| }
end

# Server mode: joins are detected at the msg4 + first-C→S-heartbeat confirm
# (the S→C NewPeerInfo broadcast is not analyzed), leaves via the C→S
# PeerDisconnect sync action in the client's final heartbeat (the observed
# quit signal; msg 14 is kept as a fallback).
joined = left = nil
online_after_quit = nil
_, sn = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |s|
  agent = fake_agent_class.new
  s.instance_variable_set(:@agent, agent)
  ts = 1_700_000_000.0
  # msg 4 ConnectionRequestReplyConfirm — connection attempt with username
  msg4 = "\x04".b + [1].pack('v') + [100].pack('V') + [200].pack('V') + [300].pack('V') + [5].pack('C') + 'alice'
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, msg4)
  # first C→S heartbeat with a real action → confirm → :joined
  s.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
  # C→S heartbeat whose ONLY sync action is PeerDisconnect (reason=0, no
  # peer_id) — the clean-quit signal in server mode → :left
  quit_hb = fixture_packet('player_quit')
  s.send(:process_packet, 3, ts, CLIENT_IP, SERVER_IP, 34197, 34197, quit_hb)
  joined, left = agent.events[0], agent.events[1]
  online_after_quit = s.online_players
end
check(joined == [:joined, 'alice'], "join detected on confirm (got #{joined.inspect})")
check(left == [:left, 'alice'], "leave detected on C→S PeerDisconnect (got #{left.inspect})")
check(!online_after_quit.include?('alice'), 'leaver removed from online list (bot context is accurate)')

# msg 14 RequestForHeartbeatWhenDisconnecting — kept fallback, still works.
left14 = nil
_, sn = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |s|
  agent = fake_agent_class.new
  s.instance_variable_set(:@agent, agent)
  ts = 1_700_000_000.0
  msg4 = "\x04".b + [1].pack('v') + [100].pack('V') + [200].pack('V') + [300].pack('V') + [5].pack('C') + 'alice'
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, msg4)
  s.send(:process_packet, 2, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_chat_message_0x0b'))
  s.send(:process_packet, 3, ts, CLIENT_IP, SERVER_IP, 34197, 34197, "\x0e".b + [7].pack('V'))
  left14 = agent.events[1]
end
check(left14 == [:left, 'alice'], "leave detected on msg 14 fallback (got #{left14.inspect})")

# A disconnected-but-never-confirmed src_ip should not produce a leave.
_, sn = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |s|
  agent = fake_agent_class.new
  s.instance_variable_set(:@agent, agent)
  s.send(:process_packet, 1, 1_700_000_000.0, CLIENT_IP, SERVER_IP, 34197, 34197, "\x0e".b + [7].pack('V'))
  @events = agent.events
end
check(@events.empty?, 'msg 14 from unknown src_ip → no leave event')

# ── Test 10: split chat messages reassembled across packets ──────────
puts "\nTest 10: split chat reassembly"
FactorioProtocol.select_version('2.0.77')  # segment 104 = write_to_console
# Segment metadata: total_segs/seg_no mark messages split across packets.
# Each packet carries ONE segment; the agent must receive the merged text.
messages = []
fake_agent_class2 = Class.new do
  define_method(:initialize) { @msgs = [] }
  define_method(:on_chat) { |_p, m| @msgs << m }
  define_method(:on_player_event) { |_k, _n| }
  attr_reader :msgs
end
_, sn = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |s|
  agent = fake_agent_class2.new
  s.instance_variable_set(:@agent, agent)
  ts = 1_700_000_000.0
  # fragment 0: [0x15][29] + first 18 chars
  frag0 = "\x15\x1dwe dont need it to".b
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197,
         build_segment_packet(frag0, total: 2, no: 0, green: 21))
  # fragment 1: raw continuation (no prefix), next packet
  frag1 = ' be 2 lanes'.b
  s.send(:process_packet, 2, ts + 0.1, CLIENT_IP, SERVER_IP, 34197, 34197,
         build_segment_packet(frag1, total: 2, no: 1, green: 21))
  messages = agent.msgs
end
check(messages == ['we dont need it to be 2 lanes'],
      "split chat reassembled (got #{messages.inspect})")

# ── Test 11: always-on auto-named captures ────────────────────────────
puts "\nTest 11: always-on auto-named captures"

Dir.mktmpdir do |dir|
  Dir.chdir(dir) do
    # server mode: named at init (captures/server-34197.pcap, stable base)
    _, sn = run_sniffer(server: true, server_ip: SERVER_IP, port: 34197, player_db: nil, autoname: true) do |s|
      w = s.instance_variable_get(:@pcap_writer)
      ok = w && w.path =~ %r{captures/server-34197\.pcap\z}
      check(!!ok, "server auto-name, no run timestamp (got #{w && w.path})")
      w&.close
    end

    # client mode: deferred until the first packet reveals the server
    _, sn = run_sniffer(local_ip: '10.0.0.50', player_db: nil, autoname: true) do |s|
      check(s.instance_variable_get(:@pending_capture) == File.join(dir, 'captures'),
            'client capture pending until first packet')
      pkt = "\x06\x02".b + ([0] * 10).pack('C*')
      s.send(:process_packet, 1, 1_700_000_000.0, '10.0.0.50', '10.0.0.1', 50000, 34197, pkt)
      w = s.instance_variable_get(:@pcap_writer)
      ok = w && w.path =~ %r{captures/client-10\.0\.0\.1\.pcap\z}
      check(!!ok, "client auto-name from first packet, no run timestamp (got #{w && w.path})")
      w&.close
    end
  end
end

# ── Player DB encoding: legacy binary-flagged names must not kill save ──
puts "\nPlayer DB encoding hardening"
require_relative '../lib/player_db'

# A name that arrived binary-flagged (pre-fix decode path / reloaded state)
# must be sanitized on add — the stored value stays usable and JSON-safe.
db = PlayerDatabase.new(nil)
db.add(1, "sévérin".b)
pn = db.lookup(1)
check(pn == 'sévérin', 'binary-flagged name sanitized on add')
check(pn.encoding == Encoding::UTF_8 && pn.valid_encoding?, 'stored name is valid UTF-8')
check(db.name_to_id('sévérin') == 1, 'name index works with the sanitized name')

# Simulate what an old reload could leave behind: a binary entry injected
# straight into @players (bypassing add). save() must still write valid JSON.
Dir.mktmpdir do |dir|
  path = File.join(dir, 'players.json')
  db2 = PlayerDatabase.new(path)
  db2.add(1, 'alice')
  db2.instance_variable_get(:@players)[2] = "sévérin".b   # legacy poison
  db2.save
  raw = File.read(path)
  parsed = JSON.parse(raw)
  check(parsed['2'] == 'sévérin', 'legacy binary entry sanitized at save (no GeneratorError)')
  check(parsed['1'] == 'alice', 'clean entry survives')
end

puts "\n#{'-' * 40}\n#{$pass} passed, #{$fail} failed"
exit($fail.zero? ? 0 : 1)