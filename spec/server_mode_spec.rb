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

def run_sniffer(opts)
  out = StringIO.new
  old = $stdout
  $stdout = out
  sniffer = FactorioSniffer.new(opts)
  begin
    yield sniffer
  ensure
    $stdout = old
  end
  [out.string, sniffer]
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
capture_path = File.join(Dir.tmpdir, 'srv_test.pcap')
File.delete(capture_path) if File.exist?(capture_path)

out, sniffer = run_sniffer(
  server: true, server_ip: SERVER_IP, player_db: nil, save_capture: capture_path
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

# capture file: client chat (incoming) + server echo (outgoing) are
# captured; only msg13 TransferBlocks are excluded from capture in server
# mode. Close the writer to flush the background thread's buffer.
sniffer.instance_variable_get(:@pcap_writer).close
pcap_bytes = File.binread(capture_path)
recs = 0
bad = 0
off = 24
while off + 16 <= pcap_bytes.bytesize
  _, _, incl, _ = pcap_bytes.unpack('VVVV', offset: off)
  off += 16
  break if off + incl > pcap_bytes.bytesize
  payload = pcap_bytes[off + 14 + 20 + 8, incl - 14 - 20 - 8] # eth+ip+udp
  bad += 1 if payload && payload.bytesize >= 500
  recs += 1
  off += incl
end
puts "  INFO: captured #{recs} records, #{bad} large (>=500B) payloads"
check(recs == 2, "capture has 2 records (client + echo), msg13 excluded (got #{recs})")
check(bad.zero?, 'no 503-byte TransferBlock payloads in capture')

# ── Test 2: server mode, pcap-read path (no raw_frame) ────────────────
out, = run_sniffer(server: true, server_ip: SERVER_IP, player_db: nil) do |s|
  ts = 1_700_000_000.0
  s.send(:process_packet, 1, ts, CLIENT_IP, SERVER_IP, 34197, 34197, fixture_packet('client_cursor_select'))
  s.send(:process_packet, 2, ts, SERVER_IP, CLIENT_IP, 34197, 34197, fixture_packet('server_open_gui_echo_14b'))
  s.send(:process_packet, 3, ts, SERVER_IP, CLIENT_IP, 34197, 34197, msg13_packet)
end
puts "\nTest 2: server mode (pcap-read path)"
check(out.include?('cursor_select'), 'incoming msg 6 action logged')
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
out, = run_sniffer(server: true, server_ip: nil, player_db: nil) do |s|
  s.send(:process_packet, 1, 1.0, CLIENT_IP, non_loopback, 34197, 34197, fixture_packet('client_pipette'))
end
puts "  INFO: detected local IPs: #{local_ips.inspect}"
check(out.include?('pipette'), 'auto-detected server IP classified incoming correctly')

# ── Test 5: banner printed via run() pcap-read path ───────────────────
puts "\nTest 5: server mode banner via run()"
run_pcap = File.join(Dir.tmpdir, 'srv_banner.pcap')
File.delete(run_pcap) if File.exist?(run_pcap)
w = PcapWriter.new(run_pcap)
builder = FactorioSniffer.new(player_db: nil)
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

# bare rcon.print body
roster = RconClient.parse_roster("{{i = 1, n = \"morganc\"}, {i = 2, n = \"bob\"}}\n")
check(roster == [{ index: 1, name: 'morganc' }, { index: 2, name: 'bob' }],
      'parse_roster parses the rcon.print body')
# escaped quote in a name
roster = RconClient.parse_roster("{{i = 7, n = \"a \\\"quoted\\\" name\"}}")
check(roster == [{ index: 7, name: 'a "quoted" name' }], 'parse_roster unescapes quotes in names')
# valid empty roster
check(RconClient.parse_roster("{}\n") == [], 'empty roster parses to []')
# non-roster payload
check(RconClient.parse_roster('some random error text').nil?, 'non-roster payload → nil')

# refresh_roster → load_roster: initial load only (new players come from
# the packet stream, no periodic refresh)
sr = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil })
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
sr2 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil })
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
sr3 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil })
sr3.instance_variable_set(:@rcon, fake3)
sr3.send(:load_roster)              # startup query
st = sr3.snapshot                   # Ctrl-C reload: state carried over
sr4 = FactorioSniffer.new({ server: true, server_ip: SERVER_IP, player_db: nil }, st)
sr4.instance_variable_set(:@rcon, fake3)
sr4.send(:load_roster)              # reload — must NOT query again
check(queries == 1, 'roster queried exactly once across hot reload')

puts "\n#{'-' * 40}\n#{$pass} passed, #{$fail} failed"
exit($fail.zero? ? 0 : 1)