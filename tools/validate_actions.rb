#!/usr/bin/env ruby
# Validate input-action wire IDs by correlating `/toggle-action-logging`
# output with packet captures, self-contained: it captures packets and
# tails factorio-current.log for the SAME window.
#
# The game logs one line per action (names only, no IDs):
#   Action performed [7544253 36 StartWalking]
# i.e. [<game_tick> <player_index> <ActionName>]. Heartbeat tick closures
# carry the SAME game tick with the wire action IDs, in processing order —
# so joining on (tick, player, position) pairs each name with its ID.
#
# One-shot (needs root for capture; RCON for the toggle):
#   sudo ruby tools/validate_actions.rb --capture 60 --toggle --table 20 --suggest
#
# Or with an existing capture:
#   ruby tools/validate_actions.rb --pcap factorio.pcap --table 20
#
# Options:
#   --capture SECONDS  capture for SECONDS (root) + tail the log meanwhile
#   --pcap FILE        analyze an existing capture (log filtered by window)
#   --toggle           enable action logging at start, disable at end (RCON)
#   --log FILE         default ~/factorio/factorio-current.log
#   --table 20|21      diff against ACTIONS_20 (default) or ACTIONS (2.1)
#   --suggest          print a corrected Ruby table for pasting
require 'optparse'
require 'timeout'
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'
require_relative '../lib/server_detect'

options = { log: File.expand_path('~/factorio/factorio-current.log'), table: 20, suggest: false }
OptionParser.new do |opts|
  opts.banner = 'Usage: validate_actions.rb [--capture SECONDS | --pcap FILE] [--toggle] [--table 20|21] [--suggest]'
  opts.on('--capture SECONDS', Integer, 'Live-capture for SECONDS (root), tailing the log meanwhile') { |v| options[:capture] = v }
  opts.on('--pcap FILE', 'Analyze an existing packet capture') { |v| options[:pcap] = v }
  opts.on('--toggle', 'Enable action logging at start, disable at end (RCON)') { |v| options[:toggle] = true }
  opts.on('--log FILE', "Factorio log (default: ~/factorio/factorio-current.log)") { |v| options[:log] = v }
  opts.on('--table N', Integer, 'Table to diff against: 20 (2.0 defines) or 21 (2.1)') { |v| options[:table] = v }
  opts.on('--suggest', 'Print a corrected Ruby table for pasting') { |v| options[:suggest] = true }
end.parse!
abort 'Give --capture SECONDS or --pcap FILE' unless options[:capture] || options[:pcap]

def rcon
  d = ServerDetect.detect
  abort 'No running factorio server / RCON detected' unless d[:rcon_port]
  require_relative '../lib/rcon_client'
  RconClient.new(host: d[:rcon_host] || 'localhost', port: d[:rcon_port], password: d[:rcon_password])
end

pkt_actions = Hash.new { |h, k| h[k] = [] }  # tick => [[raw_player, wire_type], ...]

# ── Capture mode: capture + tail the log for the same window ───────
if options[:capture]
  if options[:toggle]
    rcon.command('/toggle-action-logging')
    puts 'action logging enabled'
  end

  require_relative '../lib/live_capture'
  detected = ServerDetect.detect
  iface = ServerDetect.capture_iface(detected[:cmdline]) || LiveCapture.list_interfaces.first
  port = detected[:game_port]
  puts "capturing #{options[:capture]}s on #{iface}:#{port} (tail #{options[:log]})..."

  # Tail the log from its current end, recording action lines as they appear.
  log_actions = Hash.new { |h, k| h[k] = [] }
  log_done = false
  tail = Thread.new do
    File.open(options[:log], 'r') do |f|
      f.seek(0, IO::SEEK_END)
      loop do
        break if log_done
        line = f.gets
        if line
          m = line.match(/Action performed \[(\d+) (\d+) (\w+)\]/)
          log_actions[m[1].to_i] << [m[2].to_i, m[3]] if m
        else
          f.reopen(options[:log]) if f.stat.size < f.pos  # rotated/truncated
          sleep 0.05
        end
      end
    end
  end

  n_pkts = 0
  begin
    Timeout.timeout(options[:capture]) do
      LiveCapture.new(interface: iface, port: port).each_packet do |_pkt, _ts, _src, _dst, _sp, _dp, udp_data, _raw|
        n_pkts += 1
        next unless udp_data && udp_data.getbyte(0) == 6
        parsed = FactorioProtocol.parse_udp_payload(udp_data)
        next unless parsed
        hb = parsed[:heartbeat]
        hb[:tick_closures]&.each do |tc|
          next unless tc[:tick]
          tc[:actions]&.each { |a| pkt_actions[tc[:tick]] << [a[:player], a[:type]] }
        end
      end
    end
  rescue Timeout::Error
    # window done
  rescue => e
    warn "capture failed: #{e.class}: #{e.message}"
  ensure
    log_done = true
    tail.join(2)
  end
  puts "captured #{n_pkts} packets, #{log_actions.sum { |_, v| v.size }} log lines"
  rcon.command('/toggle-action-logging') if options[:toggle]
end

# ── Pcap mode: filter the whole log to the capture's tick window ───
if options[:pcap]
  reader = PcapReader.new(options[:pcap])
  reader.each_packet do |_pkt, _ts, _src, _dst, _sp, _dp, udp_data, _raw|
    next unless udp_data && udp_data.getbyte(0) == 6
    parsed = FactorioProtocol.parse_udp_payload(udp_data)
    next unless parsed
    hb = parsed[:heartbeat]
    hb[:tick_closures]&.each do |tc|
      next unless tc[:tick]
      tc[:actions]&.each { |a| pkt_actions[tc[:tick]] << [a[:player], a[:type]] }
    end
  end
  lo, hi = pkt_actions.keys.minmax
  log_actions = Hash.new { |h, k| h[k] = [] }
  File.foreach(options[:log]) do |line|
    m = line.match(/Action performed \[(\d+) (\d+) (\w+)\]/)
    next unless m
    t = m[1].to_i
    next if t < lo || t > hi
    log_actions[t] << [m[2].to_i, m[3]]
  end
end

abort 'no packet actions captured' if pkt_actions.empty?
puts "pcap: #{pkt_actions.size} ticks, #{pkt_actions.sum { |_, v| v.size }} actions"
puts "log:  #{log_actions.size} ticks, #{log_actions.sum { |_, v| v.size }} action lines"

# ── Join on (tick, player, position) ───────────────────────────────
# The log's player index may be raw (0-based) or game (1-based), and the
# closure tick may lead/lag the server's processing tick — scan small
# offsets and keep the alignment with the most (tick, player) joins.
# Type-0 "nothing" padding is stripped from the pcap side (it is never
# logged; keeping it would shift the last pairing by one).
def self.normalize(name)
  name.to_s.gsub(/([a-z0-9])([A-Z])/, '\1_\2').downcase  # CamelCase -> snake_case
end

best = { score: -1, tick_off: 0, p_off: 0, conf: {}, exact: 0 }
(-2..2).each do |tick_off|
  [0, 1].each do |p_off|
    conf = Hash.new(0)
    joined = 0
    exact = 0
    (log_actions.keys & pkt_actions.keys.map { |t| t + tick_off }).each do |lt|
      lbp = log_actions[lt].group_by(&:first)
      pbp = pkt_actions[lt - tick_off].group_by(&:first)
      lbp.each do |lplayer, lseq|
        pseq = pbp[lplayer + p_off]&.reject { |(_p, w)| w == 0 }  # strip nothing padding
        next unless pseq
        joined += 1
        next unless lseq.size == pseq.size  # exact positional match only
        exact += 1
        lseq.zip(pseq).each { |(_, name), (_, wire)| conf[[wire, normalize(name)]] += 1 }
      end
    end
    best = { score: joined, tick_off: tick_off, p_off: p_off, conf: conf, exact: exact } if joined > best[:score]
  end
end
puts "alignment: tick_offset=#{best[:tick_off]} player=#{best[:p_off].zero? ? 'raw' : 'game'} (#{best[:score]} joins, #{best[:exact]} exact)"

# Table names are snake_case; compare against the normalized log names.
table = options[:table] == 21 ? FactorioProtocol::ACTIONS : FactorioProtocol::ACTIONS_20
known = table.each_with_object({}) { |(id, (name, _)), h| h[id] = name }
best_name = {}
best[:conf].each { |(wire, name), n| best_name[wire] = [name, n] if !best_name[wire] || n > best_name[wire][1] }

puts "\n== Confirmed wire IDs (#{best_name.size}) =="
best_name.sort.each do |wire, (name, n)|
  tname = known[wire]
  flag = if tname == name
    'OK'
  elsif tname
    "MISMATCH — table says #{tname}"
  else
    'NOT IN TABLE'
  end
  puts format('  %3d (0x%02x) %-32s x%-4d %s', wire, wire, name, n, flag)
end

cap_ids = pkt_actions.values.flatten(1).map(&:last).uniq
missing = cap_ids - known.keys
puts "\n== Wire IDs in capture not in table (#{missing.size}) =="
puts '  ' + missing.sort.map { |w| format('%d(0x%02x)', w, w) }.join(' ') unless missing.empty?

never = known.keys - cap_ids
puts "\n== Table entries never seen in capture (#{never.size}) =="
puts '  (unexercised — not necessarily wrong)' unless never.empty?

if options[:suggest]
  suggest = {}
  known.each { |id, name| suggest[id] = name unless best_name[id] }
  best_name.each { |id, (name, _)| suggest[id] = name }
  puts "\n== Suggested table (confirmed overrides) =="
  suggest.sort.each { |id, name| puts "  #{id} => [#{name.inspect}, #{table[id]&.last.inspect}]," }
end
