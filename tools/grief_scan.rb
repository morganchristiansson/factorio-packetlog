#!/usr/bin/env ruby
# Scan a pcap for grief evidence: builds/deconstructs/mining near a target.
# Usage: ruby tools/grief_scan.rb CAPTURE [--tx X] [--ty Y] [--ver 2.0|2.1]
#
# Decode corrections (2026-08-16): drop_item and zoom_around_point are NOT
# position sources (drop_item = direction double; zoom doubles don't match
# player positions) — excluded. change_shooting_state is [flag(1)][V x][V y]
# (/256), not signed i32. Default protocol is 2.0 (this server); pass
# --ver 2.1 for 2.1 captures.
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'

TX = (ARGV.find_index('--tx') ? ARGV[ARGV.find_index('--tx') + 1].to_f : 558.0)
TY = (ARGV.find_index('--ty') ? ARGV[ARGV.find_index('--ty') + 1].to_f : 83.0)
VER = (ARGV.find_index('--ver') ? ARGV[ARGV.find_index('--ver') + 1] : '2.0')
path = ARGV.reject { |a| a.start_with?('--') }.first
abort "usage: ruby tools/grief_scan.rb CAPTURE [--tx X] [--ty Y] [--ver 2.0|2.1]" unless path

FactorioProtocol.select_version(VER)
R = 8  # search radius around target

def px(signed32raw)
  signed32raw >= 0x80000000 ? signed32raw - 0x100000000 : signed32raw
end

min_ts = Float::INFINITY
max_ts = 0.0
players = {}
builds = []        # [ts, game_player, tick, x, y]
decon = []         # [ts, game_player, tick, x1,y1,x2,y2]
mining = []        # [ts, game_player, tick, name]
other_pos = {}     # game_player => [[ts, name, x, y], ...]
n_pkts = 0
n_hb = 0
n_actions = 0

PcapReader.new(path).each_packet do |_, ts, src, dst, sport, dport, udp, _|
  next unless udp
  n_pkts += 1
  min_ts = ts if ts < min_ts
  max_ts = ts if ts > max_ts
  begin
    res = FactorioProtocol.parse_udp_payload(udp)
  rescue => e
    next
  end
  next unless res && res[:heartbeat]
  hb = res[:heartbeat]
  next unless hb[:tick_closures]
  n_hb += 1
  hb[:tick_closures].each do |tc|
    (tc[:actions] || []).each do |a|
      next unless a[:name]
      n_actions += 1
      gp = a[:game_player]
      players[gp] = true
      case a[:name]
      when 'build'
        pos = FactorioProtocol::Position.decode(a)
        if pos
          builds << [ts, gp, tc[:tick], pos[0], pos[1]]
          (other_pos[gp] ||= []) << [ts, 'build', pos[0], pos[1]]
        end
      when 'deconstruct'
        area = FactorioProtocol::Position.decode(a)
        if area
          x1, y1, x2, y2 = area
          decon << [ts, gp, tc[:tick], x1, y1, x2, y2]
          (other_pos[gp] ||= []) << [ts, 'deconstruct', (x1+x2)/2, (y1+y2)/2]
        end
      when 'begin_mining', 'stop_mining'
        mining << [ts, gp, tc[:tick], a[:name]]
      when 'begin_mining_terrain', 'change_shooting_state', 'move_on_pan'
        pos = FactorioProtocol::Position.decode(a)
        if pos
          name = { 'begin_mining_terrain' => 'mine_terrain',
                   'change_shooting_state' => 'shoot',
                   'move_on_pan' => 'pan' }[a[:name]]
          (other_pos[gp] ||= []) << [ts, name, pos[0], pos[1]]
        end
      end
    end
  end
end

puts "== #{path}  (proto #{VER}) =="
puts "range: #{Time.at(min_ts).strftime('%Y-%m-%d %H:%M:%S')} .. #{Time.at(max_ts).strftime('%Y-%m-%d %H:%M:%S')}  (#{((max_ts-min_ts)/60).round(1)} min)"
puts "packets: #{n_pkts}  heartbeats: #{n_hb}  actions: #{n_actions}  players: #{players.keys.sort.join(',')}"
puts
puts "== builds near (#{TX},#{TY}) ±#{R} tiles =="
near = builds.select { |b| (b[3]-TX).abs <= R && (b[4]-TY).abs <= R }
near.sort_by { |b| b[0] }.each do |ts, gp, tick, x, y|
  puts "  #{Time.at(ts).strftime('%H:%M:%S')} p#{gp} tick #{tick} build at (#{x},#{y})"
end
puts "  (none)" if near.empty?
puts
puts "== deconstruct areas covering (#{TX},#{TY}) =="
cov = decon.select { |d| d[3] <= TX && d[5] >= TX && d[4] <= TY && d[6] >= TY }
cov.sort_by { |d| d[0] }.each do |ts, gp, tick, x1, y1, x2, y2|
  puts "  #{Time.at(ts).strftime('%H:%M:%S')} p#{gp} tick #{tick} area (#{x1},#{y1})- (#{x2},#{y2})"
end
puts "  (none)" if cov.empty?
puts
puts "== all mining begin/stop (raw) =="
mining.sort_by { |m| m[0] }.each do |ts, gp, tick, name|
  puts "  #{Time.at(ts).strftime('%H:%M:%S')} p#{gp} tick #{tick} #{name}"
end
puts "  (none)" if mining.empty?
puts
puts "== other position-bearing actions within #{R} tiles =="
other_pos.each do |gp, arr|
  arr.select { |e| (e[2]-TX).abs <= R && (e[3]-TY).abs <= R }.sort_by { |e| e[0] }.each do |ts, name, x, y|
    puts "  #{Time.at(ts).strftime('%H:%M:%S')} p#{gp} #{name} at (#{x},#{y})"
  end
end
