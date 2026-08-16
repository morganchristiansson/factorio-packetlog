#!/usr/bin/env ruby
# Per-player position map: all position-bearing actions with correct decodes.
# Usage: ruby tools/posmap.rb CAPTURE [--ver 2.0|2.1] [--near X Y R] [--player N]
# Position sources only (2026-08-16 corrections): build, begin_mining_terrain,
# change_shooting_state, move_on_pan, deconstruct. NOT drop_item (direction
# double) or zoom_around_point (doubles don't match player positions).
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'

VER = (ARGV.find_index('--ver') ? ARGV[ARGV.find_index('--ver') + 1] : '2.0')
path = ARGV.reject { |a| a.start_with?('--') }.first
abort "usage: ruby tools/posmap.rb CAPTURE [--ver ..] [--near X Y R] [--player N]" unless path
FactorioProtocol.select_version(VER)

NEAR = ARGV.find_index('--near') ? ARGV[ARGV.find_index('--near') + 1, 3].map(&:to_f) : nil
PLAYER = ARGV.find_index('--player') ? ARGV[ARGV.find_index('--player') + 1].to_i : nil

def px(v) = v >= 0x80000000 ? v - 0x100000000 : v
def ok(gp) = PLAYER.nil? || gp == PLAYER

events = []  # [ts, gp, tick, name, x, y]
PcapReader.new(path).each_packet do |_, ts, src, dst, sport, dport, udp, _|
  next unless udp
  begin
    res = FactorioProtocol.parse_udp_payload(udp)
  rescue
    next
  end
  next unless res && res[:heartbeat]
  (res[:heartbeat][:tick_closures] || []).each do |tc|
    (tc[:actions] || []).each do |a|
      gp = a[:game_player]
      next unless ok(gp)
      pos = FactorioProtocol::Position.decode(a)
      next unless pos
      x, y = pos[0], pos[1]
      next unless x.finite? && y.finite? && x.abs < 1_000_000 && y.abs < 1_000_000
      events << [ts, gp, tc[:tick], a[:name], x, y]
    end
  end
end

if NEAR
  tx, ty, r = NEAR
  puts "== events within #{r} tiles of (#{tx},#{ty}) =="
  hits = events.select { |e| (e[4]-tx).abs <= r && (e[5]-ty).abs <= r }
  hits.sort_by { |e| e[0] }.each do |ts, gp, tick, name, x, y|
    puts "  #{Time.at(ts).strftime('%m-%d %H:%M:%S')} p#{gp} tick #{tick} #{name} at (#{x.round(1)},#{y.round(1)})"
  end
  puts "  (none)" if hits.empty?
else
  # per-player: first/last known position + bounding box + count
  byp = Hash.new { |h, k| h[k] = [] }
  events.each { |e| byp[e[1]] << e }
  puts "== per-player position footprint =="
  byp.keys.sort.each do |gp|
    arr = byp[gp].sort_by { |e| e[0] }
    xs = arr.map { |e| e[4] }; ys = arr.map { |e| e[5] }
    first = Time.at(arr.first[0]).strftime('%H:%M:%S')
    last = Time.at(arr.last[0]).strftime('%H:%M:%S')
    puts "  p#{gp}: #{arr.size} pos-actions #{first}..#{last}  x[#{xs.min.round(0)}..#{xs.max.round(0)}] y[#{ys.min.round(0)}..#{ys.max.round(0)}]"
  end
end
