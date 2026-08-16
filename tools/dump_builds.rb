#!/usr/bin/env ruby
# Dump ALL build positions (to validate scale + find exact target hits) and
# all mining sessions per player, from a capture.
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'

VER = (ARGV.find_index('--ver') ? ARGV[ARGV.find_index('--ver') + 1] : '2.0')
path = ARGV.reject { |a| a.start_with?('--') }.first
abort "usage: ruby tools/dump_builds.rb CAPTURE [--ver 2.0|2.1] [--min-only]" unless path
FactorioProtocol.select_version(VER)
MIN_ONLY = ARGV.include?('--min-only')

def px(signed32raw)
  signed32raw >= 0x80000000 ? signed32raw - 0x100000000 : signed32raw
end

TX, TY = 558.0, 83.0
builds = []
mining = {}   # gp => [[ts, tick, name], ...]
pos_by = {}   # gp => [[ts, name, x, y], ...]

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
      next unless gp && gp < 10000   # skip bogus player deltas
      case a[:name]
      when 'build'
        pos = FactorioProtocol::Position.decode(a)
        if pos
          builds << [ts, gp, tc[:tick], pos[0], pos[1]]
          (pos_by[gp] ||= []) << [ts, 'build', pos[0], pos[1]]
        end
      when 'begin_mining', 'stop_mining'
        (mining[gp] ||= []) << [ts, tc[:tick], a[:name]]
      when 'deconstruct'
        area = FactorioProtocol::Position.decode(a)
        if area
          x1, y1, x2, y2 = area
          (pos_by[gp] ||= []) << [ts, 'deconstruct', (x1+x2)/2, (y1+y2)/2]
        end
      when 'begin_mining_terrain', 'change_shooting_state'
        pos = FactorioProtocol::Position.decode(a)
        if pos
          name = { 'begin_mining_terrain' => 'mine_terrain', 'change_shooting_state' => 'shoot' }[a[:name]]
          (pos_by[gp] ||= []) << [ts, name, pos[0], pos[1]]
        end
      end
    end
  end
end

unless MIN_ONLY
  puts "== all build positions (sorted by time) =="
  puts "  total builds: #{builds.size}"
  # histogram of build coords in 10-tile buckets to sanity-check scale
  buckets = Hash.new(0)
  builds.each { |b| buckets[[(b[3]/10).floor, (b[4]/10).floor]] += 1 }
  puts "  distinct 10-tile buckets: #{buckets.size}"
  near = builds.select { |b| (b[3]-TX).abs <= 12 && (b[4]-TY).abs <= 12 }
  puts "  builds within ±12 tiles of (558,83): #{near.size}"
  near.sort_by { |b| b[0] }.each do |ts, gp, tick, x, y|
    puts "    #{Time.at(ts).strftime('%m-%d %H:%M:%S')} p#{gp} tick #{tick} (#{x},#{y})"
  end
  puts "  build x-range: #{builds.map { |b| b[3] }.min} .. #{builds.map { |b| b[3] }.max}  y-range: #{builds.map { |b| b[4] }.min} .. #{builds.map { |b| b[4] }.max}"
end

puts
puts "== mining sessions per player (count, first, last) =="
mining.keys.sort.each do |gp|
  arr = mining[gp].sort_by { |m| m[0] }
  begins = arr.count { |m| m[2] == 'begin_mining' }
  next if begins == 0
  first = Time.at(arr.first[0]).strftime('%H:%M:%S')
  last = Time.at(arr.last[0]).strftime('%H:%M:%S')
  puts "  p#{gp}: #{begins} sessions  #{first} .. #{last}"
end

puts
puts "== position-bearing actions near (558,83) ±12 tiles =="
pos_by.each do |gp, arr|
  arr.select { |e| (e[2]-TX).abs <= 12 && (e[3]-TY).abs <= 12 }.sort_by { |e| e[0] }.each do |ts, name, x, y|
    puts "  #{Time.at(ts).strftime('%m-%d %H:%M:%S')} p#{gp} #{name} at (#{x},#{y})"
  end
end
