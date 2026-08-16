#!/usr/bin/env ruby
# Dead-reckon a player's position from start_walking/stop_walking direction
# vectors + game ticks, re-anchoring at builds whose cursor offset is known
# (selected_entity_changed_relative = [dx(2)][dy(2)] i16 LE in 1/256 tiles
# from the player's character). Prints the player position at every
# begin_mining and the estimated mining target (player + last cursor offset).
#
# IMPORTANT — output is APPROXIMATE. Walking speed is not a reliable
# constant: it depends on ground tile, armor equipment (exoskeletons),
# obstacles that stop the player, drag-build placement cadence, and we do
# NOT run the simulation / cannot query historical sim state. Positions
# over long unanchored stretches drift (tens of tiles per minute). Treat
# results as evidence for EXONERATING (player far away) or as a short-range
# corroboration, not as proof of presence. Anchored segments (fresh REL
# offset ≤ ~2s before a build, or a stationary drag-build) are the
# trustworthy parts — check the anchor timestamps in the output.
#
# Usage: ruby tools/track_player.rb CAPTURE --player N --start HH:MM:SS --end HH:MM:SS [--speed TILES_PER_TICK]
require 'time'
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'

VER = (ARGV.find_index('--ver') ? ARGV[ARGV.find_index('--ver') + 1] : '2.0')
path = ARGV.reject { |a| a.start_with?('--') }.first
abort "usage: ruby tools/track_player.rb CAPTURE --player N --start HH:MM:SS --end HH:MM:SS" unless path
FactorioProtocol.select_version(VER)
PLAYER = ARGV[ARGV.find_index('--player') + 1].to_i
T0 = Time.parse(ARGV[ARGV.find_index('--start') + 1])
T1 = Time.parse(ARGV[ARGV.find_index('--end') + 1])
SPEED = ARGV.find_index('--speed') ? ARGV[ARGV.find_index('--speed') + 1].to_f : 0.1455

def px(v) = v >= 0x80000000 ? v - 0x100000000 : v

# state
pos = nil          # [x, y] player character position (tiles)
dir = nil          # [dx, dy] unit vector of current walk
last_tick = nil    # game tick when the current walk segment started
walking = false
last_off = nil     # last known cursor offset [dx, dy] + tick
anchors = 0

def advance!(pos, dir, from_tick, to_tick, speed)
  return pos unless pos && dir && from_tick && to_tick
  dt = to_tick - from_tick
  return pos if dt <= 0
  [pos[0] + dir[0] * speed * dt, pos[1] + dir[1] * speed * dt]
end

rows = []
PcapReader.new(path).each_packet do |_, ts, src, dst, sport, dport, udp, _|
  next unless udp
  t = Time.at(ts)
  next if t < T0 || t > T1
  begin
    res = FactorioProtocol.parse_udp_payload(udp)
  rescue
    next
  end
  next unless res && res[:heartbeat]
  (res[:heartbeat][:tick_closures] || []).each do |tc|
    tick = tc[:tick]
    (tc[:actions] || []).each do |a|
      next unless a[:game_player] == PLAYER
      case a[:name]
      when 'start_walking'
        d = a[:data]
        next unless d && d.bytesize >= 16
        dx = d.unpack('E', offset: 0).first
        dy = d.unpack('E', offset: 8).first
        # advance on the old heading first
        pos = advance!(pos, dir, last_tick, tick, SPEED) if walking
        mag = Math.sqrt(dx * dx + dy * dy)
        if mag > 0.001
          dir = [dx / mag, dy / mag]
        else
          dir = [0.0, 0.0]
        end
        last_tick = tick
        walking = true
      when 'stop_walking'
        pos = advance!(pos, dir, last_tick, tick, SPEED) if walking
        walking = false
        last_tick = tick
      when 'selected_entity_changed_relative'
        d = a[:data]
        if d && d.bytesize >= 4
          last_off = [d.unpack('s<', offset: 0).first / 256.0,
                      d.unpack('s<', offset: 2).first / 256.0, tick]
        end
      when 'build'
        # advance to now, then anchor: player = build_pos - cursor_offset
        pos = advance!(pos, dir, last_tick, tick, SPEED) if walking
        d = a[:data]
        next unless d && d.bytesize >= 8
        bx = px(d.unpack('i', offset: 0).first) / 256.0
        by = px(d.unpack('i', offset: 4).first) / 256.0
        if last_off && tick - last_off[2] <= 120   # offset fresher than 2s
          pos = [bx - last_off[0], by - last_off[1]]
          anchors += 1
        end
      when 'begin_mining', 'stop_mining'
        pos = advance!(pos, dir, last_tick, tick, SPEED) if walking
        target = nil
        off_age = last_off ? tick - last_off[2] : nil
        if pos && last_off && off_age <= 300   # offset fresher than 5s
          target = [pos[0] + last_off[0], pos[1] + last_off[1]]
        end
        # Last anchor age: how many ticks since the position was pinned to a
        # build+offset pair (nil = never anchored in this window).
        rows << [t, tick, a[:name],
                 pos ? format('(%.1f, %.1f)', pos[0], pos[1]) : '?',
                 target ? format('target=(%.1f, %.1f) off_age=%ds', target[0], target[1], (off_age / 60).round) : '',
                 anchors]
      end
    end
  end
end

puts "player p#{PLAYER}  #{T0.strftime('%H:%M:%S')}..#{T1.strftime('%H:%M:%S')}  speed=#{SPEED} tiles/tick  anchors=#{anchors}"
rows.each { |t, tick, name, ppos, tgt, a| puts "#{t.strftime('%H:%M:%S.%L')} tick #{tick} #{name.ljust(12)} #{ppos} #{tgt}" }
