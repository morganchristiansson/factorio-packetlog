#!/usr/bin/env ruby
# Per-player action timeline around a time window, to correlate who was where.
# Usage: ruby tools/timeline.rb CAPTURE --player N [--start HH:MM:SS] [--end HH:MM:SS] [--ver 2.0|2.1]
require 'time'
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'

VER = (ARGV.find_index('--ver') ? ARGV[ARGV.find_index('--ver') + 1] : '2.0')
path = ARGV.reject { |a| a.start_with?('--') }.first
PLAYER = (ARGV.find_index('--player') ? ARGV[ARGV.find_index('--player') + 1].to_i : nil)
START = ARGV.find_index('--start') ? ARGV[ARGV.find_index('--start') + 1] : nil
ENDT = ARGV.find_index('--end') ? ARGV[ARGV.find_index('--end') + 1] : nil
abort "usage: ruby tools/timeline.rb CAPTURE --player N [--start HH:MM:SS] [--end HH:MM:SS]" unless path && PLAYER
FactorioProtocol.select_version(VER)

def px(signed32raw)
  signed32raw >= 0x80000000 ? signed32raw - 0x100000000 : signed32raw
end

t0 = START ? Time.parse(START) : nil
t1 = ENDT ? Time.parse(ENDT) : nil

PcapReader.new(path).each_packet do |_, ts, src, dst, sport, dport, udp, _|
  next unless udp
  t = Time.at(ts)
  next if t0 && t < t0
  next if t1 && t > t1
  begin
    res = FactorioProtocol.parse_udp_payload(udp)
  rescue
    next
  end
  next unless res && res[:heartbeat]
  (res[:heartbeat][:tick_closures] || []).each do |tc|
    (tc[:actions] || []).each do |a|
      gp = a[:game_player]
      next unless gp == PLAYER
      line = "#{t.strftime('%H:%M:%S')} tick #{tc[:tick]} #{a[:name]}"
      if %w[build begin_mining_terrain change_shooting_state move_on_pan].include?(a[:name]) && (pos = FactorioProtocol::Position.decode(a))
        line += "  pos=(#{pos[0].round(2)},#{pos[1].round(2)})"
      elsif a[:name] == 'deconstruct' && (area = FactorioProtocol::Position.decode(a))
        line += "  area=(#{area[0].round(2)},#{area[1].round(2)})- (#{area[2].round(2)},#{area[3].round(2)})"
      elsif a[:name] == 'write_to_console'
        msg = FactorioProtocol.decode_chat(a[:data]) rescue nil
        line += "  chat=#{msg.inspect}" if msg && msg.bytesize > 0
      end
      puts line
    end
  end
end
