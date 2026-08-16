#!/usr/bin/env ruby
# Locate hand-mining via the hover mechanism (2.0 only): the last
# selected_entity_changed_based_on_unit_number (type 254) before a
# begin_mining carries the hovered entity's unit number — which IS the
# mining target (verified: 64 hover→begin_mining pairs, mostly 0.0s apart).
#
# Usage:
#   ruby tools/hover_mining.rb CAPTURE [--player N] [--window S] [--ver 2.0]
#     prints every hover→mining pair (time, player, hovered unit number).
#   ... --resolve   additionally resolves surviving unit numbers via RCON
#                   (game.get_entity_by_unit_number) → name + position.
#
# Entities mined are gone from the world → resolve returns nil; that's
# expected and itself a signal (the hovered entity was deleted = mined).
require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'
require 'json'

VER = (ARGV.find_index('--ver') ? ARGV[ARGV.find_index('--ver') + 1] : '2.0')
path = ARGV.reject { |a| a.start_with?('--') }.first
abort "usage: ruby tools/hover_mining.rb CAPTURE [--player N] [--window S] [--resolve] [--ver 2.0|2.1]" unless path
FactorioProtocol.select_version(VER)
if FactorioProtocol.segment_types[254].nil? && FactorioProtocol.actions[254].nil?
  warn "type 254 (selected_entity_changed_based_on_unit_number) is not in the #{VER} table — this tool is 2.0-only"
  exit 1
end
PLAYER = ARGV.find_index('--player') ? ARGV[ARGV.find_index('--player') + 1].to_i : nil
WINDOW = (ARGV.find_index('--window') ? ARGV[ARGV.find_index('--window') + 1].to_f : 6.0)
RESOLVE = ARGV.include?('--resolve')

last_hover = {}   # gp => [ts, unit]
pairs = []
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
      next if PLAYER && gp != PLAYER
      if a[:type] == 254 && a[:data] && a[:data].bytesize >= 4
        last_hover[gp] = [ts, a[:data].unpack('V').first]
      elsif a[:name] == 'begin_mining' && last_hover[gp]
        hts, hun = last_hover[gp]
        if ts - hts <= WINDOW
          pairs << [ts, gp, hun, ts - hts]
          last_hover[gp] = nil
        end
      end
    end
  end
end

puts "hover→begin_mining pairs (window #{WINDOW}s): #{pairs.size}"
if RESOLVE && pairs.any?
  # Batch-resolve surviving unit numbers via RCON
  ids = pairs.map { |p| p[2] }.uniq
  idlist = ids.join(',')
  body = `ruby tools/rcon.rb exec "/sc local o={} for _,id in ipairs({#{idlist}}) do local e=game.get_entity_by_unit_number(id) if e and e.valid then local p=e.position o[#o+1]=id..'='..e.name..' '..e.surface.name..' '..string.format('%.1f,%.1f',p.x,p.y) else o[#o+1]=id..'=nil' end end rcon.print(helpers.table_to_json(o))" 2>/dev/null`
  resolved = {}
  begin
    JSON.parse(body).each do |entry|
      k, v = entry.split('=', 2)
      resolved[k.to_i] = v
    end
  rescue
    warn "could not parse RCON resolve response; run without --resolve or check tools/rcon.rb"
  end
  pairs.sort_by { |p| p[0] }.each do |ts, gp, hun, dt|
    puts "  #{Time.at(ts).strftime('%m-%d %H:%M:%S')} p#{gp} hover #{dt.round(1)}s before mining → unit #{hun}: #{resolved[hun] || '(deleted — mined?)'}"
  end
else
  pairs.sort_by { |p| p[0] }.each do |ts, gp, hun, dt|
    puts "  #{Time.at(ts).strftime('%m-%d %H:%M:%S')} p#{gp} hover #{dt.round(1)}s before mining → unit #{hun}"
  end
end
