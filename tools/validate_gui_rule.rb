#!/usr/bin/env ruby
# Validate a candidate variable-length rule for open_gui (5), open_character_gui (61),
# open_blueprint_library_gui (64), change_active_item_group_for_filters (110):
#   "consume 14 bytes if 14+ available, else 2"
# by walking every server/client heartbeat and checking the walk terminates
# exactly at the packet boundary (server) or the 8-byte next_receive (client).

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'factorio_protocol'

def dec16v(d, o)
  return [o + 1, nil] if o >= d.bytesize
  v = d.getbyte(o)
  return [o + 3, d.unpack1('v', offset: o + 1)] if v == 0xFF && o + 3 <= d.bytesize
  [o + 1, v]
end

def dec32v(d, o)
  return [o + 1, nil] if o >= d.bytesize
  v = d.getbyte(o)
  return [o + 5, d.unpack1('V', offset: o + 1)] if v == 0xFF && o + 5 <= d.bytesize
  [o + 1, v]
end

GUI = [5, 61, 64, 110].freeze

def walk(d, gui_rule)
  # returns [:ok, end_pos] or [:fail, reason, pos]
  mt = d.getbyte(0) & 0x1F
  pos = (d.getbyte(0) & 0x20) != 0 ? 5 : 1
  pos += 1
  pos += 4
  return [:fail, 'short', pos] if pos + 8 > d.bytesize
  pos += 8
  pos, cf = dec32v(d, pos)
  return [:fail, 'no count', pos] if cf.nil?
  count = cf >> 1
  has_seg = (cf & 1) == 1
  count.times do
    return [:fail, 'short type', pos] if pos + 1 > d.bytesize
    pos, t = dec16v(d, pos)
    pos, delta = dec16v(d, pos)
    return [:fail, 'short delta', pos] if t.nil? || delta.nil?
    if GUI.include?(t)
      pos += gui_rule.call(d, pos)
    else
      entry = FactorioProtocol::ACTIONS[t]
      alen = entry ? entry[1] : nil
      if alen == 0
      elsif alen && pos + alen <= d.bytesize
        pos += alen
      else
        return [:fail, "len #{alen.inspect} for #{t} at #{pos}", pos]
      end
    end
  end
  # trailing: client = 8B next_receive, server = end (ignore segments)
  if mt == 6
    return pos + 8 == d.bytesize ? [:ok, pos] : [:fail, "client leftover #{d.bytesize - pos}", pos]
  else
    return pos == d.bytesize ? [:ok, pos] : [:fail, "server leftover #{d.bytesize - pos}", pos]
  end
end

data = File.binread(File.expand_path('../factorio_capture.pcap', __dir__))
stats = Hash.new(0)
gui_seen = 0
off = 24
while off + 16 <= data.bytesize
  incl = data.unpack1('V', offset: off + 8)
  break if off + 16 + incl > data.bytesize
  pkt = data[off + 16, incl]
  off += 16 + incl
  raw = pkt[14..]
  next if raw.nil? || raw.bytesize < 28
  next unless raw.getbyte(9) == 17
  ihl = (raw.getbyte(0) & 0x0F) * 4
  d = raw[ihl + 8, raw.bytesize - ihl - 8]
  next if d.nil? || d.bytesize < 1
  mt = d.getbyte(0) & 0x1F
  next unless [6, 7].include?(mt)
  gui_rule = lambda do |dd, pp|
    (dd.bytesize - pp) >= 14 ? 14 : 2
  end
  status, detail = walk(d, gui_rule)
  stats[status] += 1
  stats["#{status}:#{detail}"] += 1 if status == :fail && mt == 7
end
puts "=== walk results with '14 if available else 2' rule ==="
stats.sort_by { |k, _| k.to_s }.each { |k, v| puts "#{k}: #{v}" }
