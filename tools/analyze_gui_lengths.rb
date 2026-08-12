#!/usr/bin/env ruby
# Determine TRUE data lengths for variable-length actions by exact boundary
# math on CLIENT packets: after the final action, exactly 8 bytes (next_receive)
# must remain. So for a GUI action at data_start: len = pkt_size - data_start - 8.
# Server echoes may differ; this pins the client-side ground truth.

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
data = File.binread(File.expand_path('../factorio_capture.pcap', __dir__))
result = Hash.new(0) # [type, len, gui] -> count
samples = {}

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
  next unless mt == 6 # client packets only (exact 8-byte next_receive boundary)
  pos = (d.getbyte(0) & 0x20) != 0 ? 5 : 1
  pos += 1 # flags
  pos += 4 # seq
  next if pos + 8 > d.bytesize
  pos += 8 # tick
  pos, cf = dec32v(d, pos)
  next if cf.nil?
  count = cf >> 1
  # walk actions until we hit a GUI type
  found = false
  count.times do
    break if pos + 1 > d.bytesize
    pos, t = dec16v(d, pos)
    pos, delta = dec16v(d, pos)
    break if t.nil? || delta.nil?
    if GUI.include?(t)
      len = d.bytesize - pos - 8
      if len >= 0
        gt = len >= 1 ? d.getbyte(pos) : nil
        result[[t, len, gt]] += 1
        samples[[t, len, gt]] ||= d[pos, [len, 24].min].unpack1('H*')
      end
      found = true
      break
    else
      entry = FactorioProtocol::ACTIONS[t]
      alen = entry ? entry[1] : nil
      if alen == 0
      elsif alen && pos + alen <= d.bytesize
        pos += alen
      else
        break
      end
    end
  end
end

puts '=== client GUI action true lengths (exact boundary) ==='
result.sort_by { |(t, len, gt), _| [t, len, gt || -1] }.each do |(t, len, gt), c|
  puts "type #{t} (#{FactorioProtocol.action_name(t)}) len=#{len} gui=0x#{gt&.to_s(16)}: #{c}  sample=#{samples[[t, len, gt]]}"
end
