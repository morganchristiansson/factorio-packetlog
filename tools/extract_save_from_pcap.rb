#!/usr/bin/env ruby
# Extract the map save (mp-save-100.zip + decompressed level.dat) from a pcap.
#
# The Factorio map download is a stream of TransferBlock (msg 13) packets,
# each carrying a 503-byte block. Blocks 0..N concatenated = the server's
# save file, which is a ZIP (with data-descriptor flags) containing the
# scenario files and level.dat0..123 chunks. Each level.dat chunk is
# independently zlib-compressed and decompresses to exactly 1 MiB; chunks
# must be joined in NAME order (zip entry order is the random transfer order).
#
# Usage:
#   ruby tools/extract_save_from_pcap.rb factorio_capture.pcap [outdir]
#
# Outputs:
#   outdir/save.zip            — the reconstructed save archive
#   outdir/level.dat           — concatenated decompressed chunks (name order)
#   outdir/level.dat.N         — each individual decompressed chunk
#   outdir/files/              — other zip entries (control.lua, info.json, ...)
#   outdir/summary.txt         — what was recovered
#
# Notes:
#   - If the pcap contains MULTIPLE server connections (e.g. joined a 2nd
#     server), block numbers collide. Each download is separated by
#     ConnectionRequest (msg 2) timestamps; download 1 = before the 2nd
#     connection request, download 2 = after. Use --download N to pick one.
#   - Packet loss in the capture leaves holes (zero-padded) which corrupt
#     some zlib chunks; intact chunks are decompressed, others are skipped.

require 'zlib'

PCAP_PATH = ARGV[0] || 'factorio_capture.pcap'
OUTDIR = ARGV[1] || 'save_extract'
DOWNLOAD = (ARGV[2] && ARGV[2].to_i) || 1

# ── pcap reading ──────────────────────────────────────────────────────────
data = File.binread(PCAP_PATH)
magic = data.unpack1('V')
endian = (magic == 0xa1b2c3d4) ? :little : :big
raise "Not a pcap file" unless [:little, :big].include?(endian)
gh = data.unpack(endian == :little ? 'VvvVVVV' : 'NnnNNNN')
linktype = gh[6]

blocks = {}   # block_number -> 503-byte payload
conn_ts = []  # timestamps of ConnectionRequest packets
pkt_num = 0
offset = 24
while offset + 16 <= data.bytesize
  ph = data.unpack(endian == :little ? 'VVVV' : 'NNNN', offset: offset)
  ts_sec, ts_usec, incl_len, _ = ph
  offset += 16
  break if offset + incl_len > data.bytesize
  pkt_data = data[offset, incl_len]
  offset += incl_len
  pkt_num += 1

  raw = case linktype
        when 1 then pkt_data[14..]
        when 0 then pkt_data[4..]
        when 113 then pkt_data[16..]
        else pkt_data
        end
  next if raw.nil? || raw.bytesize < 28
  ihl = (raw.getbyte(0) & 0x0F) * 4
  next unless raw.getbyte(9) == 17
  next if raw.bytesize < ihl + 8
  udp = raw[ihl + 8, raw.bytesize - ihl - 8]
  next if udp.nil? || udp.bytesize < 1
  mt = udp.getbyte(0) & 0x1F
  ts = ts_sec + ts_usec / 1_000_000.0
  conn_ts << ts if mt == 2
  next unless mt == 13

  # Separate downloads: each ConnectionRequest starts a new connection.
  # Download 1 = packets before the 2nd connection request, etc.
  dl_index = conn_ts.count { |t| t <= ts }
  next unless dl_index == DOWNLOAD
  bn = udp.unpack1('V', offset: 1)
  blocks[bn] = udp[5..] || '' unless blocks.key?(bn)
end

if blocks.empty?
  warn "No TransferBlocks found for download #{DOWNLOAD}"
  exit 1
end
maxb = blocks.keys.max
missing = (0..maxb).reject { |bn| blocks[bn] }
puts "Download #{DOWNLOAD}: #{blocks.size}/#{maxb + 1} blocks (missing #{missing.size})"

stream = (0..maxb).map { |bn| blocks[bn] || ("\x00" * 503) }.join('')

# ── central directory (authoritative sizes; local headers use data descriptors) ──
cd = []
pos = 0
while pos + 46 <= stream.bytesize
  if stream.unpack1('V', offset: pos) == 0x02014b50
    method = stream.unpack1('v', offset: pos + 10)
    csize = stream.unpack1('V', offset: pos + 20)
    usize  = stream.unpack1('V', offset: pos + 24)
    nlen = stream.unpack1('v', offset: pos + 28)
    elen = stream.unpack1('v', offset: pos + 30)
    clen = stream.unpack1('v', offset: pos + 32)
    name = stream[pos + 46, nlen]
    cd << { name: name, method: method, csize: csize, usize: usize }
    pos += 46 + nlen + elen + clen
  else
    pos += 1
  end
end
puts "Central directory entries: #{cd.size}"

# ── locate local headers by scanning (data-descriptor flags make walking unreliable) ──
entries = []
pos = 0
while pos + 30 <= stream.bytesize
  unless stream.getbyte(pos) == 0x50 && stream.getbyte(pos + 1) == 0x4b &&
         stream.getbyte(pos + 2) == 0x03 && stream.getbyte(pos + 3) == 0x04
    pos += 1
    next
  end
  nlen = stream.unpack1('v', offset: pos + 26)
  elen = stream.unpack1('v', offset: pos + 28)
  if nlen.nil? || nlen < 5 || nlen > 200 || pos + 30 + nlen > stream.bytesize
    pos += 4
    next
  end
  name = stream[pos + 30, nlen]
  cent = cd.find { |c| c[:name] == name }
  if cent
    cent[:data_start] = pos + 30 + nlen + elen
    entries << cent
    pos += 30 + nlen + elen + cent[:csize]
  else
    pos += 4
  end
end
puts "Local headers located: #{entries.size}"

require 'fileutils'
FileUtils.mkdir_p(File.join(OUTDIR, 'files'))

summary = []
entries.each do |e|
  ds = e[:data_start]
  first_block = ds / 503
  last_block = (ds + e[:csize] - 1) / 503
  intact = (first_block..last_block).none? { |bn| missing.include?(bn) }
  raw = stream[ds, e[:csize]]
  e[:data] = nil
  if intact && e[:method] == 8
    begin
      e[:data] = Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(raw)
    rescue
      e[:data] = nil
    end
  elsif intact && e[:method] == 0
    # Stored zip entries may still be zlib-compressed internally (level.dat
    # chunks start with the 0x78 0x01 zlib header). Try inflating; fall back
    # to raw data if it isn't zlib.
    begin
      e[:data] = Zlib::Inflate.inflate(raw)
    rescue
      e[:data] = raw
    end
  end
  if e[:data]
    fname = e[:name].tr('/', '_')
    File.binwrite(File.join(OUTDIR, 'files', fname), e[:data]) unless e[:name] =~ %r{level\.dat\d+$}
    summary << "#{e[:name]}: #{e[:data].bytesize}B recovered" if e[:name] =~ %r{level\.dat\d+$} || e[:name] =~ /info.json|script.dat|metadata/
  elsif e[:name] =~ %r{level\.dat\d+$}
    summary << "#{e[:name]}: MISSING/BROKEN (#{e[:csize]}B, spans blocks #{first_block}-#{last_block})"
  end
end

# ── reconstruct level.dat in NAME order ──────────────────────────────────
chunks = {}
entries.each do |e|
  next unless e[:name] =~ %r{/level\.dat(\d+)$} && e[:data]
  chunks[$1.to_i] = e[:data]
end
leveldat = +''
(0...chunks.keys.max.to_i + 1).each do |ci|
  if chunks[ci]
    leveldat << chunks[ci]
    File.binwrite(File.join(OUTDIR, "level.dat.#{ci}"), chunks[ci])
  else
    leveldat << ("\x00" * 1_048_576)
  end
end
File.binwrite(File.join(OUTDIR, 'level.dat'), leveldat)
File.binwrite(File.join(OUTDIR, 'save.zip'), stream[0..(entries.last[:data_start] + entries.last[:csize] - 1)])

File.write(File.join(OUTDIR, 'summary.txt'), summary.join("\n") + "\n")
puts "Recovered #{chunks.size}/#{entries.count { |e| e[:name] =~ %r{level\.dat\d+$} }} level.dat chunks -> #{OUTDIR}/level.dat (#{leveldat.bytesize}B)"
puts "Other files -> #{OUTDIR}/files/"
puts "Summary -> #{OUTDIR}/summary.txt"
