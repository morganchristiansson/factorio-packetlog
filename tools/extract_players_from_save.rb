require 'json'
#!/usr/bin/env ruby
# Extract player name <-> game index mappings from a decompressed level.dat.
#
# The save's console buffer (chat + event log) embeds the sender's GAME INDEX
# after each rendered message:
#
#   02 [len]["name [planet=...]: message"] 00 [INDEX] 00 [color floats] [tick]
#
# Verified against heartbeat echoes: morganc's messages carry index 27
# (0-indexed) == their C->S game index. Alerts reference players by name only
# (no index) and are NOT usable for mapping.
#
# Usage:
#   ruby tools/extract_save_from_pcap.rb factorio_capture.pcap outdir 1
#   ruby tools/extract_players_from_save.rb outdir/level.dat [players.json]
#
# Output (players.json, 1-indexed like the sniffer's db):
#   { "1": "Darkcry", "6": "ElNapo", ... }

data = File.binread(ARGV[0] || 'outdir/level.dat')
OUT = ARGV[1] || 'players_from_save.json'

# The console buffer lives in the chat/event section of level.dat. Scan the
# whole file for chat-shaped messages (cheap enough at ~130 MB).
mapping = {}  # name -> set of indexes seen
msgs = 0
i = 0
while i < data.bytesize - 30
  if data.getbyte(i) == 0x02
    len = data.getbyte(i + 1)
    if len && len >= 3 && len <= 200 && i + 2 + len + 20 < data.bytesize
      txt = data[i + 2, len]
      # rendered console message: "name [planet=...]: ..." or "name: ..."
      if txt =~ /\A[a-zA-Z0-9_\-\. ]+\[planet=[a-z]+\]: / ||
         txt =~ /\A[a-zA-Z0-9_\-\.]+: /
        name = txt[/\A[a-zA-Z0-9_\-\.]+/]
        index = data.getbyte(i + 2 + len + 1)  # the XX field
        next if index.nil?
        (mapping[name] ||= {})[index] = true
        msgs += 1
        i += 2 + len + 40
        next
      end
    end
  end
  i += 1
end

puts "console messages parsed: #{msgs}"
puts "unique players: #{mapping.size}"

db = {}
mapping.each do |name, idxs|
  if idxs.size > 1
    puts "[warn] #{name} has multiple indexes #{idxs.keys.inspect} — skipped"
    next
  end
  idx = idxs.keys.first
  db[(idx + 1).to_s] = name  # 1-indexed
  puts "  #{name} -> game index #{idx} (1-idx #{idx + 1})"
end

File.write(OUT, JSON.pretty_generate(db))
puts "wrote #{OUT}"
