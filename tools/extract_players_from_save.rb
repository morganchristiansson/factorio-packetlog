#!/usr/bin/env ruby
# Recover the player roster (game index -> name, play time, last-online, locale)
# from a Factorio save. The parsing lives in lib/factorio_save.rb (the save's
# string container + the player-record fields); this is the CLI: anchor the run
# against players-cache.json, report, optionally merge.
#
# The roster is an array of LuaPlayer records in GAME-INDEX ORDER (see
# docs/save/level-dat.md). A record is found by its name field; the play-time
# pair and the locale are read out of it, and the game index is the record's
# position in the run — anchored (and validated) with players-cache.json when
# it has names, assumed to start at index 1 when it does not (client mode,
# before anyone has joined; the first join seen on the wire corrects it).
#
# Usage:
#   ruby tools/extract_players_from_save.rb SAVE.zip [players-cache.json] [--merge]
#   ruby tools/extract_players_from_save.rb level.dat  [players-cache.json] [--merge]
#
#   SAVE.zip    a save archive (level.dat0..N chunks, joined in NAME order;
#               needs `unzip` on PATH)
#   level.dat   the already decompressed/joined stream
#   --merge     write the recovered names (and any locale the cache lacks) into
#               players-cache.json, keeping its admin/quickbar fields
#
# Output: {game index (1-indexed) => {name:, online_time_ticks:,
# last_online_tick:, locale:}}, plus what was added.

require 'json'
require 'zlib'
require_relative '../lib/factorio_save'

SAVE = ARGV.find { |a| !a.start_with?('--') } or abort(<<~USAGE)
  usage: ruby tools/extract_players_from_save.rb SAVE.zip|level.dat [players-cache.json] [--merge]
USAGE
CACHE = ARGV.reject { |a| a.start_with?('--') }[1] || 'players-cache.json'
MERGE = ARGV.include?('--merge')

# The decompressed level.dat stream, chunk by chunk (~1 MiB each).
def each_chunk(path)
  return enum_for(:each_chunk, path) unless block_given?
  if File.extname(path) == '.zip'
    # Chunks are zlib-compressed individually and MUST be joined in name
    # order (zip entry order is random).
    names = IO.popen(['unzip', '-Z1', path], &:read).lines.map(&:strip)
    names.grep(%r{/level\.dat\d*\z}).sort_by { |n| n[%r{level\.dat(\d*)\z}, 1].to_i }.each do |n|
      yield Zlib::Inflate.inflate(IO.popen(['unzip', '-p', path, n], 'rb', &:read))
    end
  else
    File.open(path, 'rb') do |f|
      while (chunk = f.read(1 << 20))
        yield chunk
      end
    end
  end
end

roster_scan = FactorioSave::Roster.new(each_chunk(SAVE))
records = roster_scan.records
abort 'no candidate names found — not a level.dat stream?' if records.empty?

# A PLAYER RECORD is a name with a play-time/last-online pair in front of it:
# exactly the 338 records in our save have one, against ~280 prototype names
# and chat strings carrying the same name signature.
roster_records = records.select { |r| r[:online_time_ticks] }

cache = File.exist?(CACHE) ? JSON.parse(File.read(CACHE)) : {}
known = {}
cache.each { |id, rec| known[rec['name']] = id.to_i if rec.is_a?(Hash) && rec['name'] }

# Anchor: index - position is constant across the run. With no cache to anchor
# on we ASSUME the run starts at index 1 (verified on 2.0.77, where index 0
# has no record) — and a join seen on the wire later corrects it anyway
# (PlayerDatabase#remove_other_entries_for).
offsets = Hash.new(0)
roster_records.each_with_index { |r, i| offsets[known[r[:name]] - i] += 1 if known[r[:name]] }
if known.empty?
  shift = 1
  puts 'no known players in the cache — roster taken from the record structure alone'
else
  shift, votes = offsets.max_by { |_, v| v }
  puts "candidates: #{records.size}   known names anchoring the run: #{votes}/#{known.size}"
end
mismatched = roster_records.each_with_index.reject { |r, i| !known[r[:name]] || known[r[:name]] - i == shift }
                   .map { |r, i| "#{r[:name]}@#{i} (cache index #{known[r[:name]]}, run says #{i + shift})" }
# A cached player the save does NOT have is normal, not a foreign world: they
# joined after this save was written. Only a name at a DIFFERENT index means
# the two are not the same world, and that is what refuses the merge.
absent = known.keys - roster_records.map { |r| r[:name] }
if absent.any?
  puts "note: #{absent.size} cached player(s) joined after this save: #{absent.first(5).inspect}#{'…' if absent.size > 5}"
end
if mismatched.any?
  puts "[warn] #{mismatched.size} known name(s) disagree with the run: #{mismatched.first(5).join(', ')}"
  puts '[warn] the save does not match this cache (different world/savefile?) — not merging'
  exit 1
end

roster = roster_records.each_with_index.to_h { |r, i| [i + shift, r] } # index -> record
puts "roster: #{roster.size} players (indexes #{roster.keys.min}..#{roster.keys.max})"
ticks = roster.values.sum { |r| r[:online_time_ticks] || 0 }
puts "play time: #{roster.values.count { |r| r[:online_time_ticks] }} records, #{ticks} ticks total " \
     "(#{(ticks / 60 / 3600.0).round} h), save tick #{roster_scan.save_tick}, pair slots #{roster_scan.slots.inspect}"
locales = roster.values.count { |r| r[:locale] }
puts "locale: #{locales}/#{roster.size} records (#{roster.values.count { |r| r[:locale] == 'en' }} en)"
colors = roster.values.count { |r| r[:color] }
puts "color: #{colors}/#{roster.size} records (#{roster.values.map { |r| r[:color] }.compact.uniq.size} distinct)"

named = roster.transform_values { |r| r[:name] }
added = named.reject { |_, name| known.key?(name) } # the mismatch check passed, so these are new
puts "new: #{added.size} -> #{added.values.first(10).inspect}#{'…' if added.size > 10}"
renamed = named.select { |id, name| known.key?(name) && known[name] != id }
puts "renamed: #{renamed.map { |id, n| "#{id}: #{known[n]} -> #{n}" }.join(', ')}" if renamed.any?

if MERGE
  merged = {}
  named.each { |id, name| merged[id.to_s] = (cache[id.to_s] || {}).merge('name' => name) }
  # a locale the save knows and the cache does not (packets/RCON win):
  # ||= so a known locale is never overwritten, and a missing one stays missing
  roster.each { |id, r| merged[id.to_s]['locale'] ||= r[:locale] if r[:locale] }
  roster.each { |id, r| merged[id.to_s]['color'] ||= r[:color] if r[:color] }
  (cache.keys - merged.keys).sort_by(&:to_i).each { |k| merged[k] = cache[k] } # keep stale ids
  File.write(CACHE, JSON.pretty_generate(merged))
  puts "wrote #{CACHE} (#{merged.size} players)"
else
  out = roster.to_h { |id, r|
    [id.to_s, {name: r[:name], online_time_ticks: r[:online_time_ticks],
               last_online_tick: r[:last_online_tick], locale: r[:locale],
               color: r[:color]}.compact]
  }
  puts JSON.pretty_generate(out)
end
