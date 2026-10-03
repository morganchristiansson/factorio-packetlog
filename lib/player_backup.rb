# frozen_string_literal: true

require 'json'

# Player backup — the file is lib/player_backup.rb, the class takes its
# CamelCase name, and it is listed in config.yaml `plugins:`. Nothing in the
# sniffer names it: Plugins.features builds every listed class and pushes
# `on_join_enriched` at the ones that implement it.
#
# What it keeps, per player, keyed by NAME, in `players-backup.json` next to
# the process cwd (the players-cache.json convention, and no configuration of
# its own):
#
#   quickbar  the 10×10 grid
#   color     LuaPlayer.color as [r, g, b, a]
#
# WHY a side file, keyed by name: players-cache.json's per-player state is
# per-savefile — game indexes are handed out in join order and reset when the
# save does, so index 42 on a new map is a different person. A name is the
# only thing that survives the save, so this file's lifetime is longer than any
# single save's. That matters most for the quickbar, which the save does NOT
# carry (verified: no encoding of the slot ids appears anywhere in it), so a
# bar has to be restored from here or it is lost.
#
# WHEN: once at startup, from ONE query over the WHOLE roster (see #on_start)
# — every player the save knows, offline included, so a save change cannot
# take a bar we never heard of. Then on every confirmed join, from the ONE
# RCON query the sniffer already makes for the joiner (see
# RconClient#player_attributes_for, which reads the whole bar and the colour).
# Their in-game bar is the truth:
#   * they have one  → snapshot it, which is also how a player who edited
#     their bar mid-session gets the new one saved;
#   * they have none but we do → write it back over RCON, then bring the
#     in-memory cache in line with the game.
#
# The COLOUR is snapshot-only. The save does carry it (four f32s in front of
# the player's name — docs/save/level-dat.md), so the game never loses it and
# there is nothing to restore; we keep it because it is the one per-player
# identity that outlives a save and reads in text ("alice, 208,6,0").
#
# No RCON, no backup: the event is simply not acted on (client mode, or RCON
# down), and the file is only read when there is something to restore. Other
# events (Plugins::Feature) are inherited no-ops.
class PlayerBackup
  FILENAME = 'players-backup.json'
  # The quickbar-only file this feature started as; read once, so renaming it
  # on a live server does not throw away everybody's saved bars.
  LEGACY_FILENAME = 'quickbars.json'

  # `host` is the sniffer (Plugins hands every feature its owner): the two
  # things this one needs are on it, and either may be nil — no RCON, no
  # backup.
  def initialize(host)
    @rcon = host.rcon
    @player_db = host.player_db
    @mutex = Mutex.new # one join at a time + the file write (see #persist)
  end

  # A player changed their colour mid-session (the set_player_color action,
  # 4 UNORM bytes — see FactorioPacketTools#log_action). The game and the
  # save keep their own copy, so this is a snapshot like every other colour
  # here: it just keeps the file current between joins instead of at the next
  # one. The picker sends ~25 samples/second while it is open, so the
  # no-op-if-unchanged check in #note_color is load-bearing, not a nicety.
  def on_player_color(name, rgba)
    note_color(name, rgba)
  end

  # Startup (see FactorioPacketTools#on_start): ONE query for the whole
  # roster and a snapshot of everyone in it, joined or not. Without this the
  # file only ever learns about players who join AFTER we start — on a
  # long-running server that is nobody who played before us, and their bars
  # are exactly the ones a save change takes away. The roster goes through
  # helpers.write_file, so its size (a 300-player server × 100 slots) costs
  # nothing but disk.
  #
  # Same rules as the join path: an empty bar teaches us nothing (we keep
  # what we have — that is the whole point of this file), and a :failed read
  # (an offline player whose getter raises) is not an empty bar. The join
  # query still runs and still overwrites: it is the only source for a bar
  # edited mid-session, and it reads the same Lua this does, so a player in
  # both must come back identical.
  def on_start
    return unless @rcon
    roster = @rcon.roster_backup
    return if roster.nil? || roster.empty?
    bars = colors = 0
    @mutex.synchronize do
      roster.each do |p|
        name = p[:name].to_s
        next if name.empty?
        rec = (records[name] ||= {})
        color = p[:color]
        if color.is_a?(Array) && color.length == 4 && rec['color'] != color.map(&:to_f)
          rec['color'] = color.map(&:to_f)
          colors += 1
        end
        bar = p[:quickbar]
        next if bar == :failed # the getter raised: not an empty bar, nothing to save
        next unless filled?(bar) && rec['quickbar'] != copy(bar)
        rec['quickbar'] = copy(bar)
        bars += 1
      end
      persist if bars + colors > 0 # one write for the whole roster, not one per player
    end
    puts "[player-backup] roster snapshot: #{roster.size} players, #{bars} bar(s), #{colors} colour(s) saved"
  end

  # The event (see FactorioPacketTools#on_join_enriched). Runs on the join
  # thread, so the restore is a blocking RCON call on a thread that is there
  # for it.
  def on_join_enriched(name, index, attrs)
    return unless @rcon
    saved = saved_record(name) # read BEFORE we overwrite anything
    note_color(name, attrs[:color])
    # nil is the join query's "empty bar" (the payload always carries the
    # key); only :failed, the Lua read raising, means we do not know
    return if attrs[:quickbar] == :failed
    bar = attrs[:quickbar]
    if filled?(bar)
      save_quickbar(name, bar)
    elsif saved && filled?(saved['quickbar'])
      restore(name, index, saved['quickbar'])
    end
  end

  # Everything we keep for a name, or nil: {"quickbar" => …, "color" => […]}.
  def [](name)
    saved_record(name)
  end

  # The saved bar alone (what the quickbar side of this file is for).
  def saved_bar(name)
    saved_record(name)&.fetch('quickbar', nil)
  end

  private

  # ── the name-keyed file ───────────────────────────────────────────

  # One copy per field: the caller keeps editing what it handed us.
  def saved_record(name)
    return nil if name.to_s.empty?
    rec = @mutex.synchronize { records[name.to_s] }
    return nil unless rec.is_a?(Hash) # someone we have never seen (a copy of
                                      # {} would be truthy)
    rec.merge('quickbar' => rec['quickbar'] && copy(rec['quickbar']),
              'color' => rec['color'] && rec['color'].dup)
  end

  # The colour the join query reported. The game keeps its own copy (it is in
  # the save), so this is a snapshot, never a restore.
  def note_color(name, color)
    return unless color.is_a?(Array) && color.length == 4
    @mutex.synchronize do
      rec = (records[name.to_s] ||= {})
      return if rec['color'] == color.map(&:to_f) # unchanged: no write
      rec['color'] = color.map(&:to_f)
      persist
    end
  end

  def save_quickbar(name, bar)
    @mutex.synchronize do
      rec = (records[name.to_s] ||= {})
      rec['quickbar'] = copy(bar)
      persist
    end
  end

  # A copy of the stored grid: the caller keeps editing the one it handed us.
  def copy(grid)
    Array(grid).map { |slots| slots.is_a?(Array) ? slots.dup : slots }
  end

  def filled?(bar)
    Array(bar).flatten.compact.any?
  end

  # ── restore ──────────────────────────────────────────────────────

  def restore(name, index, bar)
    return unless filled?(bar)
    cells = cells_of(bar)
    done = @rcon.restore_quickbar(name, cells)
    if done == cells.size
      puts "[player-backup] #{name}: restored #{done} slot(s) from #{PlayerBackup::FILENAME}"
    else
      version = @rcon.server_version || 'unknown version'
      warn "[player-backup] #{name}: restored #{done}/#{cells.size} slot(s) — #{version} rejected the rest?"
    end
    @player_db&.replace_quickbar(index, bar) # the game now has it; so must the cache
  end

  # 10×10 grid → {flat slot index (1..100) => item id}, the form the setter
  # command takes.
  def cells_of(bar)
    cells = {}
    bar.each_with_index do |slots, page|
      Array(slots).each_with_index do |item, slot|
        cells[(page * PlayerDatabase::QUICKBAR_SLOTS) + slot + 1] = item if item
      end
    end
    cells
  end

  # ── state ────────────────────────────────────────────────────────

  def records
    @records ||= load_records
  end

  # Reads the current file, or — when it does not exist yet — the
  # quickbar-only file this feature used to be, so a rename on a live server
  # keeps every saved bar.
  def load_records
    out = {}
    [FILENAME, LEGACY_FILENAME].each do |file|
      next unless File.exist?(file)
      JSON.parse(File.read(file)).each do |name, rec|
        next unless rec.is_a?(Array) || rec.is_a?(Hash)
        rec = { 'quickbar' => rec } if rec.is_a?(Array) # the legacy shape
        out[name.to_s] = rec.select { |k, _v| k == 'quickbar' || k == 'color' }
      end
      break unless out.empty?
    end
    out
  rescue JSON::ParserError, SystemCallError
    {} # corrupt or unreadable: start empty, the next join with a bar refills it
  end

  # Assumes the mutex is held (called from #save). Same temp+rename as
  # players-cache.json: a crash mid-write must not leave a file that would
  # then be read back as "this player's bar is empty".
  def persist
    path = FILENAME
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(records))
    File.rename(tmp, path)
  rescue StandardError => e
    warn "#{FILENAME} save failed: #{e.class}: #{e.message}"
  end
end
