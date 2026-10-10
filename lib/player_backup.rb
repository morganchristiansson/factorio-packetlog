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
#   online_time  ticks played on EARLIER saves — the base added to the live
#                total (see #sync_times)
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
# The COLOUR: the current save carries its own copy (four f32s in front of
# the player's name — docs/save/level-dat.md), so mid-session it only needs
# snapshotting (they can re-pick it any time — the set_player_color action,
# ~25 samples/second while the picker is open, hence the no-op-if-unchanged
# check). But a NEW save has no copy: the player is handed a palette colour
# by index. `LuaPlayer.color` is writable, so #restore puts ours back with
# the bar, in the same one RCON command.
#
# No RCON, no backup: the event is simply not acted on (client mode, or RCON
# down), and the file is only read when there is something to restore. Other
# events (Plugins::Feature) are inherited no-ops.
class PlayerBackup
  FILENAME = 'players-backup.json'
  # Every key one record may carry. Anything else in the file is dropped on
  # read, so a typo'd field cannot masquerade as data.
  FIELDS = %w[quickbar color online_time online_time_seen].freeze

  # `host` is the sniffer (Plugins hands every feature its owner): the two
  # things this one needs are on it, and either may be nil — no RCON, no
  # backup.
  #
  # `path:` is the same dependency injection every other file-backed class
  # here takes (PlayerDatabase.new(path), MemoryStore.new(dir)): the file to
  # keep is a CONSTRUCTOR argument, not a baked-in constant, so a caller (a
  # test, or two features with two files) names its own instead of the whole
  # process chdir'ing into a scratch directory to get out of the way.
  def initialize(host, path: FILENAME)
    @rcon = host.rcon
    @player_db = host.player_db
    @player_attrs = host.respond_to?(:attrs) ? host.attrs : nil
    @path = path
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
    times = []
    @mutex.synchronize do
      roster.each do |p|
        name = p[:name].to_s
        next if name.empty?
        times << [name, p[:online_time]] # o= in the roster Lua — the live total
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
    # outside the lock (sync_times takes it) — one write for the roster
    sync_times(times)
    puts "[player-backup] roster snapshot: #{roster.size} players, #{bars} bar(s), #{colors} colour(s) saved"
  end

  # The event (see FactorioPacketTools#on_join_enriched). Runs on the join
  # thread, so the restore is a blocking RCON call on a thread that is there
  # for it.
  def on_join_enriched(name, index, attrs)
    return unless @rcon
    saved = saved_record(name) # read BEFORE we overwrite anything
    # Play time first, before any :failed return below: it is independent of
    # the bar. A name in the returned list is a save change (see #sync_times).
    new_save = sync_times([[name, attrs[:online_time]]]).include?(name.to_s)
    # A save change hands the player the game's DEFAULTS: a starting
    # quickbar and a palette colour. Both are perfectly valid values, so
    # neither the "empty bar" rule below nor a snapshot can tell them apart
    # from state the player chose — snapshotting here would overwrite the
    # backup with the defaults, and restoring them later would be restoring
    # the defaults forever. The play-time clock is the one thing that knows,
    # so it gates the restore, and the snapshot is skipped: what we put back
    # is what the game ends up holding, so the file and the game still agree.
    return if new_save && restore(name, index, saved)
    note_color(name, attrs[:color])
    # nil is the join query's "empty bar" (the payload always carries the
    # key); only :failed, the Lua read raising, means we do not know
    return if attrs[:quickbar] == :failed
    bar = attrs[:quickbar]
    if filled?(bar)
      save_quickbar(name, bar)
    elsif saved && filled?(saved['quickbar'])
      restore(name, index, saved)
    end
  end

  # Player LEFT the game (clean quit in either direction, or the heartbeat
  # watchdog) — the live total is already folded into PlayerAttrs, last
  # chance to record what this save is worth.
  #
  # The sniffer hands us PlayerAttrs' FULL total: this-save ticks PLUS the
  # earlier-saves base that PlayerBackup itself keeps and PlayerAttrs adds
  # back on read. But `seen` tracks the GAME's own p.online_time — this-save
  # only — so a drop under `seen` means the save restarted, not the base
  # inflating the mirror. Stripping the base is what makes the leave value a
  # this-save lower bound again (the assumption sync_times relies on):
  # without it, a leave+rejoin of the SAME save looks like a drop (the base
  # lifts `seen` past what the game reports) and the player's bar and colour
  # get restored on every reconnect instead of only on the first join of a
  # new save.
  def on_player_left(name, online_time_ticks)
    this_save = online_time_ticks.to_i - base_ticks(name)
    sync_times([[name, this_save]], exact: false)
  end

  # Fold the game's live play times (name → ticks; a whole roster is fine)
  # into the stored high-water mark. A live total that DROPPED means the
  # save's own clock restarted — a new save, a new map — and everything the
  # old save had that this one hasn't yet becomes a base, added to the live
  # total on read (PlayerAttrs#online_time_ticks). The game cannot be told
  # about a base: LuaPlayer.online_time is read-only, which is the whole
  # reason this file exists. Same name-keyed accumulator the Biter Battles
  # scenario keeps in its `session` global (utils/datastore/session_data.lua)
  # with their web panel in the middle; we are the panel.
  #
  # WHY a drop, and whose: the game's own `p.online_time` cannot fall inside one
  # save — it only accumulates while the player is connected — so a drop in
  # an EXACT number (roster snapshot, join query; both read it over RCON)
  # means the save's clock restarted, and everything the old save had that
  # this one hasn't yet becomes a base. Our own mirror (PlayerAttrs, what a
  # leave reports) is NOT exact: a player we never seeded from RCON has a
  # base of 0 there, so it undercounts, and treating ITS drop as a reset
  # would invent play time. Hence `exact: false` — a mirror number may push
  # the mark up (it can only know more, never less) but never lower it, so
  # every reset is read off the game. Wrong direction by design: a missed
  # reset loses time, a false one invents it.
  #
  # Within one save the mark only rises, so nothing is written on every sync:
  # a roster snapshot of 300 players is one file write, and a re-sync with
  # unchanged numbers is none.
  # the file carries). Returns the names whose clock RESTARTED at this sync
  # (empty on a normal one) — a join that sees its own name in the list knows
  # the game just handed it the defaults of a new save.
  def sync_times(pairs, exact: true)
    bases = {}
    resets = []
    @mutex.synchronize do
      changed = false
      pairs.each do |name, live|
        name = name.to_s
        next if name.empty?
        live = live.to_i
        rec = (records[name] ||= {})
        seen = rec['online_time_seen']
        dropped = seen && live < seen.to_i && exact
        base = rec['online_time'].to_i + (dropped ? seen.to_i - live : 0)
        bases[name] = base
        resets << name if dropped
        next if seen == live || (seen && !exact && live <= seen.to_i)
        rec['online_time'] = base
        rec['online_time_seen'] = live
        changed = true
      end
      persist if changed # one write for the whole batch, not one per player
    end
    @player_attrs&.set_foreign_bases(bases) unless bases.empty?
    resets
  end

  # The base (ticks from earlier saves) alone — what the online_time total is
  # this much bigger than the save's own.
  def base_ticks(name)
    @mutex.synchronize { (records[name.to_s] || {})['online_time'].to_i }
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

  # Put back everything we saved, in ONE RCON command (RconClient#
  # restore_player): the quickbar cells and the colour, each only if we have
  # it. True when something was written. Called for a player joining a NEW
  # save (the game's defaults are not what they chose) and for one joining
  # with an empty bar.
  def restore(name, index, saved)
    return false unless saved.is_a?(Hash)
    bar = filled?(saved['quickbar']) ? saved['quickbar'] : nil
    color = saved['color'].is_a?(Array) && saved['color'].length == 4 ? saved['color'] : nil
    return false unless bar || color
    cells = cells_of(bar || [])
    done = @rcon.restore_player(name, cells, color: color)
    if bar
      if done == cells.size
        puts "[player-backup] #{name}: restored #{done} slot(s) from #{PlayerBackup::FILENAME}"
      else
        version = @rcon.server_version || 'unknown version'
        warn "[player-backup] #{name}: restored #{done}/#{cells.size} slot(s) — #{version} rejected the rest?"
      end
    end
    puts "[player-backup] #{name}: restored colour #{Array(color).join(',')}" if color
    # the game now holds it; so must the cache
    @player_db&.replace_quickbar(index, bar) if bar
    @player_db[index] = { color: color } if color && @player_db
    true
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

  # Reads the current file. Unreadable or corrupt: start empty, the next join
  # with a bar refills it. There is NO copy of this file: it is the one
  # artifact here that cannot be rebuilt from anywhere else, so copy it by
  # hand (`cp players-backup.json{,.bak}`) when starting a new save.
  def load_records
    return {} unless File.exist?(@path)
    JSON.parse(File.read(@path)).each_with_object({}) do |(name, rec), out|
      next unless rec.is_a?(Hash)
      out[name.to_s] = rec.select { |k, _v| FIELDS.include?(k) }
    end
  rescue JSON::ParserError, SystemCallError
    {}
  end

  # Assumes the mutex is held (called from #save). Same temp+rename as
  # players-cache.json: a crash mid-write must not leave a file that would
  # then be read back as "this player's bar is empty".
  def persist
    path = @path
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(records))
    File.rename(tmp, path)
  rescue StandardError => e
    warn "#{@path} save failed: #{e.class}: #{e.message}"
  end
end
