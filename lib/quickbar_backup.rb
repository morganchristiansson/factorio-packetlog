# frozen_string_literal: true

require 'json'

# Quickbar backup — the file is lib/quickbar_backup.rb, the class takes its
# CamelCase name, and it is listed in config.yaml `plugins:`. Nothing in the
# sniffer names it: Plugins.features builds every listed class and pushes
# `on_join_enriched` at the ones that implement it.
#
# What it keeps: a copy of every player's quickbar keyed by NAME, in
# `quickbars.json` next to the process cwd (the players-cache.json
# convention, and no configuration of its own).
#
# WHY a side file, keyed by name: players-cache.json's 10×10 quickbar is
# per-savefile — game indexes are handed out in join order and reset when the
# save does, so index 42 on a new map is a different person. A name is the
# only thing that survives the save, so this file's lifetime is longer than
# any single save's.
#
# WHEN: on a confirmed join, from the ONE RCON query the sniffer already makes
# for the joiner (see RconClient#player_attributes_for, which reads the whole
# bar). Their in-game bar is the truth:
#   * they have one  → snapshot it, which is also how a player who edited
#     their bar mid-session gets the new one saved;
#   * they have none but we do → write it back over RCON, then bring the
#     in-memory cache in line with the game.
#
# No RCON, no backup: the event is simply not acted on (client mode, or RCON
# down), and the file is only read when there is something to restore. Other
# events (Plugins::Feature) are inherited no-ops.
class QuickbarBackup
  FILENAME = 'quickbars.json'

  # `host` is the sniffer (Plugins hands every feature its owner): the two
  # things this one needs are on it, and either may be nil — no RCON, no
  # backup.
  def initialize(host)
    @rcon = host.rcon
    @player_db = host.player_db
    @mutex = Mutex.new # one join at a time + the file write (see #persist)
  end

  # The event (see FactorioPacketTools#on_join_enriched). Runs on the join
  # thread, so the restore is a blocking RCON call on a thread that is there
  # for it.
  def on_join_enriched(name, index, attrs)
    return unless @rcon
    # nil is the join query's "empty bar" (the payload always carries the
    # key); only :failed, the Lua read raising, means we do not know
    return if attrs[:quickbar] == :failed
    bar = attrs[:quickbar]
    saved = saved_bar(name)
    if filled?(bar)
      save(name, bar)
    elsif saved
      restore(name, index, saved)
    end
  end

  # The saved bar for a name, or nil.
  def [](name)
    saved_bar(name)
  end

  private

  # ── the name-keyed file ───────────────────────────────────────────

  def saved_bar(name)
    return nil if name.to_s.empty?
    bar = @mutex.synchronize { bars[name] }
    bar && copy(bar) # nil for someone we have never seen (copy of nil would
                     # be [], and [] is truthy)
  end

  def save(name, bar)
    @mutex.synchronize do
      bars[name] = copy(bar)
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
      puts "[quickbar] #{name}: restored #{done} slot(s) from #{QuickbarBackup::FILENAME}"
    else
      version = @rcon.server_version || 'unknown version'
      warn "[quickbar] #{name}: restored #{done}/#{cells.size} slot(s) — #{version} rejected the rest?"
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

  def bars
    @bars ||= load_bars
  end

  def load_bars
    return {} unless File.exist?(QuickbarBackup::FILENAME)
    raw = JSON.parse(File.read(QuickbarBackup::FILENAME))
    raw.each_with_object({}) { |(name, bar), h| h[name.to_s] = bar if bar.is_a?(Array) }
  rescue JSON::ParserError, SystemCallError
    {} # corrupt or unreadable: start empty, the next join with a bar refills it
  end

  # Assumes the mutex is held (called from #save). Same temp+rename as
  # players-cache.json: a crash mid-write must not leave a file that would
  # then be read back as "this player's bar is empty".
  def persist
    path = QuickbarBackup::FILENAME
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(bars))
    File.rename(tmp, path)
  rescue StandardError => e
    warn "#{QuickbarBackup::FILENAME} save failed: #{e.class}: #{e.message}"
  end
end
