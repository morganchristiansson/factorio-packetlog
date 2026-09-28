# frozen_string_literal: true

require 'json'

# Quickbar backup — the file is lib/quickbar_backup.rb, the module takes its
# CamelCase name, and it is listed in config.yaml `plugins:`. Nothing in the
# sniffer names it: Plugins.apply_mixins mixes it in, and it hooks the
# `on_join_enriched` seam.
#
# What it keeps: a copy of every player's quickbar keyed by NAME, in
# `quickbars.json` next to the process cwd (same convention as
# players-cache.json, and no configuration of its own).
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
# No RCON, no backup: the seam is a no-op when the client is missing (client
# mode, or RCON down), and the file is only read when something is actually
# restored — a backup that cannot restore must not look like it works.
module QuickbarBackup
  FILENAME = 'quickbars.json'

  private

  # The seam (see FactorioPacketTools::Defaults). Runs on the join thread, so
  # the restore below is a blocking RCON call on a thread that exists for it.
  def on_join_enriched(name, index, attrs)
    # nil is the join query's "empty bar" (it always carries the key; only
    # :failed, the Lua read raising, means we do not know)
    return if attrs[:quickbar] == :failed
    bar = attrs[:quickbar]
    saved = quickbar_saved_bar(name)
    if quickbar_bar?(bar)
      quickbar_save_bar(name, bar)
    elsif saved
      quickbar_restore(name, index, saved)
    end
  end

  def quickbar_backup_enabled? = !@rcon.nil?

  # ── the name-keyed file ───────────────────────────────────────────

  def quickbar_saved_bar(name)
    return nil unless quickbar_backup_enabled?
    bar = quickbar_mutex.synchronize { quickbar_bars[name] }
    bar && deep_copy(bar) # nil for someone we have never seen (deep_copy of
                          # nil would be [], and [] is truthy)
  end

  def quickbar_save_bar(name, bar)
    quickbar_mutex.synchronize do
      quickbar_bars[name] = deep_copy(bar)
      quickbar_persist
    end
  end

  # A copy of the stored grid: the caller keeps editing the one it handed us.
  def deep_copy(grid)
    Array(grid).map { |slots| slots.is_a?(Array) ? slots.dup : slots }
  end

  def quickbar_bar?(bar)
    Array(bar).flatten.compact.any?
  end

  # ── restore ──────────────────────────────────────────────────────

  def quickbar_restore(name, index, bar)
    return unless quickbar_bar?(bar)
    cells = quickbar_cells(bar)
    done = @rcon.restore_quickbar(name, cells)
    if done == cells.size
      puts "[quickbar] #{name}: restored #{done} slot(s) from #{QuickbarBackup::FILENAME}"
    else
      version = @rcon.server_version || 'unknown version'
      warn "[quickbar] #{name}: restored #{done}/#{cells.size} slot(s) — #{version} rejected the rest?"
    end
    @player_db.replace_quickbar(index, bar) # the game now has it; so must the cache
  end

  # 10×10 grid → {flat slot index (1..100) => item id}, the form the setter
  # command takes.
  def quickbar_cells(bar)
    cells = {}
    bar.each_with_index do |slots, page|
      Array(slots).each_with_index do |item, slot|
        cells[(page * PlayerDatabase::QUICKBAR_SLOTS) + slot + 1] = item if item
      end
    end
    cells
  end

  # ── state ────────────────────────────────────────────────────────

  def quickbar_mutex
    @quickbar_mutex ||= Mutex.new # one join at a time + the file write
  end

  def quickbar_bars
    @quickbar_bars ||= quickbar_load
  end

  def quickbar_load
    path = QuickbarBackup::FILENAME
    return {} unless File.exist?(path)
    raw = JSON.parse(File.read(path))
    raw.each_with_object({}) { |(name, bar), h| h[name.to_s] = bar if bar.is_a?(Array) }
  rescue JSON::ParserError, SystemCallError
    {} # corrupt or unreadable: start empty, the next join with a bar refills it
  end

  # Assumes the mutex is held (called from #quickbar_save_bar). Same
  # temp+rename as players-cache.json: a crash mid-write must not leave a file
  # that would then be read back as "this player's bar is empty".
  def quickbar_persist
    path = QuickbarBackup::FILENAME
    tmp = "#{path}.tmp"
    File.write(tmp, JSON.pretty_generate(quickbar_bars))
    File.rename(tmp, path)
  rescue StandardError => e
    warn "#{QuickbarBackup::FILENAME} save failed: #{e.class}: #{e.message}"
  end
end
