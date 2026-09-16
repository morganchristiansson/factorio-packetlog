# frozen_string_literal: true

require 'json'

# Player ID -> info mapping, persisted to a JSON file.
# IDs are 1-indexed game player indexes (protocol values are 0-indexed;
# add +1 when decoding). Persists across restarts and hot reloads via the
# JSON file.
#
# Format: {id: {name: "<name>", locale: "<locale>"}}
# Locale is a property of the account, not the current game session index.
class PlayerDatabase
  attr_reader :players

  def initialize(path = nil)
    @path = path
    @players = {}  # id -> {name:, locale:}
    @id_by_name = {}  # name -> id
    load if @path && File.exist?(@path)
  end

  def lookup(id)
    p = @players[id]
    p ? p[:name] : "Player_#{id}"
  end

  def lookup_info(id)
    @players[id] || {name: "Player_#{id}", locale: nil}
  end

  # Names are forced to UTF-8 + scrubbed on Entry: packet-derived names can
  # still carry a binary encoding tag with non-ASCII bytes (hot-reload state
  # written by an older build, or a decode path that missed the scrub), and a
  # binary name makes JSON.pretty_generate in #save raise JSON::GeneratorError
  # — killing Ctrl-C shutdown/reload. Sanitizing here keeps the DB self-
  # healing regardless of caller.
  # Persist immediately when a player mapping actually changes (new id
  # or name change), so players.json survives a crash/kill mid-session —
  # previously the mapping was only saved on quit/reload (FactorioSniffer
  # #finish / Ctrl-C), losing every player learned after the last save.
  # Called from every join path: roster load, connection accept,
  # NewPeerInfo, C→S heartbeat index binding, self-confirm. Identical
  # re-adds are no-ops (skip the disk write).
  def add(id, name, locale: nil)
    name = clean(name)
    return if name.nil? || name.empty?
    id = id.to_i
    existing = @players[id]
    return if existing && existing[:name] == name && existing[:locale] == locale
    @players[id] = {name: name, locale: locale}
    @id_by_name[name] = id
    save
  end

  def name_to_id(name)
    @id_by_name[name]
  end

  # Remove all entries for a name except the given id (used when the
  # true game index is learned and may override peer-id-based guesses).
  # Saves when anything was actually deleted (the correction is
  # immediately persisted too).
  def remove_other_entries_for(name, keep_id)
    name = clean(name)
    return if name.nil?
    changed = false
    @players.each do |id, info|
      if info[:name] == name && id != keep_id.to_i
        @players.delete(id)
        changed = true
      end
    end
    rebuild_index
    save if changed
  end

  # Store a player's locale (e.g., "pt-BR", "en", "zh-CN").
  # Keyed by ID since that's what we have from the action.
  def set_locale_by_id(id, locale)
    id = id.to_i
    locale = locale.to_s.strip
    return if locale.empty?
    p = @players[id]
    return unless p
    return if p[:locale] == locale
    p[:locale] = locale
    save
  end

  # Get a player's stored locale by ID, or nil if unknown
  def get_locale(id)
    p = @players[id.to_i]
    p ? p[:locale] : nil
  end

  # All known locales (for debugging)
  def all_locales
    @players.transform_values { |p| p[:locale] }.compact
  end

  def save
    return unless @path
    # Defensive sanitize: never let a legacy binary-flagged name (from
    # reloaded state) poison the write.
    safe = @players.transform_values { |p| {name: clean(p[:name]), locale: p[:locale]} }
    # Atomic write (tmp + rename): players.json is now written on every
    # join, so a crash mid-write must not be able to truncate/corrupt it.
    tmp = "#{@path}.tmp"
    File.write(tmp, JSON.pretty_generate(safe))
    File.rename(tmp, @path)
  rescue StandardError => e
    warn "players.json save failed: #{e.class}: #{e.message}"
  end

  private

  # scrub('?') guards against invalid UTF-8 (strip/regex on malformed bytes
  # raises ArgumentError). Force UTF-8 FIRST so binary-flagged strings are
  # cleaned too (a "valid" byte sequence under BINARY is garbage under UTF-8).
  def clean(name)
    return nil if name.nil?
    name.to_s.dup.force_encoding('UTF-8').scrub('?').strip
  end

  def rebuild_index
    @id_by_name = {}
    @players.each { |id, info| @id_by_name[info[:name]] = id }
  end

  def load
    raw = JSON.parse(File.read(@path))
    @players = raw.each_with_object({}) { |(k, v), h|
      next unless k =~ /^\d+$/
      h[k.to_i] = {name: v['name'] || v[:name], locale: v['locale'] || v[:locale]}
    }
    rebuild_index
  rescue JSON::ParserError, TypeError
    # Invalid/corrupt format — start fresh, will be repopulated from RCON
    @players = {}
    @id_by_name = {}
  end
end
