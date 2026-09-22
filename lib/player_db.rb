# frozen_string_literal: true

require 'json'

# Player ID -> info mapping, persisted to a JSON file.
# IDs are 1-indexed game player indexes (parser converts from the
# 0-indexed wire protocol at decode time). Persists across restarts and
# hot reloads via the JSON file.
#
# TWO files, both managed here:
#
#   players-cache.json     {id: {name: "<name>", locale: "<locale>", admin: <bool>}}
#       The game-index -> identity cache. ONLY valid for a single server +
#       savefile: ids are handed out in join order and reused across
#       sessions, so this file is never authoritative across worlds.
#       HARDCCODED: the path is not overridable (config surface policy —
#       the data is re-seeded from RCON anyway, so a knob buys nothing).
#       Pass nil to PlayerDatabase.new for an in-memory DB (tests/pcap).
#
#   players-locale.json    {"<name>": ["en", "pt"], ...}
#       Per-player LANGUAGE OVERRIDES, keyed by NAME (stable across
#       sessions). A player's effective readable languages = their Factorio
#       locale plus these. Players like KrlosUltimate (pt-BR interface, but
#       actually English) get an entry here so the translation agent stops
#       translating for them. Set via the /locales console command — and by
#       the agent itself once players can self-set locales.
#
# Locale is a property of the account, not the current game session index.
#
# THREAD SAFETY: one mutex serializes hash MUTATION + the temp+rename disk
# write, because both hashes are written from several threads:
#   @players    capture thread (add / remove_other_entries_for on joins),
#               translation-agent event worker (set_locale_by_id via
#               note_joined), main thread (load_roster, --map-player).
#               Without the lock, an @players.each (rebuild_index /
#               remove_other_entries_for) racing a concurrent key-add
#               raises "can't add a new key into hash during iteration",
#               and two concurrent saves race on the same .tmp file.
#   @overrides  stdin thread (set_locale_overrides) today; the agent will
#               write it too once players self-set locales — same lock.
# Single-key READS (lookup / id_for / get_locale / locale_overrides)
# are lock-free: they're atomic under the GVL.
class PlayerDatabase
  DEFAULT_CACHE_BASENAME = 'players-cache.json'
  DEFAULT_LOCALES_BASENAME = 'players-locale.json'

  attr_reader :players

  def initialize(path = nil)
    @path = path
    @locales_path = derive_path(path, DEFAULT_LOCALES_BASENAME)
    @mutex = Mutex.new  # hash mutations + disk writes (see header)
    @players = {}  # id -> {name:, locale:, admin:}
    @id_by_name = {}  # name -> id
    @overrides = {}  # name -> [lang, ...]
    # load runs at construction (single thread, before any capture/agent
    # threads exist) — no lock needed.
    load if @path && File.exist?(@path)
    load_overrides
  end

  def lookup(id)
    p = @players[id]
    p ? p[:name] : "Player_#{id}"
  end

  # Names are forced to UTF-8 + scrubbed on Entry: packet-derived names can
  # still carry a binary encoding tag with non-ASCII bytes (hot-reload state
  # written by an older build, or a decode path that missed the scrub), and a
  # binary name makes JSON.pretty_generate in #save raise JSON::GeneratorError
  # — killing Ctrl-C shutdown/reload. Sanitizing here keeps the DB self-
  # healing regardless of caller.
  # Persist immediately when a player mapping actually changes (new id
  # or name change), so the cache survives a crash/kill mid-session —
  # previously the mapping was only saved on quit/reload (FactorioSniffer
  # #finish / Ctrl-C), losing every player learned after the last save.
  # Record accessors. Index (Numeric) or name (String) keys both work.
  # `[]` reads; `[]=` merges into the existing record (or creates one)
  # and persists immediately. Admin lives here (players-cache.json).
  def [](key)
    id = id_for(key)
    @players[id]
  end

  def []=(key, record)
    id = id_for(key)
    return unless id
    @mutex.synchronize do
      rec = (record || {}).dup
      rec[:name] = clean(rec[:name]) if rec.key?(:name)
      @players[id] = (@players[id] || {}).merge(rec)
      @id_by_name[@players[id][:name]] = id if @players[id][:name]
      persist
    end
  end

  def id_for(key)
    return nil if key.nil?
    key.is_a?(Numeric) ? key.to_i : @id_by_name[clean(key)]
  end

  # Remove all entries for a name except the given id (used when the
  # true game index is learned and may override peer-id-based guesses).
  # Saves when anything was actually deleted (the correction is
  # immediately persisted too).
  def remove_other_entries_for(name, keep_id)
    name = clean(name)
    return if name.nil?
    @mutex.synchronize do
      changed = false
      @players.each do |id, info|
        if info[:name] == name && id != keep_id.to_i
          @players.delete(id)
          changed = true
        end
      end
      kept = @players[keep_id.to_i]
      if kept
        admin = @players.values.find { |p| p[:name] == name }&.dig(:admin)
        if admin != kept[:admin]
          kept[:admin] = admin
          changed = true
        end
      end
      rebuild_index
      persist if changed
    end
  end

  # Store a player's locale (e.g., "pt-BR", "en", "zh-CN").
  # Keyed by ID since that's what we have from the action.
  def set_locale_by_id(id, locale)
    id = id.to_i
    locale = locale.to_s.strip
    return if locale.empty?
    @mutex.synchronize do
      p = @players[id]
      next unless p
      next if p[:locale] == locale
      p[:locale] = locale
      persist
    end
  end

  # Get a player's stored locale by ID, or nil if unknown
  def get_locale(id)
    p = @players[id.to_i]
    p ? p[:locale] : nil
  end

  # ── Language overrides (players-locale.json, keyed by NAME) ────────

  # Override a player's FACTORIO locale with extra languages they read
  # without translation (e.g. ["en"] for a pt-BR-interface player who
  # actually writes English). Empty/nil clears the entry. Languages are
  # normalized to short base codes ("pt-BR" -> "pt"). Persisted atomically.
  def set_locale_overrides(name, langs)
    name = clean(name)
    return if name.nil?
    @mutex.synchronize do
      langs = normalize_langs(langs)
      if langs.empty?
        next unless @overrides.key?(name)
        @overrides.delete(name)
      else
        next if @overrides[name] == langs
        @overrides[name] = langs
      end
      persist_overrides
    end
  end

  # A player's stored language overrides (array of base codes) or nil.
  def locale_overrides(name)
    @overrides[clean(name)]
  end

  # All overrides as {name -> [langs]} (for the /locales console list).
  def all_locale_overrides
    @mutex.synchronize { @overrides.dup }
  end

  # Explicit flush (finish / reload / --map-player). The mutators above
  # persist eagerly on their own; this covers callers that only flush.
  def save
    @mutex.synchronize { persist }
  end

  private

  def derive_path(path, basename)
    return nil if path.nil?
    File.join(File.dirname(File.expand_path(path)), basename)
  end

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

  # "pt-BR" -> "pt"; nil/garbage -> "". The rest of the codebase compares
  # locales by base language exactly like this.
  def base_lang(lang)
    lang.to_s.split('-').first&.downcase&.strip || ''
  end

  def normalize_langs(langs)
    Array(langs).filter_map { |l|
      b = base_lang(l)
      b.empty? ? nil : b
    }.uniq
  end

  def load
    raw = JSON.parse(File.read(@path))
    @players = raw.each_with_object({}) { |(k, v), h|
      next unless k =~ /^\d+$/
      next unless v.respond_to?(:key?)
      admin = if v.key?('admin')
        v['admin']
      elsif v.key?(:admin)
        v[:admin]
      else
        nil
      end
      h[k.to_i] = {name: v['name'] || v[:name], locale: v['locale'] || v[:locale], admin: admin}
    }
    rebuild_index
  rescue JSON::ParserError, TypeError, NoMethodError, Errno::ENOENT
    # Invalid/corrupt format — start fresh, will be repopulated from RCON
    @players = {}
    @id_by_name = {}
  end

  # Assumes the mutex is held (called from the public mutators / #save).
  # Defensive sanitize: never let a legacy binary-flagged name (from
  # reloaded state) poison the write. Capture learns names while the
  # translation worker learns locales — the mutex serializes the snapshot
  # + the temp+rename below.
  def persist
    return unless @path
    safe = @players.dup.transform_values { |p|
      {name: clean(p[:name]), locale: p[:locale], admin: p.key?(:admin) ? p[:admin] : nil}
    }
    tmp = "#{@path}.tmp"
    File.write(tmp, JSON.pretty_generate(safe))
    File.rename(tmp, @path)
  rescue StandardError => e
    warn "players-cache.json save failed: #{e.class}: #{e.message}"
  end

  def persist_overrides
    return unless @locales_path
    safe = {}
    @overrides.each { |n, langs| safe[clean(n)] = langs if n && !langs.empty? }
    tmp = "#{@locales_path}.tmp"
    File.write(tmp, JSON.pretty_generate(safe))
    File.rename(tmp, @locales_path)
  rescue StandardError => e
    warn "players-locale.json save failed: #{e.class}: #{e.message}"
  end

  def load_overrides
    return unless @locales_path && File.exist?(@locales_path)
    raw = JSON.parse(File.read(@locales_path))
    @overrides = raw.each_with_object({}) { |(k, v), h|
      k = clean(k)
      next unless k
      langs = normalize_langs(v)
      h[k] = langs unless langs.empty?
    }
  rescue JSON::ParserError, TypeError
    @overrides = {}
  end
end