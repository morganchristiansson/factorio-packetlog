# frozen_string_literal: true

require 'json'

# Player ID -> info mapping, persisted to a JSON file.
# IDs are 1-indexed game player indexes (parser converts from the
# 0-indexed wire protocol at decode time). Persists across restarts and
# hot reloads via the JSON file.
#
# TWO files, both managed here:
#
#   players-cache.json     {id: {name:, locale:, admin:, quickbar:, quickbar_page:}}
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
#   @players    capture thread (add / remove_other_entries_for on joins,
#               set_quickbar_slot on quickbar events), the join-enrichment
#               thread (set_locale_by_id / replace_quickbar), main thread
#               (load_roster, --map-player).
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
  # Slots in a quickbar row and rows in a quickbar (game constants behind
  # `LuaPlayer.set_quick_bar_slot`'s slot_index / page_index). The wire bytes
  # are bounds-checked against them, so a desynced parse can neither store
  # nor invent a slot or page outside the quickbar.
  QUICKBAR_SLOTS = 10
  QUICKBAR_PAGES = 10

  attr_reader :players

  def initialize(path = nil)
    @path = path
    @locales_path = derive_path(path, DEFAULT_LOCALES_BASENAME)
    @mutex = Mutex.new  # hash mutations + disk writes (see header)
    @players = {}  # id -> {name:, locale:, admin:, quickbar:, quickbar_page:}
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
  # binary name makes JSON.pretty_generate during persistence raise JSON::GeneratorError
  # — killing Ctrl-C shutdown/reload. Sanitizing here keeps the DB self-
  # healing regardless of caller.
  # Persist immediately when a player mapping changes, so the cache survives
  # a crash/kill mid-session.
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

  # ── Quickbar (players-cache.json, in the player record) ───────────
  #
  #   "quickbar": [[10 item ids or nulls] x 10]
  #       The player's quickbar as the WIRE reports it: QUICKBAR_PAGES fixed
  #       pages, each a QUICKBAR_SLOTS array indexed by slot, value = item
  #       prototype id, null = empty slot / no data for that page. Fed by the
  #       sniffer from the quickbar input actions
  #       (FactorioProtocol::QuickBar); page 0 is the default. Rebuilt from
  #       the capture stream, so it is only as good as the packets seen: a
  #       player who had slots set before the first capture shows nulls there.
  #   "quickbar_page": <page>
  #       The page the player last switched to.
  #
  # Same mutex as the rest of the record (see the header): quickbar events
  # arrive on the capture thread, roster/join writes on the main thread.
  def quickbar_page(id)
    @players.dig(id.to_i, :quickbar_page) || 0
  end

  # Set (item id) or clear (nil) one quickbar slot on the given page. Saves
  # when the slot's content actually changed, so a page nobody ever filled
  # (or emptied again) stays null.
  #
  # Returns FALSE when the page/slot falls outside the quickbar — a slot
  # byte that big cannot be real, it means an earlier action's length
  # desynced the closure — and the caller uses that to hand the frame to the
  # unknown-packet writer. Anything else (including an unknown player, which
  # the packet-level roster check already flags) returns true.
  def set_quickbar_slot(id, page, slot, item)
    page = page.to_i
    slot = slot.to_i
    return false unless page.between?(0, QUICKBAR_PAGES - 1) && slot.between?(0, QUICKBAR_SLOTS - 1)
    @mutex.synchronize do
      rec = @players[id.to_i]
      next true unless rec
      qb = rec[:quickbar]
      slots = qb&.[](page)
      if item.nil?
        next true unless slots && slots[slot]
      else
        next true if slots && slots[slot] == item
      end
      qb ||= (rec[:quickbar] = Array.new(QUICKBAR_PAGES))
      slots = (qb[page] ||= Array.new(QUICKBAR_SLOTS))
      if item.nil?
        slots[slot] = nil
        qb[page] = nil if slots.all?(&:nil?)
      else
        slots[slot] = item
      end
      persist
      true
    end
  end

  # The page the player switched to (quick_bar_set_selected_page /
  # change_active_quick_bar). Saves when it changed. False when the page is
  # outside the quickbar (desync) — see #set_quickbar_slot.
  def set_quickbar_page(id, page)
    page = page.to_i
    return false unless page.between?(0, QUICKBAR_PAGES - 1)
    @mutex.synchronize do
      rec = @players[id.to_i]
      next true unless rec
      next true if rec[:quickbar_page] == page
      rec[:quickbar_page] = page
      persist
      true
    end
  end

  # Replace a player's whole quickbar from an AUTHORITATIVE source (the RCON
  # read on join). The grid is complete, so it overwrites what the packet
  # stream had inferred; a nil grid (an empty bar) clears the record.
  def replace_quickbar(id, pages)
    return unless pages.is_a?(Array) && pages.size == QUICKBAR_PAGES
    @mutex.synchronize do
      rec = @players[id.to_i]
      next unless rec
      next if rec[:quickbar] == pages
      rec[:quickbar] = pages
      persist
    end
  end

  # Parse the quickbar payload of the join-time attrs query into the 10×10
  # array shape, or nil when there is nothing in it. The payload is keyed by
  # the game's FLAT slot index (see RconClient#player_attrs_for_lua), which
  # the API defines as 1..10 = page one, 11..20 = page two, … — so the fold
  # into page/slot lives here, where it is testable, instead of inside a Lua
  # string. Entries outside 1..100 and non-numeric keys are dropped.
  def self.parse_quickbar(payload)
    return nil unless payload.is_a?(Hash)
    pages = Array.new(QUICKBAR_PAGES) # nil = a page with nothing in it
    payload.each do |key, id|
      # Integer(.., exception: false) so a malformed key is nil, not a raise
      i = Integer(key, exception: false)
      next unless i&.between?(1, QUICKBAR_PAGES * QUICKBAR_SLOTS)
      page = (i - 1) / QUICKBAR_SLOTS
      (pages[page] ||= Array.new(QUICKBAR_SLOTS))[(i - 1) % QUICKBAR_SLOTS] = id.to_i
    end
    pages.compact.empty? ? nil : pages
  end

  # A player's quickbar (QUICKBAR_PAGES pages of QUICKBAR_SLOTS item ids),
  # or nil if never seen.
  def quickbar(id)
    @players.dig(id.to_i, :quickbar)
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
      rec = {name: v['name'] || v[:name], locale: v['locale'] || v[:locale], admin: admin}
      rec[:quickbar] = v['quickbar'] if v['quickbar'].is_a?(Array)
      rec[:quickbar_page] = v['quickbar_page'] if v['quickbar_page'].is_a?(Integer)
      h[k.to_i] = rec
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
      rec = {name: clean(p[:name]), locale: p[:locale], admin: p.key?(:admin) ? p[:admin] : nil}
      # Quickbar state is written only for players who have some, so the
      # file stays as quiet as it was before quickbar tracking.
      rec[:quickbar] = p[:quickbar] if p[:quickbar]
      rec[:quickbar_page] = p[:quickbar_page] if p[:quickbar_page]
      rec
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