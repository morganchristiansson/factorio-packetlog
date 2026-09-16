# frozen_string_literal: true

# Translation agent — listens to chat and auto-translates for foreign players.
#
# Architecture:
# - Hooks into FactorioSniffer's chat flow (like HiveMindAgent)
# - Tracks player locales via RCON (game.players[name].locale) and persists to players.json
# - Translates incoming messages from foreign players to English (printed to console)
# - Translates outgoing replies to target players' locales via SINGLE batched RCON command
# - Supports multiple backends: LibreTranslate API, Bergamot (local), mock
# - HiveMind outgoing replies are NOT auto-translated (HiveMind handles its own language)

require_relative 'rcon_client'
require 'net/http'
require 'uri'
require 'json'

class TranslationAgent
  # How often to refresh player locales from RCON (seconds)
  LOCALE_REFRESH_INTERVAL = 300

  # Minimum interval between translations for the same player (anti-spam)
  TRANSLATE_COOLDOWN = 2.0

  # Our locale (what we translate TO for incoming, FROM for outgoing)
  OUR_LOCALE = 'en'

  # Backend types
  BACKEND_LIBRETRANSLATE = :libretranslate
  BACKEND_BERGAMOT = :bergamot
  BACKEND_MOCK = :mock

  attr_reader :rcon, :enabled, :player_db, :backend

  def initialize(rcon:, player_db:, backend: BACKEND_LIBRETRANSLATE, libretranslate_url: nil, bergamot_url: nil, api_key: nil, enabled: true)
    @rcon = rcon
    @player_db = player_db
    @backend = backend
    @enabled = enabled && !@rcon.nil? && !@player_db.nil?

    # Initialize translation backend
    @translation_service = create_translation_service(backend, libretranslate_url, bergamot_url, api_key)

    # player_name -> locale (e.g., "pt-BR") — cache from player_db + RCON
    @player_locales = {}
    # player_name -> last translation time (for cooldown)
    @last_translate = {}
    # Mutex for locale cache
    @locale_mutex = Mutex.new
    # Background refresh thread
    @refresh_thread = nil

    # Track which players we've announced translations for (avoid spam)
    @announced_players = Set.new

    # Seed cache from persisted locales
    seed_from_db
    start_locale_refresh if @enabled
  end

  # Called by sniffer for each incoming chat message
  # act: the decoded action hash (has :game_player = 1-indexed game index, matching players.json)
  # message: decoded chat text
  # Returns: [should_continue, translated_text] where should_continue=true means
  # the message should also be processed by other handlers (e.g., HiveMind)
  def on_chat(act, message)
    return [true, nil] unless @enabled
    return [true, nil] if message.nil? || message.strip.empty?
    return [true, nil] if message.start_with?('/')  # Commands not translated

    # Get player ID from action (1-indexed game_player matches players.json)
    player_id = act[:game_player]
    return [true, nil] unless player_id

    # Look up player name from ID
    player = @player_db.lookup(player_id)
    return [true, nil] if player.nil? || player.empty? || player.start_with?('Player_')

    # Check if this player needs translation - query FRESH from RCON on join
    locale = get_player_locale_fresh(player)
    return [true, nil] unless locale
    return [true, nil] unless @translation_service.needed?(locale, OUR_LOCALE)

    # Rate limit per player
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    return [true, nil] if @last_translate[player] && (now - @last_translate[player]) < TRANSLATE_COOLDOWN
    @last_translate[player] = now

    # Translate to English
    translated = @translation_service.to_english(message, source_lang: locale)

    # Announce once per player per session
    announce_translation(player, locale) unless @announced_players.include?(player)

    # Print translation to console (visible to operator)
    ts = Time.now.strftime('%H:%M:%S')
    puts "#{ts}  [translate] #{player} (#{locale} -> en): #{translated}"

    [true, translated]  # Continue processing, also return translated text
  end

  # Batch translate and send a message to multiple players in their languages.
  # messages: {player_name => english_message} hash
  # Returns: number of players sent to
  def broadcast_translated(messages)
    return 0 unless @enabled && messages.is_a?(Hash) && !messages.empty?

    # Group players by locale
    by_locale = {}
    messages.each do |player, message|
      next if message.nil? || message.strip.empty?
      locale = get_player_locale_cached(player)  # Use cached for batch
      next unless locale
      next unless @translation_service.needed?(locale, OUR_LOCALE)
      translated = @translation_service.from_english(message, target_lang: locale)
      next if translated == message
      (by_locale[locale] ||= []) << {player: player, text: translated}
    end

    return 0 if by_locale.empty?

    # Build single RCON command that prints to each player in their locale
    lua_parts = []
    by_locale.each do |locale, entries|
      entries.each do |e|
        lua_parts << %(game.players["#{lua_quote(e[:player])}"].print("#{lua_quote("[translate] #{e[:text]}")}"))
      end
    end

    @rcon.command(%(do #{lua_parts.join(' ')} end))
    by_locale.values.sum(&:size)
  rescue StandardError => e
    warn "[translation] broadcast_translated error: #{e.class}: #{e.message}"
    0
  end

  # Get player's locale - FRESH from RCON (for join/new players)
  def get_player_locale_fresh(player)
    # Query RCON directly for fresh locale
    locale = query_player_locale(player)
    if locale
      @locale_mutex.synchronize { @player_locales[player] = locale }
      id = @player_db.name_to_id(player)
      @player_db.set_locale_by_id(id, locale) if id
    end
    locale
  end

  # Get player's locale - cached (for batch operations)
  def get_player_locale_cached(player)
    @locale_mutex.synchronize do
      return @player_locales[player] if @player_locales.key?(player)
    end

    # Try player_db (persisted)
    id = @player_db.name_to_id(player)
    locale = id ? @player_db.get_locale(id) : nil
    if locale
      @locale_mutex.synchronize { @player_locales[player] = locale }
      return locale
    end

    # Not cached, query RCON
    locale = query_player_locale(player)
    if locale
      @locale_mutex.synchronize { @player_locales[player] = locale }
      @player_db.set_locale_by_id(id, locale) if id
    end
    locale
  end

  # Force refresh a specific player's locale
  def refresh_player_locale(player)
    locale = query_player_locale(player)
    if locale
      @locale_mutex.synchronize { @player_locales[player] = locale }
      id = @player_db.name_to_id(player)
      @player_db.set_locale_by_id(id, locale) if id
    end
    locale
  end

  # Get all known player locales (for debugging)
  def all_locales
    @locale_mutex.synchronize { @player_locales.dup }
  end

  # Enable/disable translation at runtime
  def enable!
    @enabled = true
    start_locale_refresh unless @refresh_thread&.alive?
  end

  def disable!
    @enabled = false
    @refresh_thread&.kill
    @refresh_thread = nil
  end

  # Shutdown
  def shutdown
    disable!
  end

  private

  # Create translation service based on backend
  def create_translation_service(backend, libretranslate_url, bergamot_url, api_key)
    case backend
    when BACKEND_BERGAMOT
      BergamotTranslationService.new(bergamot_url || 'http://localhost:8080')
    when BACKEND_MOCK
      MockTranslationService.new
    else
      LibreTranslateService.new(libretranslate_url || 'https://libretranslate.de/translate', api_key)
    end
  end

  # Seed locale cache from persisted player_db
  def seed_from_db
    @player_db.all_locales.each do |name, locale|
      @locale_mutex.synchronize { @player_locales[name] = locale }
    end
  end

  # Query a single player's locale via RCON
  def query_player_locale(player)
    return nil unless @rcon

    escaped = lua_quote(player)
    lua = %(do local p = game.players["#{escaped}"] rcon.print(p and p.locale or "nil") end)
    result = @rcon.command(lua).strip

    return nil if result.empty? || result == 'nil' || result == 'false'
    result
  rescue StandardError => e
    warn "[translation] locale query failed for #{player}: #{e.class}: #{e.message}"
    nil
  end

  # Background thread to refresh all online player locales
  def start_locale_refresh
    @refresh_thread = Thread.new do
      loop do
        sleep LOCALE_REFRESH_INTERVAL
        next unless @enabled
        refresh_all_locales
      end
    rescue StandardError => e
      warn "[translation] locale refresh thread died: #{e.class}: #{e.message}"
    end
    @refresh_thread.name = 'translation-locale-refresh'
  end

  def refresh_all_locales
    # Use the bulk player_attributes query which now includes locale
    attrs = @rcon.player_attributes
    return unless attrs

    attrs.each do |p|
      next unless p[:locale]
      @locale_mutex.synchronize { @player_locales[p[:name]] = p[:locale] }
      @player_db.set_locale_by_id(p[:index], p[:locale])
    end
  rescue StandardError => e
    warn "[translation] refresh_all_locales error: #{e.class}: #{e.message}"
  end

  # Announce that we're translating for this player (once per session)
  def announce_translation(player, locale)
    @announced_players << player
    ts = Time.now.strftime('%H:%M:%S')
    puts "#{ts}  [translate] Auto-translation enabled for #{player} (#{locale} <-> #{OUR_LOCALE})"
  end

  # Lua string escaping
  def lua_quote(str)
    out = +''
    str.to_s.each_char do |ch|
      out << "\\" if ch == '"' || ch == "\\"
      out << ((ch == "\n" || ch == "\r") ? ' ' : ch)
    end
    out
  end
end

# ─────────────────────────────────────────────────────────────────
# Translation Service Backends
# ─────────────────────────────────────────────────────────────────

class LibreTranslateService
  def initialize(url, api_key = nil)
    @url = url
    @api_key = api_key
    @cache = {}
    @mutex = Mutex.new
  end

  def translate(text, source_lang:, target_lang:)
    return text if text.nil? || text.strip.empty?
    return text if source_lang == target_lang && source_lang != 'auto'

    cache_key = "#{source_lang}|#{target_lang}|#{text}"
    @mutex.synchronize { return @cache[cache_key] if @cache.key?(cache_key) }

    result = do_translate(text, source_lang, target_lang)
    @mutex.synchronize { @cache[cache_key] = result } if result && result != text
    result
  rescue StandardError => e
    warn "[translation] LibreTranslate error: #{e.class}: #{e.message}"
    text
  end

  def to_english(text, source_lang:)
    translate(text, source_lang: normalize_locale(source_lang), target_lang: 'en')
  end

  def from_english(text, target_lang:)
    translate(text, source_lang: 'en', target_lang: normalize_locale(target_lang))
  end

  def needed?(player_locale, our_locale)
    normalize_locale(player_locale) != normalize_locale(our_locale)
  end

  def clear_cache!
    @mutex.synchronize { @cache.clear }
  end

  private

  def do_translate(text, source_lang, target_lang)
    uri = URI(@url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.read_timeout = 10
    http.open_timeout = 5

    body = {q: text, source: source_lang, target: target_lang, format: 'text'}
    body[:api_key] = @api_key if @api_key

    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req.body = body.to_json

    response = http.request(req)
    return text unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    parsed['translatedText'] || text
  rescue JSON::ParserError
    text
  end

  def normalize_locale(locale)
    return 'auto' if locale == 'auto'
    locale.split('-').first&.downcase || 'en'
  end
end

class BergamotTranslationService
  def initialize(url)
    @url = url.sub(%r{/+$}, '') + '/translate'
    @cache = {}
    @mutex = Mutex.new
  end

  def translate(text, source_lang:, target_lang:)
    return text if text.nil? || text.strip.empty?
    return text if source_lang == target_lang && source_lang != 'auto'

    cache_key = "#{source_lang}|#{target_lang}|#{text}"
    @mutex.synchronize { return @cache[cache_key] if @cache.key?(cache_key) }

    result = do_translate(text, source_lang, target_lang)
    @mutex.synchronize { @cache[cache_key] = result } if result && result != text
    result
  rescue StandardError => e
    warn "[translation] Bergamot error: #{e.class}: #{e.message}"
    text
  end

  def to_english(text, source_lang:)
    translate(text, source_lang: normalize_locale(source_lang), target_lang: 'en')
  end

  def from_english(text, target_lang:)
    translate(text, source_lang: 'en', target_lang: normalize_locale(target_lang))
  end

  def needed?(player_locale, our_locale)
    normalize_locale(player_locale) != normalize_locale(our_locale)
  end

  def clear_cache!
    @mutex.synchronize { @cache.clear }
  end

  private

  def do_translate(text, source_lang, target_lang)
    # Bergamot API: POST /translate with JSON {q, source, target}
    # Returns {translatedText: "..."}
    uri = URI(@url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.read_timeout = 30  # Local model may be slower
    http.open_timeout = 10

    body = {q: text, source: source_lang, target: target_lang}

    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req.body = body.to_json

    response = http.request(req)
    return text unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    parsed['translatedText'] || text
  rescue JSON::ParserError
    text
  end

  def normalize_locale(locale)
    return 'auto' if locale == 'auto'
    locale.split('-').first&.downcase || 'en'
  end
end

class MockTranslationService
  def initialize
    @cache = {}
    @mutex = Mutex.new
  end

  def translate(text, source_lang:, target_lang:)
    return text if text.nil? || text.strip.empty?
    cache_key = "#{source_lang}|#{target_lang}|#{text}"
    @mutex.synchronize { return @cache[cache_key] if @cache.key?(cache_key) }
    result = "[#{target_lang}] #{text}"
    @mutex.synchronize { @cache[cache_key] = result }
    result
  end

  def to_english(text, source_lang:)
    translate(text, source_lang: source_lang, target_lang: 'en')
  end

  def from_english(text, target_lang:)
    translate(text, source_lang: 'en', target_lang: target_lang)
  end

  def needed?(player_locale, our_locale)
    player_locale != our_locale
  end

  def clear_cache!
    @mutex.synchronize { @cache.clear }
  end
end