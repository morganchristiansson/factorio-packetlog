# frozen_string_literal: true

# Translation agent — listens to chat and auto-translates for foreign players.
#
# Architecture:
# - Hooks into FactorioSniffer's chat flow (like HiveMindAgent)
# - Resolves player locales from player_db (persisted players.json + the
#   startup RCON roster dump). NO live RCON locale queries, no refresh
#   timer, no duplicate locale cache: locale changes are rare and
#   intentionally ignored for now — packet-level locale tracking can come
#   later if ever needed.
# - Translates incoming messages from foreign players to English (console + relayed
#   in-game to every player whose locale differs from the speaker's)
# - Supports multiple backends: LibreTranslate API, Bergamot (local), mock
# - HiveMind outgoing replies are NOT auto-translated (HiveMind handles its own language)

require 'set'
require_relative 'rcon_client'
require_relative 'agent_events'

class TranslationAgent
  include AgentEvents
  # Minimum interval between translations for the same player (anti-spam)
  TRANSLATE_COOLDOWN = 2.0

  # Our locale (what we translate TO for incoming, FROM for outgoing)
  OUR_LOCALE = 'en'

  # Only these non-English locales get translated. Others (fr, hu, …) are
  # treated as English: no translation, no relay from them, but they still
  # receive EN relay text when a whitelisted speaker talks.
  WHITELIST = Set.new(%w[pt ru])

  # Backend types
  # Available backends: :libretranslate, :bergamot, :mock, :argos, :google, :hybrid

  attr_reader :rcon, :enabled, :player_db, :backend, :translation_service

  def initialize(rcon:, player_db:, backend: BACKEND_LIBRETRANSLATE, libretranslate_url: nil, bergamot_url: nil, api_key: nil, enabled: true)
    @rcon = rcon
    @player_db = player_db
    @backend = backend
    @enabled = enabled && !@rcon.nil? && !@player_db.nil?

    # Initialize translation backend
    @translation_service = create_translation_service(backend, libretranslate_url, bergamot_url, api_key)

    # player_name -> last translation time (for cooldown)
    @last_translate = {}

    # Track which players we've announced translations for (avoid spam)
    @announced_players = Set.new
    initialize_events
  end

  # Called by sniffer for each incoming chat message
  # act: the decoded action hash (has :game_player = 1-indexed game index, matching players.json)
  # message: decoded chat text
  # Returns: [should_continue, translated_text] where should_continue=true means
  # the message should also be processed by other handlers (e.g., HiveMind)
  def on_chat(act, message, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    return [true, nil] unless @enabled
    return [true, nil] if message.nil? || message.strip.empty?
    return [true, nil] if message.start_with?('/')  # Commands not translated
    message = message.delete("\0")  # packet padding/embedded NULs: argos + Lua reject them
    return [true, nil] if message.empty?

    # Get player ID from action (1-indexed game_player matches players.json)
    player_id = act[:game_player]
    return [true, nil] unless player_id

    # Look up player name from ID
    player = @player_db.lookup(player_id)
    return [true, nil] if player.nil? || player.empty? || player.start_with?('Player_')

    # Get player's locale from player_db (populated from the startup roster dump;
    # locale CHANGES are ignored by design — packet-level tracking is TODO).
    locale = @player_db.get_locale(player_id)
    return [true, nil] unless locale
    return [true, nil] unless whitelisted?(locale)

    # Rate limit per player (anti-spam: each message costs one argos run per
    # target locale).
    # Arrival time preserves spam limits even when translations take seconds.
    return [true, nil] if @last_translate[player] && (now - @last_translate[player]) < TRANSLATE_COOLDOWN
    @last_translate[player] = now

    if @translation_service.needed?(locale, OUR_LOCALE)
      # Foreign speaker: translate to English (console + relay base)
      translated = @translation_service.to_english(message, source_lang: locale)

      # Announce once per player per session
      announce_translation(player, locale) unless @announced_players.include?(player)

      # Print translation to console (visible to operator)
      ts = Time.now.strftime('%H:%M:%S')
      puts "#{ts}  [translate] #{player} (#{locale} -> en): #{translated}"
    else
      # English speaker: the message IS the relay base — foreign readers get
      # it re-localized, en readers already saw the original broadcast.
      translated = message
    end

    # Relay IN GAME to everyone who can't read the original: one Lua pass
    # over game.connected_players (the live roster), printing per player the
    # relay text re-localized to THEIR locale (en readers take it as-is).
    relay_to_others(player, locale, translated)

    [true, translated]  # Continue processing, also return translated text
  end

  # Synthetic relay for the /simulate console command: translate + relay
  # to the connected players exactly like a real chat message would
  # (bypasses on_chat's player DB / cooldown path). Returns the EN text.
  def simulate_translation(player_name, speaker_locale, message)
    translated = @translation_service.to_english(message, source_lang: speaker_locale)
    relay_to_others(player_name, speaker_locale, translated)
    translated
  end

  # Called on a CONFIRMED join: one targeted RCON query to learn the
  # joiner's locale (joins are rare — not per message, not a timer) and
  # store it in player_db so every later relay knows it. Locale CHANGES
  # after the join are ignored by design.
  def note_joined(game_index, name)
    return unless @rcon
    escaped = lua_quote(name)
    lua = %(do local p = game.players["#{escaped}"] rcon.print(p and p.locale or "nil") end)
    locale = @rcon.command("/sc #{lua}").strip
    if locale && !locale.empty? && locale != 'nil' && locale != 'false'
      @player_db.set_locale_by_id(game_index, locale) if @player_db.lookup(game_index) == name
    end
    locale
  rescue StandardError => e
    warn "[translation] locale query failed for #{name}: #{e.class}: #{e.message}"
    nil
  end

  # Enable/disable translation at runtime (no background threads to manage)
  def enable!
    @enabled = true
  end

  def disable!
    @enabled = false
  end

  # Shutdown
  def shutdown
    close_events
    disable!
  end

  private

  # Create translation service based on backend
  # Only ONE backend is ever active per agent — load just that file (the
  # others stay out of memory and off the reload path).
  def create_translation_service(backend, libretranslate_url, bergamot_url, api_key)
    case backend
    when :bergamot
      require_relative 'translation_bergamot'
      BergamotTranslationService.new(bergamot_url || 'http://localhost:8080')
    when :mock
      require_relative 'translation_mock'
      MockTranslationService.new
    when :argos
      require_relative 'translation_argos'
      ArgosTranslateService.new
    when :google
      require_relative 'translation_google'
      GoogleCloudTranslateService.new(api_key)
    when :hybrid
      require_relative 'translation_hybrid'
      HybridTranslationService.new(api_key)
    else
      require_relative 'translation_libre'
      LibreTranslateService.new(libretranslate_url || 'https://libretranslate.de/translate', api_key)
    end
  end

  # Seed locale cache from player_db (persisted + the startup roster dump).
  # Runs once, lazily, on the first relay — NO RCON query.

  # Announce that we're translating for this player (once per session)
  def announce_translation(player, locale)
    @announced_players << player
    ts = Time.now.strftime('%H:%M:%S')
    puts "#{ts}  [translate] Auto-translation enabled for #{player} (#{locale} <-> #{OUR_LOCALE})"
  end

  # Relay the EN translation to English readers and whitelisted locales.
  # Only EN and whitelisted locales (pt/ru) appear in the Lua table — fr/hu/zh
  # etc. already saw the original English chat broadcast. One batched Lua:
  #   t = {["en"]="...",["pt"]="..."}; for _, p in pairs(game.connected_players)
  #   do local x = t[p.locale]; if x then p.print("[pt] name: text", ps) end end
  # Lua's connected_players loop is the guard — offline players are skipped.
  def relay_to_others(speaker_name, speaker_locale, translated)
    return unless @rcon
    locales = (@player_db.all_locales.values.uniq - [speaker_locale]).select { |loc|
      norm = loc.to_s.split('-').first&.downcase
      norm == OUR_LOCALE || WHITELIST.include?(norm)
    }
    return if locales.empty?

    entries = locales.filter_map do |loc|
      text = localize(translated, loc)
      # A whitelisted locale that returned the EN text unchanged (missing
      # pack or backend failure) gets skipped — the target already saw it.
      next if loc != OUR_LOCALE && text == translated
      %([#{loc.inspect}]="#{lua_quote(text)}")
    end
    return if entries.empty?

    sl = speaker_locale.to_s.split('-').first || 'en'
    lua = %(do local t = {#{entries.join(',')}}; local n = "#{lua_quote(speaker_name)}"; local sl = "#{lua_quote(sl)}"; local s = game.players[n]; local ps = s and {color = (s.chat_color or s.color)}; for _, p in pairs(game.connected_players) do local x = t[p.locale]; if x then local pl = p.locale:match("^[^-]+") or p.locale; local tag = (p.locale == "en") and (sl..">en") or ("en->"..pl); p.print("["..tag.."] "..n..": "..x, ps) end end end)
    @rcon.command("/sc #{lua}")
  rescue StandardError => e
    warn "[translation] in-game relay failed: #{e.class}: #{e.message}"
  end

  # The relay text is English; 'en' readers take it as-is, whitelisted
  # locales get it translated, everyone else gets the raw EN text.
  def localize(en_text, locale)
    return en_text if locale == OUR_LOCALE
    return en_text unless whitelisted?(locale)
    @translation_service.from_english(en_text, target_lang: locale)
  end

  def whitelisted?(locale)
    norm = locale.to_s.split('-').first&.downcase
    norm == OUR_LOCALE || WHITELIST.include?(norm)
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
