# frozen_string_literal: true

require 'set'
require 'yaml'
require_relative 'rcon_client'
require_relative 'agent_events'

class TranslationAgent
  include AgentEvents
  # Minimum interval between translations for the same player (anti-spam)
  TRANSLATE_COOLDOWN = 2.0

  # Locales to translate between. English is included as a
  # whitelisted language — English speakers get relayed to
  # other whitelisted readers. Translation occurs between all
  # whitelisted locales via direct service support (no pivot).
  WHITELIST = Set.new(%w[en pt ru])
  WHITELIST_ARR = %w[en pt ru]

  # Backend types
  # Available backends: :libretranslate, :bergamot, :mock, :argos, :google, :hybrid

  attr_reader :rcon, :enabled, :player_db, :backend, :translation_service, :whitelist

  # roster: a callable returning the CURRENT connected players as
  # [{index:, name:}] (the sniffer's live roster). Used by the relay to
  # decide per-player who needs a translated line and address them by game
  # index — Lua can't see the language overrides, so the decision is made
  # here and Lua just prints to the computed indexes.
  def initialize(rcon:, player_db:, backend: nil, libretranslate_url: nil, bergamot_url: nil, api_key: nil, enabled: true, roster: nil)
    # Load config-translation.yaml for defaults (param > config > hardcoded).
    trans_config = File.exist?('config-translation.yaml') ? (YAML.load_file('config-translation.yaml') || {}) : {}
    backend ||= (trans_config['backend'] || 'argos').to_sym
    libretranslate_url ||= trans_config['libretranslate_url']
    bergamot_url ||= trans_config['bergamot_url']
    # Google API key for hybrid/google backend — env-only (secret).
    if (backend == :hybrid || backend == :google) && api_key.nil? && ENV['GOOGLE_TRANSLATE_API_KEY']
      api_key = ENV['GOOGLE_TRANSLATE_API_KEY']
    end
    @rcon = rcon
    @player_db = player_db
    @backend = backend
    @enabled = enabled && !@rcon.nil? && !@player_db.nil?
    @whitelist = (trans_config['whitelist'] || WHITELIST.to_a).map(&:downcase).to_set
    @whitelist_arr = @whitelist.to_a
    @roster = roster

    # Initialize translation backend
    @translation_service = create_translation_service(backend, libretranslate_url, bergamot_url, api_key)

    # player_name -> last translation time (for cooldown)
    @last_translate = {}

    # Track which players we've announced translations for (avoid spam)
    @announced_players = Set.new
    initialize_events
  end

  # Called by sniffer for each incoming chat message
  # act: the decoded action hash (has :game_player = 1-indexed game index, matching players-cache.json)
  # message: decoded chat text
  # Returns: [should_continue, message] — original message; relay handles per-reader translation
  def on_chat(act, message, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    return [true, nil] unless @enabled
    return [true, nil] if message.nil? || message.strip.empty?
    return [true, nil] if message.start_with?('/')  # Commands not translated
    message = message.delete("\0")  # packet padding/embedded NULs: argos + Lua reject them
    return [true, nil] if message.empty?

    # Get player ID from action (1-indexed game_player matches players-cache.json)
    player_id = act[:game_player]
    return [true, nil] unless player_id

    # Look up player name from ID
    player = @player_db.lookup(player_id)
    return [true, nil] if player.nil? || player.empty? || player.start_with?('Player_')

    # The player's languages: Factorio locale (base) + /locales overrides.
    # The speaker's MESSAGE language: their base Factorio locale.
    langs = languages(player)
    return [true, nil] if langs.empty?
    locale = @player_db.get_locale(player_id)
    msg_lang = base(locale)
    return [true, nil] unless whitelisted?(msg_lang)

    # Rate limit per player (anti-spam: each message costs one argos run per
    # target locale).
    # Arrival time preserves spam limits even when translations take seconds.
    return [true, nil] if @last_translate[player] && (now - @last_translate[player]) < TRANSLATE_COOLDOWN
    @last_translate[player] = now

    # Announce translation (console only — non-English speakers).
    announce_translation(player, msg_lang) unless @announced_players.include?(player)

    # Print to console (visible to operator).
    ts = Time.now.strftime('%H:%M:%S')
    puts "#{ts}  [translate] #{player} (#{msg_lang}): #{message}"

    # Relay IN GAME to everyone who can't read the original: decided per
    # player in Ruby (locale + overrides), one Lua pass over
    # game.connected_players (the live roster) printing each computed
    # index's text. Each reader gets their language via direct translation.
    relay_to_others(player, msg_lang, message)

    [true, message]  # Continue processing, return original text
  end

  # Synthetic relay for the /simulate console command: translate + relay
  # to the connected players exactly like a real chat message would
  # (bypasses on_chat's player DB / cooldown path). Returns the EN text.
  def simulate_translation(player_name, speaker_locale, message)
    msg_lang = base(speaker_locale)
    relay_to_others(player_name, msg_lang, message)
    @translation_service.translate(message, source_lang: msg_lang, target_lang: 'en')
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

  # A player's effective languages: [Factorio locale base] + any /locales
  # overrides. The locale (their interface language) always comes first so
  # target selection prefers it for relay translations.
  def languages(name)
    id = @player_db.id_for(name)
    locale = id && @player_db.get_locale(id)
    langs = [base(locale)]
    langs += @player_db.locale_overrides(name) || []
    langs.compact.uniq
  end

  def base(locale)
    b = locale.to_s.split('-').first&.downcase&.strip
    b.empty? ? nil : b
  end

  # Announce that we're translating for this player (once per session)
  def announce_translation(player, locale)
    @announced_players << player
    ts = Time.now.strftime('%H:%M:%S')
    puts "#{ts}  [translate] Auto-translation enabled for #{player} (#{locale})"
  end

  # Relay the message to every connected player who can't read the
  # original. The READER decision (per player: locale + overrides) happens
  # in Ruby; Lua only prints the precomputed text for each player's game
  # index, still guarded by game.connected_players (offline players are
  # never in the roster and the Lua loop skips drift). One batched Lua:
  #   t = {[2]="[pt>ru] ivan: hi",[5]="[en>pt] bob: ola"}
  #   for _, p in pairs(game.connected_players) do
  #     local x = t[p.index]; if x then p.print(x, ps) end end
  def relay_to_others(speaker_name, msg_lang, message)
    return unless @rcon
    roster = @roster&.call || []
    return if roster.empty?

    entries = []
    texts = {}  # target -> localized text (one backend call per target lang)
    roster.each do |p|
      name = p[:name]
      index = p[:index]
      next unless name && index
      reader_langs = languages(name)
      next if reader_langs.empty?
      # They already read the original in one of their languages.
      next if reader_langs.include?(msg_lang)
      # Pick the first whitelisted language they read (locale first,
      # then overrides).
      target = (reader_langs & @whitelist_arr).first
      next unless target
      text = texts[target] ||= localize(message, target, msg_lang)
      # A whitelisted locale that returned the original text unchanged
      # (missing pack or backend failure) gets skipped — the target
      # already saw it.
      next if text == message
      tag = "#{msg_lang}>#{target}"
      entries << %([#{index}]="[#{tag}] #{lua_quote(speaker_name)}: #{lua_quote(text)}")
    end
    return if entries.empty?

    lua = %(do local t = {#{entries.join(',')}}; local n = "#{lua_quote(speaker_name)}"; local s = game.players[n]; local ps = s and {color = (s.chat_color or s.color)}; for _, p in pairs(game.connected_players) do local x = t[p.index]; if x then p.print(x, ps) end end end)
    @rcon.command("/sc #{lua}")
  rescue StandardError => e
    warn "[translation] in-game relay failed: #{e.class}: #{e.message}"
  end

  # Direct translation from source language to target.
  def localize(message, locale, msg_lang)
    return message if locale == msg_lang
    return message unless whitelisted?(locale)
    @translation_service.translate(message, source_lang: msg_lang, target_lang: locale)
  end

  def whitelisted?(locale)
    norm = locale.to_s.split('-').first&.downcase
    @whitelist.include?(norm)
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
