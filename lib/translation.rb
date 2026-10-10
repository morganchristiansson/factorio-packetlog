# frozen_string_literal: true

require 'set'
require 'yaml'
require_relative 'rcon_client'
require_relative 'agent_events'

# The `translation` plugin (config.yaml `plugins:`) — the file is named after
# the plugin, the class after what it does.
class TranslationAgent
  include AgentEvents
  # Non-secret translation settings live in this file. There is no key list
  # and no code default: the file must exist (checked once, so "no config at
  # all" names the example to copy) and every key is read with Hash#fetch
  # where it is used — a missing one raises `KeyError: key not found:
  # "<key>"` at that point. The Google key is the one optional key: a secret
  # (env first, `google_api_key:` here) that only the google/hybrid backends
  # need, and they refuse to start without it.
  CONFIG_FILE = 'config-translation.yaml'

  def self.load_config(path = CONFIG_FILE)
    raise Errno::ENOENT, "missing #{path}; copy config-translation.yaml.example" unless File.file?(path)

    YAML.safe_load_file(path) || {}
  end

  # Backend types
  # Available backends: :mock, :argos, :google, :hybrid

  attr_reader :rcon, :enabled, :player_db, :backend, :translation_service, :whitelist

  # roster: a callable returning the CURRENT connected players as
  # [{index:, name:}] (the sniffer's live roster). Used by the relay to
  # decide per-player who needs a translated line and address them by game
  # index — Lua can't see the language overrides, so the decision is made
  # here and Lua just prints to the computed indexes.
  # google_api_key/argos_path/backend/config_file are injection points for
  # tests (and the key for ops); everything else comes from the config file.
  def initialize(owner = nil, rcon: nil, player_db: nil, backend: nil, google_api_key: nil, roster: nil,
                 config_file: CONFIG_FILE, argos_path: nil)
    # owner (the sniffer) provides rcon/player_db/roster; the kwargs stay for
    # tests that build TranslationAgent directly. PluginSet builds
    # TranslationAgent.new(owner); config-translation.yaml is the source.
    trans_config = self.class.load_config(config_file)
    backend = (backend || trans_config.fetch('backend')).to_sym
    # Google key for the hybrid/google backend. Env wins (ops/CI
    # override without editing the file); the YAML `google_api_key:` is
    # the fallback. config-translation.yaml is gitignored, so a key there
    # stays local.
    if (backend == :hybrid || backend == :google) && google_api_key.nil?
      google_api_key = ENV['GOOGLE_TRANSLATE_API_KEY'] || trans_config['google_api_key']
    end
    @rcon = rcon || (owner&.rcon)
    @player_db = player_db || (owner&.player_db)
    @backend = backend
    @google_api_key = google_api_key
    @enabled = !@rcon.nil? && !@player_db.nil?
    # Locales to translate between. English belongs in the list as a
    # whitelisted language — English speakers get relayed to other whitelisted
    # readers. Translation occurs between all whitelisted locales via direct
    # service support (no pivot).
    @whitelist = trans_config.fetch('whitelist').map { |l| l.to_s.downcase }.to_set
    # Minimum interval between translations for the same player (anti-spam)
    @min_interval = trans_config.fetch('min_interval').to_f
    @roster = roster || -> { owner&.attrs&.roster_pairs || [] }

    # A backend we cannot actually run is a startup error, not a silent
    # no-translation agent: a Google backend with no key, an argos install
    # that isn't there (its service raises), packs that aren't installed.
    if %i[google hybrid].include?(backend) && google_api_key.to_s.empty?
      raise ArgumentError, "backend #{backend} needs a Google key: set GOOGLE_TRANSLATE_API_KEY or google_api_key: in #{config_file}"
    end

    @translation_service = create_translation_service(backend, google_api_key, argos_path)

    # player_name -> last translation time (for cooldown)
    @last_translate = {}

    # Track which players we've announced translations for (avoid spam)
    @announced_players = Set.new
    initialize_events
  end

  # True when a Google key is available (env or config-translation.yaml) —
  # google/hybrid without one can't call the API.
  def google_api_key? = !@google_api_key.to_s.empty?

  def on_chat(source, author, text, player_id = nil, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    # Sync-light relay subscriber (reached via @plugins.emit(:on_chat)):
    # in-game (:factorio) chat ONLY — Discord text and Hivemind replies
    # (English) are never re-translated. player_id is the packet's 1-indexed
    # game index, without which the per-player relay has no speaker to key
    # on; defer the heavy argos+RCON relay to handle_chat on this agent's
    # worker (emit is synchronous, on the capture thread).
    return unless source == :factorio
    return unless player_id
    enqueue(:handle_chat, player_id, text, now: now)
  end

  # The heavy relay (argos + per-player Lua print), run on this agent's worker
  # thread so the capture thread is never blocked. Body of the former on_chat,
  # keyed by player_id (1-indexed game index, matching players-cache.json).
  def handle_chat(player_id, message, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    return [true, nil] unless @enabled
    return [true, nil] if message.nil? || message.strip.empty?
    return [true, nil] if message.start_with?('/')  # Commands not translated
    message = message.delete("\0")  # packet padding/embedded NULs: argos + Lua reject them
    return [true, nil] if message.empty?

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
    return [true, nil] if @last_translate[player] && (now - @last_translate[player]) < @min_interval
    @last_translate[player] = now

    # Announce translation (console only — non-English speakers).
    announce_translation(player, msg_lang) unless @announced_players.include?(player)

    # Relay IN GAME to everyone who can't read the original: decided per
    # player in Ruby (locale + overrides), one Lua pass over
    # game.connected_players (the live roster) printing each computed
    # index's text. Each reader gets their language via direct translation.
    # Only the translations actually sent are echoed to the console — the
    # original chat is already printed by the sniffer.
    relayed = relay_to_others(player, msg_lang, message)
    unless relayed.empty?
      ts = Time.now.strftime('%H:%M:%S')
      puts "#{ts}  [translate] #{relayed.join('  |  ')}"
    end

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

  # Enable/disable translation at runtime (no background threads to manage)
  private

  # Create translation service based on backend
  # Only ONE backend is ever active per agent — load just that file (the
  # others stay out of memory and off the reload path).
  def create_translation_service(backend, google_api_key, argos_path = nil)
    case backend
    when :mock
      require_relative 'translation_mock'
      MockTranslationService.new
    when :argos
      require_relative 'translation_argos'
      ArgosTranslateService.new(path: argos_path || ArgosTranslateService::ARGOS_BIN)
    when :google
      require_relative 'translation_google'
      GoogleCloudTranslateService.new(google_api_key)
    when :hybrid
      require_relative 'translation_hybrid'
      HybridTranslationService.new(google_api_key, argos_path: argos_path || ArgosTranslateService::ARGOS_BIN)
    else
      warn "Unknown translation backend #{backend.inspect}; using argos"
      require_relative 'translation_argos'
      ArgosTranslateService.new
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
  # Returns: the per-target "[en>pt] bob: ola" lines actually relayed.
  def relay_to_others(speaker_name, msg_lang, message)
    return [] unless @rcon
    roster = @roster&.call || []
    return [] if roster.empty?

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
      target = (reader_langs & @whitelist.to_a).first
      next unless target
      text = texts[target] ||= localize(message, target, msg_lang)
      # A whitelisted locale that returned the original text unchanged
      # (missing pack or backend failure) gets skipped — the target
      # already saw it.
      next if text == message
      tag = "#{msg_lang}>#{target}"
      entries << %([#{index}]="[#{tag}] #{@rcon.lua_quote(speaker_name)}: #{@rcon.lua_quote(text)}")
    end
    return [] if entries.empty?

    lua = %(do local t = {#{entries.join(',')}}; local n = "#{@rcon.lua_quote(speaker_name)}"; local s = game.players[n]; local ps = s and {color = (s.chat_color or s.color)}; for _, p in pairs(game.connected_players) do local x = t[p.index]; if x then p.print(x, ps) end end end)
    @rcon.command("/sc #{lua}")
    texts.map { |target, text| "[#{msg_lang}>#{target}] #{speaker_name}: #{text}" }
  rescue StandardError => e
    warn "[translation] in-game relay failed: #{e.class}: #{e.message}"
    []
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
end
