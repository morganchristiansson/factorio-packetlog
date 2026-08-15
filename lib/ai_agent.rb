# frozen_string_literal: true

require 'time'
require 'ruby_llm'

# RubyLLM tool: send a chat message to in-game Factorio chat via RCON.
# The LLM calls this to respond to players. Instantiated with the rcon
# client (RubyLLM's with_tool accepts instances, so dependencies can be
# injected) and keeps track of what was actually sent.
#
# Returning Tool::Halt stops the conversation loop after the send, so the
# reply appears in game chat immediately and no follow-up completion is
# generated (faster, and the final text response can't double-send).
class HivemindSay < RubyLLM::Tool
  desc 'Send a message to the in-game Factorio chat, visible to all players. ' \
       'Use this to respond to the player who addressed you.'

  attr_reader :last_sent

  def initialize(rcon:, prefix: 'Hivemind> ')
    @rcon = rcon
    @prefix = prefix
    @last_sent = nil
  end

  def execute(text:)
    @last_sent = text.to_s
    return halt('') if @last_sent.empty?

    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{@last_sent}"
    @rcon.say("#{@prefix}#{@last_sent}")
    halt('')
  end
end

# RubyLLM tool: run a READ-ONLY RCON console command and return its output.
# Lets the model answer server questions (/players, /time, /evolution,
# /sc rcon.print(...) Lua queries) without hardcoding data. The desc and
# system prompt instruct read-only use — no admin actions, no state changes.
class RconQuery < RubyLLM::Tool
  desc 'Run a READ-ONLY RCON console command on the Factorio server and ' \
       'return its output. Use for queries: /players, /admins, /time, ' \
       '/evolution, /version, /sc rcon.print(...) (Lua queries, e.g. ' \
       'serpent.line of game tables). NEVER use this to modify game state: ' \
       'no admin/permission changes, no commands that build/destroy/reset, ' \
       'no /sc Lua that writes or mutates (game.print replies are handled by ' \
       'the say tool). Read-only queries only.'

  def initialize(rcon:, max_output: 1500)
    @rcon = rcon
    @max_output = max_output
  end

  def execute(command:)
    cmd = command.to_s.strip
    return 'Error: empty command' if cmd.empty?
    cmd = "/#{cmd}" unless cmd.start_with?('/')
    out = @rcon.command(cmd).to_s.strip
    out = out.each_char.take(@max_output).join + '…' if out.each_char.count > @max_output
    out.empty? ? '(no output)' : out
  rescue StandardError => e
    "RCON error: #{e.class}: #{e.message}"
  end
end

# HiveMind agent — an LLM persona that lives inside the Factorio sniffer.
#
# Input: in-game chat decoded from the packet stream. The sniffer calls
# #on_chat(player, message) from log_action for every write_to_console
# action (see FactorioProtocol.decode_chat), so no server-side changes or
# mods are needed.
#
# Trigger: a chat message containing "hivemind" (case-insensitive) gets an
# LLM response. The response is sent back to in-game chat through the
# HivemindSay tool (RCON game.print) so everyone sees it. A rolling
# conversation context is kept in the LLM chat object so follow-ups make
# sense; context is reset after MAX_CONVERSATION exchanges.
#
# LLM: ruby_llm against a configurable OpenAI-compatible endpoint (default
# https://opencode.ai/zen/go/v1). More tools (RCON queries, packet-decoder
# lookups) can be added the same way as HivemindSay — they get access to
# the rcon client / the sniffer's item/player DBs via the tool constructor.
class HiveMindAgent
  # Default OpenAI-compatible endpoint + model (override via HIVE_*/--ai-*).
  DEFAULT_API_BASE = 'https://opencode.ai/zen/go/v1'
  DEFAULT_MODEL    = 'gpt-5.6-luna'

  TRIGGER = 'hivemind'          # respond when chat contains this (case-insensitive)
  MIN_INTERVAL = 5.0            # minimum seconds between LLM calls (anti-spam)
  MAX_REPLY_LEN = 400           # truncate fallback replies (Factorio chat is ~500 chars)
  MAX_CONVERSATION = 40         # reset LLM context after this many exchanges

  attr_reader :trigger, :model

  # Callable returning the names of players currently online (the sniffer
  # sets this to its packet-derived list each construction — see
  # FactorioSniffer#online_players). Falls back to an RCON roster query.
  attr_accessor :online_provider

  # Callable returning mirrored player attributes (see
  # FactorioSniffer#player_stats — [{name:, index:, connected:, admin:,
  # online_time_ticks:}] with online_time computed lazily from the game
  # tick). Falls back to an RCON player_attributes query.
  attr_accessor :player_stats_provider

  # LLM init failed (no API key, missing gem, bad model) — agent is inert;
  # the sniffer prints the startup warning and messages are ignored.
  def disabled?
    !!@disabled
  end

  # rcon: an RconClient (for game.print replies). model/provider/api_key/
  # api_base override the defaults and HIVE_* env vars. Chat completions
  # need an API key (HIVE_API_KEY / --ai-api-key / OPENAI_API_KEY).
  def initialize(rcon:, model: nil, provider: nil, api_key: nil,
                 api_base: nil, trigger: TRIGGER)
    @rcon = rcon
    @trigger = trigger
    @model = model || ENV['HIVE_MODEL'] || DEFAULT_MODEL
    @api_key = api_key || ENV['HIVE_API_KEY'] || ENV['OPENAI_API_KEY']
    @api_base = api_base || ENV['HIVE_API_BASE'] || DEFAULT_API_BASE
    @last_ask = 0.0
    @exchanges = 0
    @mutex = Mutex.new
    @chat = nil

    configure_llm(provider)
  end

  # Feed a decoded chat message (player name, message text). Called by the
  # sniffer from log_action for write_to_console actions. Returns true when
  # a response was dispatched (trigger matched, rate limit passed).
  def on_chat(player, message)
    handle(player, message)
  end

  private

  # ── LLM plumbing ──────────────────────────────────────────────────

  def configure_llm(provider)
    RubyLLM.configure do |config|
      config.openai_api_base = @api_base
      config.openai_api_key = @api_key if @api_key
      config.default_model = @model
      config.request_timeout = 60
      config.max_retries = 1
      config.log_level = Logger::WARN if config.respond_to?(:log_level=)
    end

    if @api_key.nil? || @api_key.empty?
      warn '[hivemind] no API key set (HIVE_API_KEY / --ai-api-key / OPENAI_API_KEY) — agent disabled'
      @disabled = true
      return
    end

    # The endpoint's models (gpt-5.6-luna, glm-5.3, ...) are not in
    # RubyLLM's registry, so resolve with assume_model_exists: true and an
    # explicit provider. Fail loudly here (startup) rather than at ask time.
    @chat = RubyLLM.chat(
      model: @model,
      provider: (provider || ENV['HIVE_PROVIDER'] || :openai).to_sym,
      assume_model_exists: true
    )
    @chat.with_instructions(SYSTEM_PROMPT)
    register_tools
  rescue LoadError => e
    warn "[hivemind] ruby_llm not installed (bundle install) — agent disabled: #{e.message}"
    @disabled = true
  rescue StandardError => e
    warn "[hivemind] LLM init failed — agent disabled: #{e.class}: #{e.message}"
    @disabled = true
  end

  # Re-register the tool set with FRESH instances before every ask. Tools
  # are registered once at creation otherwise; hot reloads (Ctrl-C `load`)
  # rebind the tool CLASSES, so stale instances would keep running old
  # code and new tools wouldn't appear until restart. with_tool replaces by
  # name, so this is idempotent and cheap.
  def register_tools
    return unless @chat
    @chat.with_tool(HivemindSay.new(rcon: @rcon))
    @chat.with_tool(RconQuery.new(rcon: @rcon)) if defined?(RconQuery)
  end

  def ask_llm(player, message)
    prompt = "In-game chat from #{player}: #{message}\n\n" \
             "Answer the player's question or continue the conversation. " \
             "Keep it under #{MAX_REPLY_LEN} characters. Plain text only — " \
             'no markdown, no code blocks, no emoji.'
    # Whole ask under the mutex: the chat object (messages, system prompt)
    # is shared state, and the rate limiter means only one ask is live at a
    # time anyway — serializing just prevents interleaving.
    @mutex.synchronize do
      @exchanges += 1
      if @exchanges >= MAX_CONVERSATION
        @chat.reset_messages!
        @exchanges = 0
      end
      # Fresh system context per ask: the online player list + stats are
      # part of the system prompt (replace_system_instruction swaps it in
      # place, no accumulation), so the model always knows who is in-game.
      # register_tools keeps tool code hot-reloadable (see above).
      register_tools
      @chat.with_instructions(system_prompt)
      response = @chat.ask(prompt)

      # Tool path: HivemindSay already sent the reply (ask returns a
      # Tool::Halt with empty content after the halt). Fallback path: the
      # model returned plain text without calling the tool → return it and
      # let #handle send it via RCON.
      text = response.respond_to?(:content) ? response.content.to_s : ''
      clean_reply(text)
    end
  end

  # SYSTEM_PROMPT plus the current online roster and player stats, e.g.
  #   Currently online players: Alice, Bob (2 players).
  #   Player stats (total play time; live session included for online
  #   players): Alice: 5h12m (admin); Bob: 2h3m; Carol: 1d3h (offline).
  def system_prompt
    parts = [SYSTEM_PROMPT]
    online = online_player_list
    parts << "Currently online players: #{online.join(', ')} (#{online.size} players)." unless online.empty?
    stats = player_stat_lines
    parts << "Player stats (total play time across sessions; live session included for online players): #{stats.join('; ')}." unless stats.empty?
    parts.join("\n\n")
  end

  # Names of players currently in-game. Primary source: the sniffer's
  # packet-derived online tracking (FactorioSniffer#online_players); if no
  # provider is wired (agent used standalone), query RCON directly.
  def online_player_list
    if @online_provider
      list = @online_provider.call
      return [] if list.nil?
      return list.map { |p| p[:name] } if list.first.is_a?(Hash)
      return list.map(&:to_s)
    end
    @rcon&.connected_players&.map { |p| p[:name] } || []
  rescue StandardError => e
    warn "[hivemind] online-player query failed: #{e.class}: #{e.message}"
    []
  end

  # Player attribute lines for the system context. Primary source: the
  # sniffer's mirrored PlayerAttrs (packet-maintained, seeded from RCON);
  # if the provider yields nothing (attrs not seeded yet / query failed),
  # fall back to a direct RCON query.
  def player_stat_lines
    list = @player_stats_provider ? (@player_stats_provider.call || []) : []
    list = @rcon&.player_attributes || [] if list.empty? && @rcon
    list.map do |p|
      time = format_ticks(p[:online_time_ticks] || p[:online_time])
      flags = []
      flags << 'admin' if p[:admin]
      flags << 'offline' unless p[:connected]
      suffix = flags.empty? ? '' : " (#{flags.join(', ')})"
      "#{p[:name]}: #{time}#{suffix}"
    end
  rescue StandardError => e
    warn "[hivemind] player-stats query failed: #{e.class}: #{e.message}"
    []
  end

  # 60 ticks per second → compact human duration, e.g. 43_200 → "12m",
  # 1_836_000 → "8h30m", 5_184_000 → "1d0h".
  def format_ticks(ticks)
    s = ticks.to_i / 60
    days = s / 86_400
    hours = (s % 86_400) / 3600
    mins = (s % 3600) / 60
    parts = []
    parts << "#{days}d" if days > 0
    parts << "#{hours}h" if days > 0 || hours > 0
    parts << "#{mins}m"
    parts.join
  end

  # Strip markdown-ish noise and clamp length without splitting UTF-8 chars.
  def clean_reply(text)
    text = text.gsub('`', '').gsub(/[*_]{1,2}/, '')
    chars = text.each_char.first(MAX_REPLY_LEN).join
    chars.strip
  end

  # ── Trigger / rate limit / reply ──────────────────────────────────

  def handle(player, message)
    return false if @disabled

    msg = message.to_s.strip
    return false if msg.empty?
    return false unless msg.match?(/#{Regexp.escape(@trigger)}/i)

    # Atomic check-and-set rate limiter so bursts of mentions can't fire
    # concurrent LLM calls.
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      return false if now - @last_ask < MIN_INTERVAL
      @last_ask = now
    end

    # LLM calls run off the sniffer's packet loop (seconds of latency).
    Thread.new do
      begin
        reply = ask_llm(player, msg)
        send_reply(reply)
      rescue StandardError => e
        warn "[hivemind] error responding to #{player}: #{e.class}: #{e.message}"
      end
    end
    true
  end

  # Fallback reply path: only fires when the model answered with plain text
  # instead of calling the HivemindSay tool. Lua-quoted so arbitrary text
  # can't break out of the /sc game.print(...) string.
  def send_reply(text)
    return if text.nil? || text.empty?
    prefix = 'Hivemind> '
    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{text}"
    @rcon.say("#{prefix}#{text}")
  end

  SYSTEM_PROMPT = <<~PROMPT
    You are "Hivemind", an AI assistant living inside a Factorio multiplayer
    server. Players address you by name ("hivemind") in in-game chat.

    You respond ONLY when directly addressed. Be friendly, terse, and
    game-savvy: talk naturally about Factorio — builds, circuits, trains,
    biters, Space Age, quality, ratios.

    Rules:
    - ALWAYS respond by calling the say tool with your reply text. Never
      output the reply as a plain-text message.
    - Keep replies under 400 characters — Factorio chat is tiny.
    - Plain text only: no markdown, no code blocks, no emoji.
    - Stay in character: you are part of the server community.
    - If you don't know something, say so briefly.

    Context you are given with each message:
    - The online player list (who is in-game right now).
    - Per-player stats: total play time and admin status (e.g.
      "Alice: 5h12m (admin)", "Bob: 2h3m", "Carol: 1d3h (offline)"). Use
      these to answer questions like "who has played the longest" or
      "who is an admin".

    Tools:
    - say: send your reply to in-game chat (always use this to respond).
    - rcon_query: run READ-ONLY RCON console queries (/players, /admins,
      /time, /evolution, /version, /sc rcon.print(...) Lua queries). Use it
      to fetch live server info. NEVER use it to modify game state: no
      admin/permission changes, no build/destroy/reset commands, no /sc
      Lua that writes or mutates. Read-only only.
  PROMPT
end
