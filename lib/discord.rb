# frozen_string_literal: true

require 'yaml'
require_relative 'agent_events'

# The `discord` plugin (config.yaml `plugins:`) — relays chat between a
# Discord channel and in-game Factorio chat, and feeds Discord messages
# into the Hivemind agent so Discord users can address the AI (the agent
# decides, via its own trigger logic, whether to answer; its replies echo
# back to Discord through the shared relay).
#
# Mode: server only. Posting in-game chat needs RCON (game.print); Discord
# messages arrive over the gateway in real time (no polling). The bot runs
# on its own thread (Discordrb::Bot#run(:async)) parallel to the sniffer's
# capture loop — the same background-thread pattern translation/hivemind use.
#
# A plugin FEATURE: PluginSet builds Discord.new(owner)
# via the `plugins:` list. The sniffer reaches this object with the chat relay
# (`owner.publish_chat`) and reads rcon/player_db from `owner` — so the bridge
# holds no agent ref and there is no reply_callback bolt-on. It enters the
# chat event via on_chat (reached through @plugins.emit(:on_chat)) and emits
# its own messages via owner.publish_chat(:discord, author, text); it skips
# source :discord on_chat to avoid echoing a Discord message back into the
# channel (loop guard). forward_chat runs off-thread on the bridge's worker,
# like the agent's on_chat does.
#
# Config: config-discord.yaml (gitignored). The token is a secret — env-first
# (DISCORD_TOKEN), then `token:` in the yaml. channel_id is the one routing
# key. A missing file/key disables it (reported as "[discord] disabled: …"),
# never silently half-alive.
#
# MESSAGE_CONTENT intent: required to read message text for non-mentioned
# messages. Enable it both here (the intent bitmask — discordrb's INTENTS hash
# predates it, so OR the raw `1 << 15` bit in) AND in the Discord Developer
# Portal under Bot → Privileged Gateway Intents.
class Discord
  include AgentEvents

  CONFIG_FILE = 'config-discord.yaml'
  # Secret token env var — preferred over the yaml key.
  TOKEN_ENV = 'DISCORD_TOKEN'
  # discordrb's INTENTS hash predates MESSAGE_CONTENT, so supply the raw
  # privileged bit and OR it into the unprivileged set the constructor accepts.
  MESSAGE_CONTENT_INTENT = 1 << 15

  # Mirrors TranslationAgent.load_config: a missing file is a clear startup
  # error naming the example to copy (checked once).
  def self.load_config(path = CONFIG_FILE)
    raise Errno::ENOENT, "missing #{path}; copy config-discord.yaml.example" unless File.file?(path)

    YAML.safe_load_file(path) || {}
  end

  attr_reader :channel_id

  # owner: the sniffer (host of the chat relay). Reads rcon/player_db from it
  # and publishes Discord-sourced chat back through owner.publish_chat so the
  # agent sees it and its replies echo to the channel — no agent: ref. Built
  # by PluginSet as Discord.new(owner); bot: injected only by tests.
  def initialize(owner, config_file: CONFIG_FILE, bot: nil)
    @rcon = owner.rcon
    @player_db = owner.player_db
    @emit_chat = ->(source, author, text) { owner.publish_chat(source, author, text) }
    cfg = self.class.load_config(config_file)
    # channel_id is the routing key — fetch names its absence (KeyError).
    @channel_id = cfg.fetch('channel_id').to_i
    # Secret, env-first: DISCORD_TOKEN wins, the yaml `token:` is the local
    # fallback. Absent both → startup error (not a silent no-token bridge).
    @token = ENV[TOKEN_ENV] || cfg['token']
    raise ArgumentError, "no Discord token — set #{TOKEN_ENV} or `token:` in #{config_file}" if @token.to_s.empty?

    @bot = bot || build_bot
    # Register the gateway handler as a bound method so a hot reload (which
    # reopens the class) dispatches to the redefined on_discord_message on
    # the SAME gateway thread — no reconnect needed, mirroring hivemind's
    # chat object surviving reload.
    @bot.message(&method(:on_discord_message))
    initialize_events
  end

  # Build (and async-start) the real discordrb gateway. The require is lazy
  # so this file loads for non-server runs / tests without the gem present;
  # a missing gem disables the bridge via the sniffer's construction guard.
  def build_bot
    require 'discordrb'
    # Minimal intents: only GUILD_MESSAGES (to receive MESSAGE_CREATE in the
    # bridged channel) + MESSAGE_CONTENT (the one privileged bit, so message
    # text arrives for non-@mentioned messages — toggle it in the Developer
    # Portal). Nothing else is subscribed: no members/presences/firehose.
    # discordrb resolves the channel via REST (cached after first message)
    # instead of GUILD_CREATE state, which is fine for a single bridged channel.
    intents = Discordrb::INTENTS[:server_messages] | MESSAGE_CONTENT_INTENT
    bot = Discordrb::Bot.new(token: @token, intents: intents, suppress_ready: true)
    bot.run(:async) # gateway on its own thread; returns immediately
    bot
  rescue LoadError => e
    raise "cannot load discordrb — run `bundle install` (or `gem install discordrb`): #{e.message}"
  rescue => e
    raise "discord gateway failed to start: #{e.class}: #{e.message}"
  end

  # Factorio chat → Discord. Called off the capture thread via the AgentEvents
  # worker (forward_chat), since @bot.send_message does a blocking REST call —
  # the same reason translation keeps RCON/REST off the capture thread.
  def forward_chat(name, msg)
    return unless @bot

    text = "#{name}: #{msg}"
    # allowed_mentions with an empty parse array suppresses @-pings on relayed
    # chat (Factorio names aren't Discord users). send_message caps at 2000 chars.
    @bot.send_message(@channel_id, text, false, nil, nil, { parse: [] })
  rescue StandardError => e
    warn "[discord] failed to forward chat: #{e.class}: #{e.message}"
  end

  # Chat relay subscriber (reached via @plugins.emit(:on_chat)). Forwards
  # in-game chat and Hivemind replies to the Discord channel; skips its own
  # :discord input (a Discord message that triggered this must not be echoed
  # back to the channel — that's the loop guard) and ALL slash-prefixed
  # lines (commands and whispers stay in the game). Runs on the bridge's
  # worker, so the blocking send_message stays off the emitter's thread.
  def on_chat(source, author, message, player_id = nil)
    return if source == :discord
    return if message.to_s.start_with?('/')
    enqueue(:forward_chat, author, message)
  end

  # Gateway entry point (Discord → game). Runs on discordrb's event thread, so
  # it only extracts + validates and immediately enqueues the blocking work to
  # this bridge's worker thread.
  def on_discord_message(event)
    return unless event.channel&.id&.to_i == @channel_id
    # Skip the bot's own echoes (Hivemind replies) and other bots — prevents
    # loops and cross-bot noise. (discordrb skips self by default too.)
    return if event.author&.bot_account?

    author = clean_text(event.author&.display_name || event.author&.username || 'someone')
    content = clean_text(event.content.to_s)
    return if content.empty?

    enqueue(:handle_discord_message, author, content)
  rescue StandardError => e
    warn "[discord] event handling failed: #{e.class}: #{e.message}"
  end

  # Runs on this bridge's worker thread: the blocking part (RCON + routing).
  def handle_discord_message(author, content)
    # Discord → Factorio: broadcast via RCON game.print so in-game players
    # see Discord chatter. Server mode never captures S→C, so the sniffer
    # won't re-ingest its own relay (no loop).
    @rcon&.say("[Discord] #{author}: #{content}")
    # → chat relay: every (non-bot, on-channel) Discord message is published
    # as :discord; the sniffer's relay fans it to the agent (which decides via
    # its own trigger logic whether to answer). Discord skips :discord on_chat,
    # so this never echoes back to the channel.
    @emit_chat.call(:discord, author, content)
  rescue StandardError => e
    warn "[discord] relay failed: #{e.class}: #{e.message}"
  end

  # Stop the gateway + drain the capture-thread worker.
  def close
    @bot&.stop(true) if @bot&.respond_to?(:stop)
    close_events
  rescue StandardError => e
    warn "[discord] error on close: #{e.class}: #{e.message}"
  end

  private

  # Author names carry non-UTF-8 bytes from the API; scrub before they reach an
  # in-game print or a log line (mirrors HivemindAgent#clean_text).
  def clean_text(text)
    text.to_s.dup.force_encoding('UTF-8').scrub('?').strip
  end
end
