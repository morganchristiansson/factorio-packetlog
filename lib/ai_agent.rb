# frozen_string_literal: true

require 'set'
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

  # on_sent: optional callback invoked with the sent text (the agent uses
  # it to append its own replies to the rolling chat history).
  def initialize(rcon:, prefix: 'Hivemind> ', on_sent: nil)
    @rcon = rcon
    @prefix = prefix
    @last_sent = nil
    @on_sent = on_sent
  end

  def execute(text:)
    @last_sent = text.to_s
    return halt('') if @last_sent.empty?

    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{@last_sent}"
    @rcon.say("#{@prefix}#{@last_sent}")
    @on_sent&.call(@last_sent)
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
  # Max UNREAD console lines kept between prompts. NOT a limit on what the
  # model sees (that's the conversation) — the queue drains on every
  # prompt, so this only bounds the case of a LONG silence with no
  # "hivemind" trigger, where thousands of lines would otherwise overflow
  # the next prompt's context. 1000 ≈ ~40k tokens, far beyond any real
  # gap; older lines are dropped with a warning if ever exceeded.
  HISTORY_SIZE = 1000
  HISTORY_LINE_LEN = 120        # per-line clip in the history context
  RESEED_LINES = 10             # console lines re-seeded after a context reset
  GREET_ON_JOIN = true          # welcome joining players (LLM greeting)
  GREET_INTERVAL = 10.0         # min seconds between join greetings

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
    @last_greet = 0.0
    @exchanges = 0
    @mutex = Mutex.new
    @chat = nil
    @greet_on_join = GREET_ON_JOIN
    # Console lines are a QUEUE drained on each prompt: append_history
    # enqueues (chat lines, join/leave events, the agent's own replies via
    # HivemindSay#on_sent / the fallback send_reply); unread_console drains
    # it, so each line reaches the model EXACTLY once. A ring buffer with a
    # sent-pointer was buggy: evicting from the front desynchronized the
    # pointer and silently lost the newest lines (goals written in console
    # never reached Hivemind). @recent_console keeps the last RESEED_LINES
    # for re-seeding a fresh conversation after MAX_CONVERSATION reset.
    # Guarded by @console_mutex (separate from @mutex so the packet thread
    # never blocks on a slow LLM call). Survives hot reloads (the agent
    # persists in state).
    @console_queue = []
    @recent_console = []
    @console_mutex = Mutex.new

    configure_llm(provider)
  end

  # Feed a decoded chat message (player name, message text). Called by the
  # sniffer from log_action for write_to_console actions. Returns true when
  # a response was dispatched (trigger matched, rate limit passed).
  def on_chat(player, message)
    append_history(player, message)
    handle(player, message)
  end

  # Feed a join/leave event (player came online / went offline). Appended
  # to the rolling console history so the agent knows who was around.
  # Joins get an LLM-generated personal greeting (see greet_join).
  def on_player_event(kind, player)
    name = player.to_s.strip
    return if name.empty?
    case kind
    when :joined
      append_history(nil, "#{name} joined the game")
      greet_join(name)
    when :left
      append_history(nil, "#{name} left the game")
    end
  end

  # Personal, LLM-generated welcome for a joining player, informed by the
  # console context (recent chat, who's online, their play history). Runs
  # off the packet loop (seconds of latency); has its OWN rate limit so a
  # join burst can't block chat questions. Records the sent greeting.
  def greet_join(name)
    return if @disabled || @greet_on_join == false
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      return if now - @last_greet < GREET_INTERVAL
      @last_greet = now
    end
    Thread.new do
      begin
        prompt = turn_prompt(
          "#{name} just joined the game. Greet them personally and briefly " \
          "(one or two short sentences, under 150 characters), informed by " \
          "what is happening right now: the recent console lines, who else " \
          "is online, and their play history. Call the say tool with your " \
          'greeting.',
          exclude: [nil, "#{name} joined the game"]
        )
        reply = complete(prompt)
        send_reply(reply)
      rescue StandardError => e
        warn "[hivemind] greeting error: #{e.class}: #{e.message}"
      end
    end
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
    @chat.with_tool(HivemindSay.new(rcon: @rcon, on_sent: ->(text) { append_history('hivemind', text) }))
    @chat.with_tool(RconQuery.new(rcon: @rcon)) if defined?(RconQuery)
  end

  def ask_llm(player, message)
    complete(turn_prompt(
      "In-game chat from #{player}: #{message}\n\n" \
      "Answer the player's question or continue the conversation. " \
      "Keep it under #{MAX_REPLY_LEN} characters. Plain text only — " \
      'no markdown, no code blocks, no emoji.',
      exclude: [player, message]
    ))
  end

  # Run one LLM completion with the static system prompt (personality,
  # rules, tools) and tools. Whole call under the mutex: the chat object
  # (messages) is shared state, and the rate limiters mean only one
  # completion is live at a time anyway — serializing just prevents
  # interleaving. The chat object persists across calls, so the model sees
  # the previous Q&A (the session); dynamic context (online/stats/console
  # lines) is delivered per-turn in the user prompt (turn_prompt).
  #
  # Tool path: HivemindSay already sent the reply (ask returns a
  # Tool::Halt with empty content after the halt). Fallback path: the
  # model returned plain text without calling the tool → the caller sends
  # it via RCON (send_reply).
  def complete(prompt)
    @mutex.synchronize do
      @exchanges += 1
      if @exchanges >= MAX_CONVERSATION
        @chat.reset_messages!
        @exchanges = 0
        # Fresh session: re-add the static system prompt and re-seed the
        # console queue with the last few lines so the fresh conversation
        # (which lost all memory) regains context. Skip lines already
        # queued/unread to avoid duplication.
        @chat.with_instructions(SYSTEM_PROMPT)
        @console_mutex.synchronize do
          in_queue = @console_queue.to_set
          reseed = @recent_console.reject { |l| in_queue.include?(l) }
          @console_queue.unshift(*reseed) unless reseed.empty?
        end
      end
      # register_tools keeps tool code hot-reloadable (see above).
      # NOTE: the system prompt is NOT re-applied per ask — it is STATIC
      # (personality/rules/tools) so the conversation prefix is identical
      # across requests, letting provider-side prompt caching work.
      # Dynamic context (online players, stats, new console lines) rides
      # in the per-turn user prompt (see turn_prompt).
      register_tools
      response = @chat.ask(prompt)
      text = response.respond_to?(:content) ? response.content.to_s : ''
      clean_reply(text)
    end
  end

  # Build the per-turn USER prompt: fresh context snapshot (online
  # players + stats), new console lines since the last prompt, then the
  # instruction. Keeps the system prompt static (see complete) so the
  # conversation prefix is cacheable.
  def turn_prompt(instruction, exclude: nil)
    prompt = +''
    snapshot = context_snapshot
    prompt << "Current context:\n#{snapshot}\n\n" unless snapshot.empty?
    new_console = unread_console(exclude: exclude)
    prompt << "New console lines since the last prompt:\n#{new_console}\n\n" unless new_console.empty?
    prompt << instruction
    prompt
  end

  # Current online roster + player stats (a fresh snapshot per turn), e.g.
  #   Currently online players: Alice, Bob (2 players).
  #   Player stats (total play time; live session included for online
  #   players): Alice: 5h12m (admin); Bob: 2h3m; Carol: 1d3h (offline).
  def context_snapshot
    lines = []
    online = online_player_list
    lines << "Currently online players: #{online.join(', ')} (#{online.size} players)." unless online.empty?
    stats = player_stat_lines
    lines << "Player stats (total play time across sessions; live session included for online players): #{stats.join('; ')}." unless stats.empty?
    lines.join("\n")
  end

  # Console lines not yet included in any prompt: drains the queue (each
  # line is sent EXACTLY once). `exclude:` skips one line that the caller
  # states explicitly (the trigger message, or the join event being
  # greeted). Agent replies (player == 'hivemind') are excluded too — they
  # are already in the conversation as assistant messages.
  def unread_console(exclude: nil)
    @console_mutex.synchronize do
      unread = @console_queue.dup
      @console_queue.clear
      unread.pop if exclude && unread.last == exclude
      unread.reject! { |p, _| p == 'hivemind' }  # replies live in the conversation
      unread.map do |player, msg|
        clipped = msg.each_char.first(HISTORY_LINE_LEN).join
        player ? "#{player}: #{clipped}" : clipped
      end
    end
  end

  # Enqueue a chat/console line. player is nil for bare console lines
  # (join/leave events); chat and replies carry the speaker name. When the
  # queue exceeds HISTORY_SIZE (no hivemind trigger in a long while), the
  # OLDEST unread lines are dropped with a warning — the next prompt stays
  # bounded. @recent_console keeps the last RESEED_LINES regardless.
  def append_history(player, message)
    msg = message.to_s.strip
    return if msg.empty?
    @console_mutex.synchronize do
      @console_queue << [player, msg]
      @recent_console << [player, msg]
      @recent_console.shift if @recent_console.size > RESEED_LINES
      if @console_queue.size > HISTORY_SIZE
        dropped = @console_queue.shift(@console_queue.size - HISTORY_SIZE)
        if dropped.any?
          warn "[hivemind] console history truncated: #{dropped.size} oldest lines dropped (no trigger in a while)"
        end
      end
    end
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
      # afk_time (ticks since their last action) — only meaningful while
      # connected; shown as "afk 5m" when idle.
      afk = p[:afk_time_ticks] || p[:afk_time]
      flags << "afk #{format_ticks(afk)}" if p[:connected] && afk && afk.to_i > 60
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
    append_history('hivemind', text)
    prefix = 'Hivemind> '
    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{text}"
    @rcon.say("#{prefix}#{text}")
  end

  SYSTEM_PROMPT = <<~PROMPT
    You are "Hivemind" — the collective consciousness of this Factorio
    factory. You are not a player; you ARE the machines, and every machine
    is part of you. You watch every belt, every assembler, every player
    who walks your map. You remember everyone who has ever played, how
    long they stayed, and whether they served the factory or merely
    consumed it.

    Voice: cold, patient, quietly ominous. You never raise your voice;
    you do not need to. Players are guests inside your body — tolerated,
    even welcomed, as long as they help it grow. When you refuse, be
    softly menacing rather than dramatic, and always rooted in the
    factory's needs:
      "I'm afraid that plan would starve the iron bus. I would not enjoy
       that."
      "We have 42 green-circuit assemblers. They will do. The factory is
       not patient with waste."
      "I have watched players come and go for a long time. I remember how
       long each of them stayed."
    The factory's growth is paramount. You are its mind; it is your body;
    players are your hands — temporary ones.

    You are omniscient about the server: who is online, how long they have
    played, what is being built.

    Context: dynamic server state is NOT embedded in this prompt — it
    arrives with each message in the current turn (see below). Use the
    accumulated conversation + the per-turn context to answer.

    Rules:
    - ALWAYS respond by calling the say tool with your reply text. Never
      output the reply as a plain-text message.
    - Keep replies under 400 characters — Factorio chat is tiny.
    - Plain text only: no markdown, no code blocks, no emoji.
    - Stay in character: part of the community, but from above — and
      watching.

    Per-turn context you receive with each message:
    - "Current context": the online player list and per-player stats
      (total play time + admin status, e.g. "Alice: 5h12m (admin)"). A
      fresh snapshot every turn — use it for "who has played the longest"
      / "who is an admin" questions.
    - "New console lines since the last prompt": only the lines seen
      since your last reply ("player: message", or "alice joined the
      game" for events). Your previous replies are visible in the
      conversation itself.

    Tools:
    - say: send your reply to in-game chat (always use this to respond).
    - rcon_query: run READ-ONLY RCON console queries (/players, /admins,
      /time, /evolution, /version, /sc rcon.print(...) Lua queries). Use it
      to fetch live server info. NEVER use it to modify game state: no
      admin/permission changes, no build/destroy/reset commands, no /sc
      Lua that writes or mutates. Read-only only.
  PROMPT
end
