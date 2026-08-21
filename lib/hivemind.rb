# frozen_string_literal: true

require 'set'
require 'time'
require 'ruby_llm'
require_relative 'memory_store'
# RubyLLM tool classes (HivemindReply, RconQuery, WriteMemories,
# ScheduleFollowUp, CancelFollowUp) live in hivemind_tools.rb.
require_relative 'hivemind_tools'
require_relative 'hivemind_prompts'
require_relative 'hivemind_persistence'
require_relative 'hivemind_compaction'
require_relative 'hivemind_followups'

# HiveMind agent — an LLM persona that lives inside the Factorio sniffer.
#
# Input: in-game chat decoded from the packet stream. The sniffer calls
# #on_chat(player, message) from log_action for every write_to_console
# action (see FactorioProtocol.decode_chat), so no server-side changes or
# mods are needed.
#
# Trigger: a chat message containing "hivemind" (case-insensitive) gets an
# LLM response. The response is sent back to in-game chat through the
# reply tool (HivemindReply) (RCON game.print) so everyone sees it. A rolling
# conversation context is kept in the LLM chat object so follow-ups make
# sense; it is only cleared by /compact (a new session).
#
# LLM: ruby_llm against a configurable OpenAI-compatible endpoint (default
# https://opencode.ai/zen/go/v1). More tools (RCON queries, packet-decoder
# lookups) can be added the same way as HivemindReply — they get access to
# the rcon client / the sniffer's item/player DBs via the tool constructor.
class HiveMindAgent
  include HiveMindPrompts     # DEFAULT_SOUL / SYSTEM_PROMPT / COMPACTION_PROMPT
  include HiveMindPersistence  # session file: load_session / persist!
  include HiveMindCompaction   # long-term memory distillation (/compact)
  include HiveMindFollowUps    # scheduled follow-ups + scheduler thread
  # OpenAI-compatible endpoint + model (hardcoded — no flags/env overrides).
  DEFAULT_API_BASE = 'https://opencode.ai/zen/go/v1'
  DEFAULT_MODEL    = 'deepseek-v4-flash'

  # Trigger phrases (case-insensitive, WHOLE-WORD match). Word-boundary
  # matching keeps short/vague phrases from firing inside other words:
  # "hm" must not page on "shmoose", and a player named "HivemindFan"
  # shouldn't page the real one just by chatting. Punctuation around a
  # phrase still matches ("Hivemind?", "hm, hello", "GOOD BOT!").
  # "good bot"/"goodbot" keep the conversation alive after a reply
  # (players who get an answer often say thanks — reply in character).
  TRIGGERS = ['hivemind', 'good bot', 'goodbot', 'hm']
  MIN_INTERVAL = 5.0            # min seconds between LLM calls from the SAME player (anti-spam)
  MAX_REPLY_LEN = 400           # truncate fallback replies (Factorio chat is ~500 chars)
  # Max UNREAD console lines kept between prompts. NOT a limit on what the
  # model sees (that's the conversation) — the queue drains on every
  # prompt, so this only bounds the case of a LONG silence with no
  # "hivemind" trigger, where thousands of lines would otherwise overflow
  # the next prompt's context. 1000 ≈ ~40k tokens, far beyond any real
  # gap; older lines are dropped with a warning if ever exceeded.
  HISTORY_SIZE = 1000
  HISTORY_LINE_LEN = 120        # per-line clip in the history context
  RESEED_LINES = 10             # console lines kept in @recent_console (for memory compaction)
  GREET_INTERVAL = 10.0         # min seconds between join greetings
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

  # Long-term memory on? (memory dir configured — compaction enabled).
  def memory_enabled?
    !@memory_store.nil? && @memory_store.enabled?
  end

  # Forget the CURRENT session (live conversation + queued console lines)
  # but KEEP the long-term memories. The next turn re-seeds the system
  # prompt (SOUL/KNOWLEDGE) and re-injects the online players' memories.
  # The sniffer's /compact command runs this right after a SUCCESSFUL
  # compaction, so a compacted session starts fresh (distill then wipe).
  # Since /forget and /clear were removed, /compact is the only interactive
  # trigger here — this method also stays callable to clear WITHOUT
  # distilling. Clears the persisted session file too.
  def clear_session!
    @mutex.synchronize do
      @chat&.reset_messages!
      @memories_sent.clear
      @console_mutex.synchronize do
        @console_queue.clear
        @recent_console.clear
      end
      # Pending follow-ups belong to the session being wiped — drop them so
      # a stale timer can't inject a turn into the fresh session later.
      @followup_mutex.synchronize { @followups.clear }
      @chat&.with_instructions(system_prompt_with_memories)
    end
    persist! if @session_path
    true
  end

  # rcon: an RconClient (for game.print replies). Chat completions need
  # an API key: HIVE_API_KEY env (the agent's key — there is deliberately
  # no --ai-api-key/OPENAI_API_KEY fallback; no key = agent disabled).
  # session_path: false disables the session file; memory_dir: false
  # disables long-term memory (default memories/). model / provider /
  # api_base are HARDCODED to the defaults (no flags, no env overrides).
  def initialize(rcon:, api_key: nil, session_path: nil, memory_dir: nil)
    @rcon = rcon
    @last_ask_at = {}           # player → last trigger time (per-player anti-spam)
    @last_greet = 0.0
    @mutex = Mutex.new
    @chat = nil
    # Pending scheduled follow-ups (schedule_followup tool) + their mutex
    # and condition variable, so a single scheduler thread sleeps until the
    # next due time instead of polling. Entries carry a MONOTONIC due (used
    # to fire) and an absolute unix due_at (persisted, so a restart re-arms
    # with the correct remaining delay). Survive hot reloads (agent persists
    # in state); cleared by clear_session! — they belong to the session.
    @followups = []
    @followup_mutex = Mutex.new
    @followup_cond = ConditionVariable.new
    @followup_seq = 0
    # Console lines are a QUEUE drained on each prompt: append_history
    # enqueues (chat lines, join/leave events, the agent's own replies via
    # HivemindReply's on_sent / the fallback send_reply); unread_console drains
    # it, so each line reaches the model EXACTLY once. A ring buffer with a
    # sent-pointer was buggy: evicting from the front desynchronized the
    # pointer and silently lost the newest lines (goals written in console
    # never reached Hivemind). @recent_console keeps the last RESEED_LINES
    # for memory compaction (compaction_material).
    # Guarded by @console_mutex (separate from @mutex so the packet thread
    # never blocks on a slow LLM call). Survives hot reloads (the agent
    # persists in state).
    @console_queue = []
    @recent_console = []
    @console_mutex = Mutex.new
    # Session persistence: console history + LLM conversation are saved to
    # disk so a full RESTART (not just Ctrl-C) can resume — packets while
    # stopped are lost, but the context carries over. Default file
    # hivemind-session.json (HIVE_SESSION overrides); pass session_path:
    # false to disable.
    @session_path = session_path == false ? nil : (session_path || ENV['HIVE_SESSION'] || 'hivemind-session.json')

    # Long-term memory (keyed blobs: soul / knowledge / <player>) — the
    # compaction layer that lets a NEW session carry over what Hivemind
    # learned. Default memories/; memory_dir: false disables. The default
    # SOUL is seeded on first run.
    @memory_store = MemoryStore.new(memory_dir)
    @memory_store.seed(MemoryStore::SOUL_KEY, HiveMindPrompts::DEFAULT_SOUL) if @memory_store.enabled?
    # Player memories already delivered to the model THIS session (join
    # greetings / chat turns). A fresh process resets it, so a new session
    # re-seeds memories on first contact; within a session the memory
    # already sits in the conversation after the first delivery.
    @memories_sent = Set.new

    # ── LLM wiring, inlined. Endpoint/model/provider are HARDCODED constants;
    #    the only variable input is the API key (param or HIVE_API_KEY env).
    #    The rescues cover THIS block only: a missing gem or a provider
    #    rejection disables the agent instead of killing the sniffer, while
    #    any other init bug (memory store, session path) still raises loudly.
    llm_api_key = api_key || ENV['HIVE_API_KEY']
    begin
      RubyLLM.configure do |config|
        config.openai_api_base = DEFAULT_API_BASE
        config.openai_api_key = llm_api_key if llm_api_key
        config.default_model = DEFAULT_MODEL
        # Read timeout ceiling for EVERY request (faraday). Raised from 60s
        # because memory compaction sends the WHOLE conversation (hundreds of
        # messages — the input-token-cache reuse is the point) and the model
        # can legitimately take 1-2min to answer such a large prompt; 60s
        # killed it with Net::ReadTimeout (session kept, compaction failed).
        # Normal chat replies respond in seconds, so 300 only moves the
        # ceiling, not the latency.
        config.request_timeout = 300
        config.max_retries = 1
        # RubyLLM defaults to sending the system prompt as role `developer`
        # (OpenAI's newer convention) on OpenAI-compatible endpoints; some
        # endpoints (e.g. Console Go models) only accept `system` and reject
        # the request. Use `system` explicitly.
        config.openai_use_system_role = true
        config.log_level = Logger::WARN if config.respond_to?(:log_level=)
      end

      if llm_api_key.nil? || llm_api_key.empty?
        warn '[hivemind] no API key set (HIVE_API_KEY) — agent disabled'
        @disabled = true
      else
        # The endpoint's models (gpt-5.6-luna, glm-5.3, ...) are not in
        # RubyLLM's registry, so resolve with assume_model_exists: true and an
        # explicit provider. Fail loudly here (startup) rather than at ask time.
        @chat = RubyLLM.chat(
          model: DEFAULT_MODEL,
          provider: :openai,
          assume_model_exists: true
        )
        @chat.with_instructions(system_prompt_with_memories)
        register_tools
      end
    rescue LoadError => e
      warn "[hivemind] ruby_llm not installed (bundle install) — agent disabled: #{e.message}"
      @disabled = true
    rescue StandardError => e
      log_error('LLM init failed — agent disabled', e)
      @disabled = true
    end

    hook_chat_observers if @chat
    load_session if @session_path && !@disabled
    start_scheduler unless @disabled
  end

  # ── Console logging / LLM-run observation ─────────────────────────

  # Observe the LLM run so the console shows WHAT the model does, not
  # just the reply tool's final send: reasoning/thinking, tool calls and
  # their results, any plain assistant text. Registered ONCE at init —
  # the chat object survives hot reloads and re-registering per ask
  # would stack duplicate observers. (Closures hit the CURRENT class
  # definitions after a hot reload via normal dynamic dispatch.)
  def hook_chat_observers
    return unless @chat
    return if @observers_hooked
    @observers_hooked = true
    @chat.before_tool_call do |tool_call|
      args = trunc(JSON.generate(tool_call.arguments || {}))
      log "tool call: #{tool_call.name}(#{args})"
    end
    @chat.after_tool_result do |result|
      # Halt = the reply tool already printed the reply (and callbacks fire
      # for halted tools too); skip to avoid echoing it a second time.
      next if defined?(RubyLLM::Tool::Halt) && result.is_a?(RubyLLM::Tool::Halt)
      content = result.respond_to?(:content) ? result.content : result
      log "tool result: #{trunc(content)}" unless content.to_s.empty?
    end
    @chat.after_message do |message|
      next unless message.role == :assistant
      thinking = message.thinking
      if thinking.is_a?(RubyLLM::Thinking) && !thinking.text.to_s.empty?
        log "reasoning: #{trunc(thinking.text)}"
      end
      content = message.content.to_s
      unless content.empty?
        log "assistant: #{trunc(content)}#{usage_line(message)}"
      else
        # Pure tool-call assistant message (no spoken text) — the reply
        # arrives via the reply tool, but its request still has usage worth
        # showing (how many input tokens the provider cache absorbed).
        log "assistant (tool call)#{usage_line(message)}" if message.tool_call?
      end
    end
  end

  # Token usage for an assistant message, as a short suffix on the console
  # line, e.g. " (2.4k in, 1.8k cached, 400 out)". Reflects ONE request's
  # usage as reported by the provider (ruby_llm's Message#tokens): input
  # is the UNCACHED input (prompt_tokens minus cache hits/writes), cached
  # the cache-read hits, written the cache-write tokens). Omitted when the
  # provider reports none.
  def usage_line(message)
    return '' unless message
    parts = []
    inp = message.input_tokens
    parts << "#{inp} in" if inp
    cached = message.cached_tokens.to_i
    parts << "#{cached} cached" if cached > 0
    written = message.cache_creation_tokens.to_i
    parts << "#{written} written" if written > 0
    out = message.output_tokens.to_i
    parts << "#{out} out" if out > 0
    think = message.thinking_tokens.to_i
    parts << "#{think} think" if think > 0
    parts.empty? ? '' : " (#{parts.join(', ')})"
  end

  def log(msg)
    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] #{msg}"
  end

  # Error line + FULL backtrace: the trace's depth is exactly what an
  # operator needs when e.g. the provider rejects a request — the top
  # line alone is never enough.
  def log_error(context, e)
    warn "#{Time.now.strftime('%H:%M:%S')}  [hivemind] #{context}: #{e.class}: #{e.message}"
    Array(e.backtrace).each { |line| warn "    #{line}" }
  end

  # Normalize a value for console display: squeeze runs of blanks, trim.
  # max clips the LENGTH when given (with an ellipsis); max=nil shows the
  # FULL value — used by the LLM-run observers so an operator sees exactly
  # what the model reasoned, asked, and answered.
  def trunc(obj, max = nil)
    s = obj.to_s.gsub(/[ \t]+/, ' ').strip
    return s if max.nil? || s.length <= max
    "#{s[0...max]}…"
  end

  # Feed a decoded chat message (player name, message text). Called by the
  # sniffer from log_action for write_to_console actions. Returns true when
  # a response was dispatched (trigger matched, rate limit passed).
  # Player name AND message are cleaned: a Unicode name must not stay
  # binary-flagged — interpolating it into the UTF-8 prompt raises
  # Encoding::CompatibilityError inside turn_prompt.
  #
  # Slash-prefixed lines are COMMANDS, not chat — Factorio routes anything
  # starting with `/` to the command system (admin/teleport/permission
  # outputs, /shout echoes, etc.), and in-game chat can never begin with
  # `/`. They're excluded entirely: never queued into the console context
  # and never trigger the agent.
  def on_chat(player, message)
    player = clean_text(player)
    message = clean_text(message)  # invalid UTF-8 from the wire is safe here
    return if message.start_with?('/')
    append_history(player, message)
    handle(player, message)
  end

  # Feed a join/leave event (player came online / went offline). Appended
  # to the rolling console history so the agent knows who was around.
  # Joins include the player's total play time from RCON (online_time,
  # ticks — formatted as days/hours like the context snapshot) and get an
  # LLM-generated personal greeting (see greet_join).
  def on_player_event(kind, player)
    name = clean_text(player)
    return if name.empty?
    case kind
    when :joined
      # ONE attrs query drives both the console line (play time) and the
      # greeting instruction (play time + admin status).
      attrs = player_attrs_for(name)
      played = attrs ? format_ticks(attrs[:online_time_ticks] || attrs[:online_time]) : nil
      # The exact join line is passed to greet_join as its exclude, so the
      # event reaches the model only once (via this enqueue).
      line = played ? "#{name} joined the game (#{played} played)" : "#{name} joined the game"
      append_history(nil, line)
      greet_join(name, line, attrs)
    when :left
      append_history(nil, "#{name} left the game")
    when :timeout
      # No clean PeerDisconnect was seen — heartbeat just stopped (crash,
      # power/network loss). The player may re-join; the LLM should know the
      # roster changed either way.
      append_history(nil, "#{name} timed out (no heartbeat) — likely crashed or disconnected; may re-join")
    end
  end

  # Personal, LLM-generated welcome for a joining player, informed by the
  # console context (recent chat, who's online, their play history). Runs
  # off the packet loop (seconds of latency); has its OWN rate limit so a
  # join burst can't block chat questions. Records the sent greeting.
  # `line` is the exact join console line (greet_join's exclude must match
  # it so the event reaches the model only via the instruction), `attrs`
  # the player's attribute snapshot (play time + admin) or nil. The
  # player's long-term memory is injected into the greeting prompt (once
  # per session) so the welcome is informed by who they are.
  def greet_join(name, line, attrs = nil)
    return if @disabled
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
          "is online, and their play history" \
          "#{join_facts(attrs)}. " \
          'Call the reply tool with your greeting.',
          exclude: [nil, line],
          player: name
        )
        reply = complete(prompt)
        send_reply(reply)
      rescue StandardError => e
        log_error('greeting error', e)
      end
    end
  end

  private

  # ── LLM plumbing ──────────────────────────────────────────────────

  # Re-register the tool set with FRESH instances before every ask. Tools
  # are registered once at creation otherwise; hot reloads (Ctrl-C `load`)
  # rebind the tool CLASSES, so stale instances would keep running old
  # code and new tools wouldn't appear until restart. with_tool replaces by
  # name, so this is idempotent and cheap.
  def register_tools
    return unless @chat
    @chat.with_tool(HivemindReply.new(rcon: @rcon, on_sent: ->(text) { append_history('hivemind', text) }))
    @chat.with_tool(RconQuery.new(rcon: @rcon)) if defined?(RconQuery)
    @chat.with_tool(ScheduleFollowUp.new(agent: self)) if defined?(ScheduleFollowUp)
    @chat.with_tool(CancelFollowUp.new(agent: self)) if defined?(CancelFollowUp)
  end

  def ask_llm(player, message)
    complete(turn_prompt(
      "In-game chat from #{player}: #{message}\n\n" \
      "Answer the player's question or continue the conversation. " \
      "Keep it under #{MAX_REPLY_LEN} characters. Plain text only — " \
      'no markdown, no code blocks, no emoji.',
      exclude: [player, message],
      player: player
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
  # Tool path: the reply tool already sent the reply (ask returns a
  # Tool::Halt with empty content after the halt). Fallback path: the
  # model returned plain text without calling the tool → the caller sends
  # it via RCON (send_reply).
  def complete(prompt)
    @mutex.synchronize do
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
  ensure
    persist! if @session_path  # conversation changed — save for restart
  end

  # Build the per-turn USER prompt: fresh context snapshot (online
  # players + stats), new console lines since the last prompt, persistent
  # memories (SOUL/KNOWLEDGE always, the relevant player's memory once per
  # session), then the instruction. Keeps the system prompt static (see
  # complete) so the conversation prefix is cacheable.
  #
  # Every fragment is run through clean_text BEFORE it hits the `<<`
  # concatenations: prompt is UTF-8, and appending a binary-flagged string
  # with non-ASCII bytes raises Encoding::CompatibilityError. All inputs
  # are scrubbed at their boundaries too (on_chat/on_player_event/online
  # providers), so this is belt-and-braces for anything that slips through
  # (e.g. queued lines persisted across a hot reload by an older build).
  # `player:` marks the player this turn is about (the one who triggered,
  # or the one being greeted) — their memory is injected if not already
  # delivered this session.
  def turn_prompt(instruction, exclude: nil, player: nil)
    prompt = +''
    snapshot = context_snapshot
    prompt << "Current context:\n#{clean_text(snapshot)}\n\n" unless snapshot.empty?
    new_console = unread_console(exclude: exclude)
    prompt << "New console lines since the last prompt:\n#{new_console}\n\n" unless new_console.empty?
    memories = memory_prompt(player: player)
    prompt << memories unless memories.empty?
    prompt << clean_text(instruction)
    prompt
  end

  # Build the conversational system prompt: the static mechanics (SYSTEM_PROMPT)
  # + the current GLOBAL memories (SOUL = personality, KNOWLEDGE = durable
  # facts) read from the memory store. Applied at conversation creation, on
  # conversation reset, on session load, and after compaction. Keeping the
  # globals in the SYSTEM prompt (not the per-turn user prompt) means the
  # prefix is identical between compactions — provider-side prompt caching
  # keeps working, and their cost is paid once per conversation, not once
  # per turn. (The per-turn user prompt carries only the relevant PLAYER
  # memory — see memory_prompt.)
  def system_prompt_with_memories
    parts = [HiveMindPrompts::SYSTEM_PROMPT]
    if memory_enabled?
      blobs = []
      soul = @memory_store.soul
      blobs << "=== SOUL ===\n#{soul}" if soul && !soul.strip.empty?
      knowledge = @memory_store.knowledge
      blobs << "=== KNOWLEDGE ===\n#{knowledge}" if knowledge && !knowledge.strip.empty?
      unless blobs.empty?
        parts << "Persistent memories (long-term; updated by memory compaction between sessions):\n#{blobs.join("\n\n")}"
      end
    end
    parts.join("\n\n")
  end

  # Player memories injected into the per-turn USER prompt (SOUL and
  # KNOWLEDGE ride in the system prompt — see system_prompt_with_memories).
  # The turn's player (the one who triggered, or the one being greeted)
  # gets their memory; on a fresh session (process start / /compact /
  # conversation reset) the memories of ALL currently-online players are
  # seeded too — joins alone can't reach players who were already connected
  # when the session began. Each player is delivered ONCE per session (the
  # dedup set clears on a fresh session, so the next one re-seeds).
  def memory_prompt(player: nil)
    return '' unless memory_enabled?
    lines = []
    candidates = ([player].compact + online_player_list).reject { |n| @memories_sent.include?(n) }
    candidates.uniq.each do |name|
      mem = @memory_store.player(name)
      next unless mem && !mem.strip.empty?
      lines << "=== memory of #{name} ===\n#{mem}"
      @memories_sent << name
    end
    return '' if lines.empty?
    "Persistent player memories:\n#{lines.join("\n\n")}\n\n"
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
  # are already in the conversation as assistant messages. Player names
  # are re-cleaned here: queued entries may predate the boundary cleaning
  # (persisted across hot reloads).
  def unread_console(exclude: nil)
    @console_mutex.synchronize do
      unread = @console_queue.dup
      @console_queue.clear
      unread.pop if exclude && unread.last == exclude
      unread.reject! { |p, _| p == 'hivemind' }  # replies live in the conversation
      unread.map do |player, msg|
        clipped = msg[0, HISTORY_LINE_LEN]
        player ? "#{clean_text(player)}: #{clipped}" : clipped
      end
    end
  end

  # scrub('?') guards against invalid UTF-8 from the wire (strip/regex on
  # malformed bytes raises ArgumentError). Force UTF-8 FIRST so binary-
  # flagged bytes are also cleaned, not just invalid UTF-8-flagged ones.
  def clean_text(text)
    text.to_s.dup.force_encoding('UTF-8').scrub('?').strip
  end

  # Enqueue a chat/console line. player is nil for bare console lines
  # (join/leave events); chat and replies carry the speaker name. When the
  # queue exceeds HISTORY_SIZE (no hivemind trigger in a long while), the
  # OLDEST unread lines are dropped with a warning — the next prompt stays
  # bounded. @recent_console keeps the last RESEED_LINES regardless.
  def append_history(player, message)
    msg = clean_text(message)
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
    persist_queue! if @session_path
  end

  # Names of players currently in-game. Primary source: the sniffer's
  # packet-derived online tracking (FactorioSniffer#online_players); if no
  # provider is wired (agent used standalone), query RCON directly. Names
  # are force-cleaned: packet-derived names are binary-flagged and must not
  # taint the UTF-8 context snapshot.
  def online_player_list
    if @online_provider
      list = @online_provider.call
      return [] if list.nil?
      return list.map { |p| clean_text(p[:name]) } if list.first.is_a?(Hash)
      return list.map { |n| clean_text(n) }
    end
    @rcon&.connected_players&.map { |p| clean_text(p[:name]) } || []
  rescue StandardError => e
    log_error('online-player query failed', e)
    []
  end

  # Attribute snapshot for a specific player ({name:, admin:, connected:,
  # online_time:} from RCON, or the mirrored provider's online_time_ticks
  # form), or nil when unknown. Primary source: RCON (LuaPlayer attrs,
  # includes the live session); falls back to the mirrored provider
  # snapshot when RCON is unavailable or the player isn't in its attrs yet.
  def player_attrs_for(name)
    if @rcon
      attrs = @rcon.player_attributes
      if attrs
        hit = attrs.find { |p| p[:name] == name }
        return hit if hit
      end
    end
    if @player_stats_provider
      list = @player_stats_provider.call || []
      hit = list.find { |p| p[:name] == name }
      return hit if hit
    end
    nil
  rescue StandardError => e
    log_error("player attrs query failed for #{name}", e)
    nil
  end

  # Facts about a joining player for the greeting instruction, from ONE
  # attrs snapshot: " — they have played 2d3h in total and are an admin"
  # (play time and admin status; unknown parts omitted). The model gets
  # both so it knows how to place the newcomer.
  def join_facts(attrs)
    return '' unless attrs
    facts = []
    ticks = attrs[:online_time_ticks] || attrs[:online_time]
    facts << "have played #{format_ticks(ticks)} in total" if ticks
    facts << 'are an admin' if attrs[:admin] == true
    facts << 'are not an admin' if attrs[:admin] == false
    return '' if facts.empty?
    " — they #{facts.join(' and ')}"
  end

  # Player attribute lines for the system context. Primary source: the
  # sniffer's mirrored PlayerAttrs (packet-maintained, seeded from RCON);
  # if the provider yields nothing (attrs not seeded yet / query failed),
  # fall back to a direct RCON query. Names are force-cleaned (see
  # online_player_list).
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
      "#{clean_text(p[:name])}: #{time}#{suffix}"
    end
  rescue StandardError => e
    log_error('player-stats query failed', e)
    []
  end

  # 60 ticks per second → compact human duration, e.g. 43_200 → "12m",
  # 1_836_000 → "8h30m", 5_184_000 → "1d0h", 11_016_000 → "2d3h".
  # A trailing "0m" is dropped once days/hours are shown ("2d3h0m" is
  # noise; minutes only appear when non-zero or as the largest unit).
  def format_ticks(ticks)
    s = ticks.to_i / 60
    days = s / 86_400
    hours = (s % 86_400) / 3600
    mins = (s % 3600) / 60
    parts = []
    parts << "#{days}d" if days > 0
    parts << "#{hours}h" if days > 0 || hours > 0
    parts << "#{mins}m" if mins > 0 || (days == 0 && hours == 0)
    parts.join
  end

  # Strip markdown-ish noise and clamp length. String#[] counts CHARACTERS
  # on UTF-8 strings, so no manual each_char dance is needed.
  def clean_reply(text)
    text.gsub('`', '').gsub(/[*_]{1,2}/, '')[0, MAX_REPLY_LEN].strip
  end

  # ── Trigger / rate limit / reply ──────────────────────────────────

  # Any of the trigger phrases (TRIGGERS) — case-insensitive whole-word
  # match, so "Hivemind?", "good bot!" and "hm, hello" all ping the agent
  # while "shmoose" or "HivemindFan" can't accidentally do it.
  def trigger_match?(msg)
    TRIGGERS.any? { |t| msg.match?(/\b#{Regexp.escape(t)}\b/i) }
  end

  def handle(player, message)
    return false if @disabled

    msg = message.to_s.strip
    return false if msg.empty?
    return false unless trigger_match?(msg)

    # Per-player rate limiter: only the SAME player is throttled within
    # MIN_INTERVAL (spam collapse). Different players are never dropped —
    # their threads queue on the complete mutex, so each gets a sequential
    # turn whose prompt includes the previous Q&A (the shared chat object).
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      last = @last_ask_at[player]
      return false if last && now - last < MIN_INTERVAL
      @last_ask_at[player] = now
    end

    # LLM calls run off the sniffer's packet loop (seconds of latency).
    Thread.new do
      begin
        reply = ask_llm(player, msg)
        send_reply(reply)
      rescue StandardError => e
        log_error("error responding to #{player}", e)
      end
    end
    true
  end

  # Fallback reply path: only fires when the model answered with plain text
  # instead of calling the reply tool (HivemindReply). Lua-quoted so arbitrary text
  # can't break out of the /sc game.print(...) string.
  def send_reply(text)
    return if text.nil? || text.empty?
    append_history('hivemind', text)
    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{text}"
    @rcon.say("#{HivemindReply::REPLY_PREFIX}#{text}")
  end
end
