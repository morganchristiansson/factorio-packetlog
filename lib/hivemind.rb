# frozen_string_literal: true

require 'set'
require 'time'
require 'ruby_llm'
begin
  require 'ruby_llm-responses_api'
rescue LoadError
end
require_relative 'memory_store'
# RubyLLM tool classes (HivemindReply, RconQuery,
# ScheduleFollowUp, CancelFollowUp) live in hivemind_tools.rb.
require_relative 'hivemind_tools'
require_relative 'hivemind_prompts'
require_relative 'hivemind_persistence'
require_relative 'hivemind_compaction'
require_relative 'hivemind_followups'
require_relative 'log_tail'

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
  # OpenAI-compatible endpoint + model. Defaults, overridable per run via
  # HIVE_API_BASE / HIVE_MODEL (same family as HIVE_API_KEY) — e.g. pointing
  # the agent at a different provider without touching code.
  DEFAULT_API_BASE = 'https://opencode.ai/zen/go/v1'
  DEFAULT_MODEL    = 'deepseek-v4-flash'
  DEFAULT_PROVIDER = :openai

  # Models that are only available via the Responses API (Zen: /v1/responses).
  # Auto-selects :openai_responses when HIVE_PROVIDER is not set.
  RESPONSES_MODELS = %w[muse-spark-1.3-contributor-free].freeze
  def self.provider_for(model)
    return ENV['HIVE_PROVIDER'].to_sym if ENV['HIVE_PROVIDER'] && !ENV['HIVE_PROVIDER'].empty?
    return :openai_responses if RESPONSES_MODELS.include?(model) || model.to_s.downcase.include?('muse-spark')
    DEFAULT_PROVIDER
  end

  # Trigger phrases (case-insensitive, WHOLE-WORD match). Word-boundary
  # matching keeps short/vague phrases from firing inside other words:
  # "hm" must not page on "shmoose", and a player named "HivemindFan"
  # shouldn't page the real one just by chatting. Punctuation around a
  # phrase still matches ("Hivemind?", "hm, hello", "GOOD BOT!").
  # "good bot"/"goodbot" keep the conversation alive after a reply
  # (players who get an answer often say thanks — reply in character).
  TRIGGERS = ['hivemind', 'good bot', 'goodbot', 'hm', 'hive']
  # The agent's OWN name — its replies are queued with this as the player
  # and filtered from live prompts (they live in the conversation). Must
  # never become a compaction target: the agent is not a player.
  AGENT_NAME = 'hivemind'
  MIN_INTERVAL = 5.0            # min seconds between LLM calls from the SAME player (anti-spam)
  MAX_REPLY_LEN = 400           # truncate fallback replies (Factorio chat is ~500 chars)
  # Max UNREAD console lines kept between prompts. NOT a limit on what the
  # model sees (that's the conversation) — the queue drains on every
  # prompt, so this only bounds the case of a LONG silence with no
  # "hivemind" trigger, where thousands of lines would otherwise overflow
  # the next prompt's context. 1000 ≈ ~40k tokens, far beyond any real
  # gap; older lines are dropped with a warning if ever exceeded.
  HISTORY_SIZE = 1000
  # Recent-context budget (in content characters) kept AFTER a successful
  # compaction: the pass drops everything it saw EXCEPT the newest
  # stretch that fits this budget, so the session keeps recent
  # conversational flow instead of starting cold. Size-based, not count-
  # based: message sizes vary wildly (a turn can be one short line or a
  # multi-KB prompt dump).
  TRIM_TAIL_CHARS = 20_000
  HISTORY_LINE_LEN = 120        # per-line clip in the history context
  GREET_INTERVAL = 10.0         # min seconds between join greetings
  # Game-log watcher (factorio-current.log tail): lines carrying one of
  # these keys reach the agent. EVERY match is queued for the next prompt;
  # the first match within LOG_EVENT_INTERVAL additionally fires a dedicated
  # turn (so the model can react now) followed by an auto-compaction —
  # repeats inside the window stay queue-only.
  LOG_EVENT_KEYS = ['map reset:'].freeze
  LOG_EVENT_INTERVAL = 300.0    # min seconds between log-event turns (5 min)
  # Auto-compaction gate: only distill when the session holds at least
  # this many characters of conversation — 2x what post-compaction trim
  # KEEPS (TRIM_TAIL_CHARS). Below that there is little to compact and
  # the pass would be a wasted LLM call. Manual /compact ignores this.
  AUTO_COMPACTION_MIN_CHARS = TRIM_TAIL_CHARS * 2
  # Forget the CURRENT session (live conversation + queued console lines)
  # but KEEP the long-term memories. The next turn re-seeds the system
  # prompt (SOUL/KNOWLEDGE) and re-injects the online players' memories.
  # The sniffer's /compact command runs this right after a SUCCESSFUL
  # compaction, so a compacted session starts fresh (distill then wipe).
  # Since /forget and /clear were removed, /compact is the only interactive
  # trigger here — this method also stays callable to clear WITHOUT
  # distilling. Clears the persisted session file too.
  #
  # keep_unread_console: used by /compact. By wipe time the queue holds
  # ONLY lines that arrived mid-pass (the pass's own ask drained
  # everything older into its material) — wiping them would silently
  # lose events nobody has seen yet, so they carry into the fresh
  # session instead.
  def clear_session!(keep_unread_console: false)
    @mutex.synchronize do
      @chat&.reset_messages!
      @memories_sent.clear
      @session_players_mutex.synchronize { @session_players.clear }
      @console_mutex.synchronize do
        @console_queue.clear unless keep_unread_console
      end
      # Pending follow-ups belong to the session being wiped — drop them so
      # a stale timer can't inject a turn into the fresh session later.
      @followup_mutex.synchronize { @followups.clear }
      @chat&.with_instructions(system_prompt_with_memories)
    end
    persist! if @session_path
    true
  end

  # Post-compaction history trim (the /compact path — replaces the old
  # full wipe): drop exactly the messages the pass included, MINUS the
  # newest stretch that fits TRIM_TAIL_CHARS, which stays so the session
  # keeps recent conversational flow and context. Size-based, not count-
  # based: message sizes vary wildly (a turn can be one short line or a
  # multi-KB prompt dump). Console lines that arrived mid-pass are
  # untouched (the pass drained everything older into its material; these
  # were never seen). memories_sent is cleared so player memories
  # re-inject into the trimmed thread, and the system prompt IS refreshed:
  # the pass rewrote memory blobs on disk, and a trimmed thread is the one
  # sanctioned "fresh start" case for a prompt change (one bounded cache
  # rebuild). clear_session! remains for full resets.
  def trim_session_after_compaction!
    @mutex.synchronize do
      return false unless @chat
      msgs = @chat.messages
      floor = msgs.first&.role == :system ? 1 : 0   # system refreshed below
      included = [@compaction_included_count || 0, msgs.size].min
      # Walk backwards from the included boundary keeping the newest
      # messages that fit the char budget (always keep at least one).
      cut = included
      budget = TRIM_TAIL_CHARS
      while cut > floor && !(cut < included && budget.negative?)
        budget -= msgs[cut - 1].content.to_s.length + 1
        cut -= 1
      end
      # Never leave a kept :tool result dangling under a cut-away call —
      # the provider rejects the whole request. Advance past orphans.
      cut += 1 while cut < msgs.size && msgs[cut].role == :tool
      return true if cut <= floor
      msgs.slice!(floor...cut)
      log "session trimmed after compaction: dropped #{cut - floor} compacted messages, #{msgs.size - floor} kept"
      @memories_sent.clear
      @session_players_mutex.synchronize { @session_players.clear } # fresh session; post-compact lines re-populate
      @chat.with_instructions(system_prompt_with_memories)
      @persisted_messages = nil   # force re-serialization of the trimmed thread
    end
    persist! if @session_path
    true
  end

  # rcon: an RconClient (for game.print replies). Chat completions need
  # an API key: HIVE_API_KEY env by default; the api_key PARAM exists as
  # the specs' injection point ('sk-test') — production never passes it.
  # Model/endpoint resolve from HIVE_MODEL / HIVE_API_BASE or the class
  # defaults. session_path: false disables the session file;
  # memory_dir: false disables long-term memory (default memories/).
  # Resolved model id (HIVE_MODEL or default) — startup log reads this.
  attr_reader :model
  attr_reader :last_trigger
  attr_reader :memory_store

  # Reload-safe lock accessors: a HOT-RELOADED agent keeps its boot-time
  # ivars, so an agent object built by pre-split code lacks these. `||=`
  # fills them in on first use (benign race: worst case the very first
  # calls briefly hold different Mutex instances).
  def rate_mutex = (@rate_mutex ||= Mutex.new)
  def persist_mutex = (@persist_mutex ||= Mutex.new)

  def initialize(rcon:, api_key: nil, session_path: nil, memory_dir: nil)
    @rcon = rcon
    @last_ask_at = {}           # player → last trigger time (per-player anti-spam)
    @last_trigger = nil         # [player, message] of last handled trigger (for /retry)
    @last_greet = 0.0
    @last_log_event = 0.0       # last log-event turn time (LOG_EVENT_INTERVAL rate limit)
    @log_watcher = nil          # log-tail thread (survives hot reloads; revived if dead)
    @mutex = Mutex.new
    # Rate-limit state lives on ITS OWN mutex: the limiters run on the
    # PACKET THREAD (handle/greet_join), while @mutex is held across whole
    # LLM completions incl. retry sleeps (minutes during an outage). One
    # slow provider call must never stall packet processing.
    @rate_mutex = Mutex.new
    # Serializes session-file writes across persist!/persist_queue!
    # (worker threads AND the packet thread share one .tmp path).
    @persist_mutex = Mutex.new
    @chat = nil
    # Pending scheduled follow-ups (schedule_followup tool) + their mutex
    # and condition variable, so a single scheduler thread sleeps until the
    # next due time instead of polling. Entries are NAME-keyed (the model
    # picks a short stable key, e.g. 'prowl') and carry a MONOTONIC due (used
    # to fire) and an absolute unix due_at (persisted, so a restart re-arms
    # with the correct remaining delay). Scheduling an existing name again
    # REPLACES the entry (upsert — no cancel-first dance). Survive hot
    # reloads (agent persists in state); cleared by clear_session! — they
    # belong to the session.
    @followups = []
    @followup_mutex = Mutex.new
    @followup_cond = ConditionVariable.new
    # Console lines are a QUEUE drained on each prompt: append_history
    # enqueues (chat lines, join/leave events, the agent's own replies via
    # HivemindReply's on_sent / the fallback send_reply); unread_console drains
    # it, so each line reaches the model EXACTLY once. Delivered lines live on
    # inside the persisted conversation (each prompt embeds them), so no side
    # copy is kept.
    # Guarded by @console_mutex (separate from @mutex so the packet thread
    # never blocks on a slow LLM call). Survives hot reloads (the agent
    # persists in state).
    @console_queue = []
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
    # Players encountered THIS LLM session (since last compaction/reset).
    # Persisted with the session file; drives compaction targets so they
    # can't drift from what the session actually saw. Cleared on /compact
    # success and clear_session!; console lines afterwards re-populate it.
    # Own lock: marked from PACKET threads (must never wait on @mutex —
    # an in-flight LLM call would stall the capture loop).
    @session_players = Set.new
    @session_players_mutex = Mutex.new

    # ── LLM wiring. Provider is fixed (:openai — any OpenAI-compatible
    #    endpoint); model/base/key come from env or defaults. Missing key,
    #    missing gem, or bad provider config now raises — FactorioSniffer
    #    rescues and leaves @agent=nil (hard fail, no disabled object).
    llm_api_key = api_key || ENV['HIVE_API_KEY']
    @model = ENV.fetch('HIVE_MODEL', DEFAULT_MODEL)
    @provider = self.class.provider_for(@model)
    api_base = ENV.fetch('HIVE_API_BASE', DEFAULT_API_BASE)

    raise ArgumentError, 'no API key set (HIVE_API_KEY) — agent disabled' if llm_api_key.nil?

    RubyLLM.configure do |config|
      config.openai_api_base = api_base
      config.openai_api_key = llm_api_key
      config.default_model = @model
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

    # The endpoint's models (gpt-5.6-luna, glm-5.3, ...) are not in
    # RubyLLM's registry, so resolve with assume_model_exists: true and an
    # explicit provider. Fail loudly here (startup) rather than at ask time.
    @chat = RubyLLM.chat(
      model: @model,
      provider: @provider,
      assume_model_exists: true
    )
    @chat.with_instructions(system_prompt_with_memories)
    register_tools

    hook_chat_observers if @chat
    load_session if @session_path
    start_scheduler
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
    observe_chat(@chat)
  end

  # Shared observer body: the live chat hooks once at init; every
  # throwaway compaction chat gets its own registration (fresh object
  # per pass, so no duplicate-guard needed).
  def observe_chat(chat)
    chat.before_tool_call do |tool_call|
      args = trunc(JSON.generate(tool_call.arguments || {}))
      log "tool call: #{tool_call.name}(#{args})"
    end
    chat.after_tool_result do |result|
      # Halt = the reply tool already printed the reply (and callbacks fire
      # for halted tools too); skip to avoid echoing it a second time.
      next if defined?(RubyLLM::Tool::Halt) && result.is_a?(RubyLLM::Tool::Halt)
      content = result.respond_to?(:content) ? result.content : result
      log "tool result: #{trunc(content)}" unless content.to_s.empty?
    end
    chat.after_message do |message|
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
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # Packet thread — rate_mutex only, never @mutex (see initialize).
    rate_mutex.synchronize do
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

  # ── Game server log watcher ────────────────────────────────────

  # Tail the server's factorio-current.log (path from ServerDetect.log_path)
  # and feed interesting lines to the agent. The watcher thread lives on the
  # agent object, so it survives hot reloads; a dead thread is revived by
  # calling this again at the sniffer's reload seam. Idempotent.
  def ensure_log_watcher(path)
    return false if path.nil?
    return true if @log_watcher&.alive?
    unless File.file?(path)
      log "log watcher: #{path} not found — not watching"
      return false
    end
    @log_watcher = Thread.new do
      LogTail.follow(path) { |line| handle_log_line(line) }
    rescue StandardError => e
      log_error('log watcher died (restart the sniffer or hot-reload to revive)', e)
    end
    log "watching #{path} for /#{LOG_EVENT_KEYS.join('|')}/i"
    true
  end

  # One tailed log line. Only lines carrying a LOG_EVENT_KEY reach the
  # agent; everything else is dropped without parsing. A match is ALWAYS
  # queued (append_history) so it rides along with whatever prompt comes
  # next; the FIRST match in LOG_EVENT_INTERVAL additionally fires a
  # dedicated turn — react in chat if players would care — and then an
  # auto-compaction (a map reset closes a round: distill memories while
  # the session is fresh). Rate limit runs on rate_mutex (packet-style
  # thread — never touches @mutex). async:false runs the turn inline
  # (tests / synchronous callers).
  def handle_log_line(line, async: true)
    text = clean_text(strip_log_prefix(line))
    return if text.empty? || !LOG_EVENT_KEYS.any? { |k| text.downcase.start_with?(k) }
    append_history(nil, text)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    rate_mutex.synchronize do
      return if now - @last_log_event < LOG_EVENT_INTERVAL
      @last_log_event = now
    end
    return run_log_event_turn(text) unless async
    Thread.new { run_log_event_turn(text) }
    nil
  end

  # The dedicated reaction turn for one log event: build the prompt, get a
  # reply, then distill the round into long-term memory. Compaction is
  # skipped when there is little to compact (AUTO_COMPACTION_MIN_CHARS) or
  # a pass is already running (compact_memory! guards that itself).
  def run_log_event_turn(text)
    prompt = turn_prompt(
      "Game server log event: #{text}\n\n" \
      'React as fits: this event matters to the factory community — ' \
      'announce/comment in chat IF players would want to know, otherwise stay silent.',
      exclude: [nil, text]
    )
    begin
      send_reply(complete(prompt))
      # After reacting: distill the round into long-term memory. Skipped
      # when there is little to compact (AUTO_COMPACTION_MIN_CHARS) or a
      # pass is already running (compact_memory! guards that itself).
      compact_memory!('map reset') if auto_compaction_worthwhile?
    rescue StandardError => e
      log_error('log-event error', e)
    end
  end

  # Strip Factorio's log-line decoration so only the content is enqueued:
  # "   14.511 Script @__level__/reset.lua:284: map reset: …" →
  # "map reset: …".
  def strip_log_prefix(line)
    line.sub(/\A\s*[\d.]+\s+(?:Script\s+\S+:\s*)?/, '')
  end

  private

  # ── LLM plumbing ──────────────────────────────────────────────────

  # Re-register the tool set with FRESH instances before every ask. Tools
  # are registered once at creation otherwise; hot reloads (Ctrl-C `load`)
  # rebind the tool CLASSES, so stale instances would keep running old
  # code and new tools wouldn't appear until restart. with_tool replaces by
  # name, so this is idempotent and cheap.
  def register_tools(chat = @chat)
    return unless chat
    chat.with_tool(HivemindReply.new(rcon: @rcon, on_sent: ->(text) { append_history('hivemind', text) }))
    chat.with_tool(RconQuery.new(rcon: @rcon)) if defined?(RconQuery)
    chat.with_tool(ScheduleFollowUp.new(agent: self)) if defined?(ScheduleFollowUp)
    chat.with_tool(CancelFollowUp.new(agent: self)) if defined?(CancelFollowUp)
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
      response = ask_with_retry(@chat, prompt)
      text = response.respond_to?(:content) ? response.content.to_s : ''
      clean_reply(text)
    end
  ensure
    persist! if @session_path  # conversation changed — save for restart
  end

  # Provider failures worth an application-level retry. NOTE: RubyLLM's
  # built-in faraday-retry does NOT cover these: it only sees exceptions
  # raised inside its own middleware (network errors), while HTTP-status
  # failures are converted to RubyLLM errors by ErrorMiddleware, which
  # sits OUTSIDE the retry middleware in the stack — so they propagate
  # unretried (a single 503 kills the call even with max_retries set).
  RETRYABLE_LLM_ERRORS = [
    RubyLLM::ServiceUnavailableError,
    RubyLLM::ServerError,
    RubyLLM::OverloadedError,
    RubyLLM::RateLimitError,
    Faraday::TimeoutError,
    Faraday::ConnectionFailed
  ].freeze
  ASK_ATTEMPTS = 5
  ASK_RETRY_DELAYS = [5, 15, 30, 60].freeze # seconds before retries 1-4

  # Run one chat.ask with retries on transient provider failures. On a
  # failure the half-appended turn is sliced off first — chat.ask adds
  # the user message to the thread BEFORE the request goes out, so a raw
  # retry would duplicate the prompt and a final failure would persist
  # the orphan into the session file. Used by BOTH live asks (complete)
  # and memory compaction (whose ensure then strips nothing extra).
  def ask_with_retry(chat, prompt)
    attempt = 0
    begin
      start = chat.messages.size
      chat.ask(prompt)
    rescue *RETRYABLE_LLM_ERRORS => e
      attempt += 1
      chat.messages.slice!(start..)
      raise if attempt >= ASK_ATTEMPTS
      delay = ASK_RETRY_DELAYS[attempt - 1]
      log "LLM call failed (#{e.class.name.split('::').last}) — retrying #{attempt}/#{ASK_ATTEMPTS - 1} in #{delay}s"
      sleep delay
      retry
    end
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
    blobs = []
    soul = @memory_store.soul
    blobs << "=== SOUL ===\n#{soul}" if soul && !soul.strip.empty?
    knowledge = @memory_store.knowledge
    blobs << "=== KNOWLEDGE ===\n#{knowledge}" if knowledge && !knowledge.strip.empty?
    unless blobs.empty?
      parts << "Persistent memories (long-term; updated by memory compaction between sessions):\n#{blobs.join("\n\n")}"
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
    lines = []
    candidates = ([player].compact + online_player_list).reject { |n| @memories_sent.include?(n) }
    candidates.uniq.each do |name|
      mem = @memory_store.player(name)
      next unless mem && !mem.strip.empty?
      lines << "=== memory of #{name} ===\n#{mem}"
      @memories_sent << name
      mark_player_seen(name)
    end
    return '' if lines.empty?
    "Persistent player memories:\n#{lines.join("\n\n")}\n\n"
  end

  # Current online roster + per-player stats in ONE line (a fresh snapshot
  # per turn) — offline players are never listed (joins/leaves arrive as
  # console events instead), e.g.
  #   Online players (2): Alice: 5h12m (admin); Bob: 2h3m (afk 5m).
  def context_snapshot
    stats = player_stat_lines
    return "Online players (#{stats.size}): #{stats.join('; ')}." unless stats.empty?
    # No stats available (standalone agent, RCON down): fall back to the
    # packet-derived online roster's bare names.
    online = online_player_list
    return '' if online.empty?
    "Online players (#{online.size}): #{online.join(', ')}"
  end

  # Console lines not yet included in any prompt: drains the queue (each
  # line is sent EXACTLY once). `exclude:` skips one line that the caller
  # states explicitly (the trigger message, or the join event being
  # greeted). Agent replies (player == 'hivemind') are excluded too — they
  # are already in the conversation as assistant messages. Player names
  # are re-cleaned here: queued entries may predate the boundary cleaning
  # (persisted across hot reloads).
  # Mark a player as encountered in THIS LLM session. Called from every
  # encounter point: console lines (chat + join/leave) via append_history,
  # and memory injections via memory_prompt.
  def mark_player_seen(name)
    name = clean_text(name).strip
    return if name.empty? || name == HiveMindAgent::AGENT_NAME
    @session_players_mutex.synchronize { @session_players << name }
  end

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
  # bounded.
  def append_history(player, message)
    msg = clean_text(message)
    return if msg.empty?
    # Track who appeared in this LLM session (persisted; drives compaction
    # targets so they can't drift from what the session actually saw).
    if player
      mark_player_seen(player) unless player == HiveMindAgent::AGENT_NAME
    elsif msg =~ /\A(\S+) (?:joined|left) the game/
      mark_player_seen(Regexp.last_match(1))
    end
    @console_mutex.synchronize do
      @console_queue << [player, msg]
      if @console_queue.size > HISTORY_SIZE
        dropped = @console_queue.shift(@console_queue.size - HISTORY_SIZE)
        if dropped.any?
          warn "[hivemind] console history truncated: #{dropped.size} oldest lines dropped (no trigger in a while)"
        end
      end
    end
    persist_queue! if @session_path
  end

  # Names of players currently in-game, queried live from RCON. There is
  # deliberately no other source: every reply is DELIVERED via RCON too,
  # so if these queries fail nothing could be sent regardless. Names are
  # force-cleaned: wire-derived names may be binary-flagged and must not
  # taint the UTF-8 context snapshot.
  def online_player_list
    @rcon&.connected_players&.map { |p| clean_text(p[:name]) } || []
  rescue StandardError => e
    log_error('online-player query failed', e)
    []
  end

  # Attribute snapshot for a specific player ({name:, admin:, connected:,
  # online_time:} — LuaPlayer attrs via RCON), or nil when unknown.
  def player_attrs_for(name)
    return nil unless @rcon
    @rcon.player_attributes&.find { |p| p[:name] == name }
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

  # Player attribute lines for the system context, queried live from RCON
  # (LuaPlayer attrs — same reasoning as online_player_list: replies need
  # RCON anyway). Names are force-cleaned (see online_player_list).
  # One "Name: total-play-time (flags)" fragment per CONNECTED player.
  # Offline players are omitted entirely — the prompt covers who is online
  # right now; lifetime stats of everyone else are noise (and a growing
  # token cost on long-lived servers). Flags: admin; afk <time> while
  # connected and idle.
  def player_stat_lines
    list = @rcon ? (@rcon.player_attributes || []) : []
    list.select { |p| p[:connected] }.map do |p|
      time = format_ticks(p[:online_time_ticks] || p[:online_time])
      flags = []
      flags << 'admin' if p[:admin]
      # afk_time (ticks since their last action) — reset by any real input
      # action; shown as "afk 5m" when idle.
      afk = p[:afk_time_ticks] || p[:afk_time]
      flags << "afk #{format_ticks(afk)}" if afk && afk.to_i > 60
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

    msg = message.to_s.strip
    return false if msg.empty?
    return false unless trigger_match?(msg)

    # Per-player rate limiter: only the SAME player is throttled within
    # MIN_INTERVAL (spam collapse). Different players are never dropped —
    # their threads queue on the completion path, so each gets a sequential
    # turn whose prompt includes the previous Q&A (the shared chat object).
    # Runs on the PACKET THREAD: rate_mutex only — @mutex is held across
    # whole LLM completions (complete) and must never back-pressure packet
    # processing (regression: a hung provider call used to block every new
    # chat line here for minutes).
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    rate_mutex.synchronize do
      last = @last_ask_at[player]
      return false if last && now - last < MIN_INTERVAL
      @last_ask_at[player] = now
    end

    @last_trigger = [player, msg]

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

  public

  # ── Runtime model switching (/model, /try) ───────────────────────

  # Switch the persistent model at runtime (like HIVE_MODEL but live).
  # Uses RubyLLM::Chat#with_model which mutates the SAME chat in place —
  # messages, tools, and observers stay, only the model+provider changes.
  # Survives hot reloads (ivar) but not a full restart (reverts to ENV).
  def switch_model!(new_model)
    cleaned = clean_text(new_model.to_s).strip
    return "Error: model name empty — usage: /model <model-id>" if cleaned.empty?
    return "Model already #{@model}." if cleaned == @model
    begin
      @model = cleaned
      # Keep RubyLLM's global default in sync so compaction forks and any
      # future chats pick up the new model.
      begin
        RubyLLM.configure { |c| c.default_model = @model if c.respond_to?(:default_model=) }
      rescue StandardError
        nil
      end
      @provider = self.class.provider_for(@model)
      @mutex.synchronize do
        if @chat
          @chat.with_model(@model, provider: @provider, assume_exists: true)
        else
          @chat = RubyLLM.chat(model: @model, provider: @provider, assume_model_exists: true)
          @chat.with_instructions(system_prompt_with_memories)
          register_tools
          @observers_hooked = false
          hook_chat_observers
        end
      end
      persist! if @session_path
      log "model switched to #{@model}"
      "Model switched to #{@model}. Future replies will use it (persists until restart; reverts to HIVE_MODEL/DEFAULT on restart)."
    rescue StandardError => e
      log_error('model switch failed', e)
      "Error: failed to switch model: #{e.message}"
    end
  end

  # One-off dry-run: run a prompt with a different model WITHOUT touching
  # the real conversation, history, or game chat. Perfect for A/B testing
  # personality across models. Result is logged to the operator console only.
  # Pass explicit message or reuse last trigger. Never drains the console
  # queue or marks memories as sent.
  def try_model!(model, message = nil, player: 'tester')
    m = clean_text(model.to_s).strip
    return "Error: model name empty — usage: /try <model> [message]" if m.empty?
    if message.nil? || clean_text(message.to_s).strip.empty?
      trig = @last_trigger
      return "No previous trigger to try (no hivemind message yet) — pass a message: /try <model> <message>" unless trig
      player, message = trig
    end
    msg = clean_text(message.to_s).strip
    msg = "hivemind #{msg}" unless trigger_match?(msg)
    # Build prompt without mutating real state (queue / memories_sent).
    saved_queue = @console_mutex.synchronize { @console_queue.dup }
    saved_memories = @memories_sent.dup
    saved_players = @session_players_mutex.synchronize { @session_players.dup }
    prompt = nil
    begin
      prompt = turn_prompt(
        "In-game chat from #{player}: #{msg}\n\n" \
        "Answer the player's question or continue the conversation. " \
        "Keep it under #{MAX_REPLY_LEN} characters. Plain text only — " \
        'no markdown, no code blocks, no emoji.',
        exclude: [player, msg],
        player: player
      )
    ensure
      @console_mutex.synchronize { @console_queue.replace(saved_queue) }
      @memories_sent.replace(saved_memories)
      @session_players_mutex.synchronize { @session_players.replace(saved_players) } if saved_players
    end
    snapshot = @mutex.synchronize { @chat ? @chat.messages.dup : [] }
    Thread.new do
      begin
        tmp_provider = self.class.provider_for(m)
        tmp = RubyLLM.chat(model: m, provider: tmp_provider, assume_model_exists: true)
        tmp.messages.replace(snapshot.dup)
        register_tools(tmp)
        observe_chat(tmp)
        start_t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
        response = ask_with_retry(tmp, prompt)
        elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_t
        text = clean_reply(response.respond_to?(:content) ? response.content.to_s : '')
        # Try to extract usage from last assistant message if available.
        usage = ''
        if tmp.messages.last
          usage = usage_line(tmp.messages.last)
        end
        if text.empty?
          log "[try #{m}] (#{elapsed.round(1)}s) → (no reply — model stayed silent)#{usage}"
        else
          log "[try #{m}] (#{elapsed.round(1)}s) → #{text}#{usage}"
        end
        # Also log tool result if reply came via tool (Halt has empty content).
        # The observe_chat callbacks already logged tool calls/results for tmp,
        # so operator sees full trace.
      rescue StandardError => e
        log_error("try (#{m}) failed", e)
      end
    end
    "[try] Running '#{msg}' with model #{m} — one-off, not persisted, not sent to game. See [hivemind] logs for result..."
  end

  # Generic dry-run with arbitrary prompt (used by /eval tooling or /try).
  def dry_run!(model, prompt_text)
    try_model!(model, prompt_text, player: 'eval')
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
