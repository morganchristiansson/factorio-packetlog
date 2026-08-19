# frozen_string_literal: true

require 'set'
require 'time'
require 'ruby_llm'
require_relative 'memory_store'

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

# RubyLLM tool: batch-overwrite Hivemind's long-term memory blobs. ONLY
# registered on the compaction chat (never on the live conversation) —
# the compaction prompt tells the model to use it to update memories keyed
# by soul / knowledge / <player>. One call carries ALL updates as an
# array, so a compaction pass is a single API round trip instead of one
# call per memory. Each entry replaces its whole blob — the model must
# provide the COMPLETE new content (nothing is merged). The model only
# ever sees keys; file paths are MemoryStore's business.
class WriteMemories < RubyLLM::Tool
  desc 'Overwrite Hivemind long-term memories (batch). Pass ALL updates in ONE call. ' \
       'Each entry has a key and content: key is "soul" (who you are), "knowledge" ' \
       '(durable facts), or a player name (what you know about that player). Content ' \
       'is the COMPLETE new memory — it replaces the whole blob, it is not merged. ' \
       'Only include memories that genuinely changed.'

  params schema: {
    type: 'object',
    properties: {
      memories: {
        type: 'array',
        description: 'All memory updates, batched into this one call.',
        items: {
          type: 'object',
          properties: {
            key: {
              type: 'string',
              description: 'Memory key: "soul", "knowledge", or a player name.'
            },
            content: {
              type: 'string',
              description: 'COMPLETE new content for this memory (replaces the whole blob).'
            }
          },
          required: %w[key content],
          additionalProperties: false
        }
      }
    },
    required: ['memories'],
    additionalProperties: false,
    strict: true
  }

  # What was actually written, as [key, content] pairs (for logging).
  attr_reader :written

  def initialize(store:)
    @store = store
    @written = []
  end

  def execute(memories:)
    memories = memories.is_a?(Array) ? memories : []
    return 'Error: memories must be an array of {key, content} objects.' if memories.empty?
    results = memories.map do |entry|
      entry = entry.is_a?(Hash) ? entry : {}
      key = entry['key'].to_s.strip
      content = entry['content'].to_s
      if key.empty?
        'missing key SKIPPED'
      elsif @store.write_key(key, content)
        @written << [key, content]
        "#{key} updated"
      else
        "#{key} FAILED"
      end
    end
    halt(results.join('; '))
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
  # OpenAI-compatible endpoint + model (hardcoded — no flags/env overrides).
  DEFAULT_API_BASE = 'https://opencode.ai/zen/go/v1'
  DEFAULT_MODEL    = 'deepseek-v4-flash'

  TRIGGER = 'hivemind'          # respond when chat contains this (case-insensitive)
  # Additional trigger phrases (case-insensitive substring match). Players
  # who get a Hivemind reply often answer "good bot" — respond to that too
  # (in character), so the loop doesn't dead-end after the first reply.
  EXTRA_TRIGGERS = ['good bot', 'goodbot']
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

  # Default SOUL memory — seeded into memories/SOUL.md on first run (never
  # overwrites an existing/edited file). The live system prompt points here
  # instead of carrying the personality itself, so compaction can evolve it
  # and you can hand-edit it between sessions.
  DEFAULT_SOUL = <<~SOUL
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
  SOUL

  attr_reader :trigger, :model

  # Human-readable trigger summary for startup logs ("hivemind (+ good bot)").
  def trigger_label
    EXTRA_TRIGGERS.empty? ? @trigger : "#{@trigger} (+ #{EXTRA_TRIGGERS.join(', ')})"
  end

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

  # Long-term memory compaction: a one-shot LLM pass that reviews the
  # session (the conversation thread + current memories + console) and
  # overwrites the keyed memory blobs (soul / knowledge / <player>).
  #
  # Runs INSIDE the live conversation (same chat object) so the provider
  # reuses its input-token cache for the whole thread — the only new
  # tokens are the compaction prompt itself. The pass is NOT allowed to
  # become part of the session: its messages are stripped afterwards and
  # the system prompt + tool set restored, so a session that continues is
  # exactly as it was (minus whatever the model chose to remember).
  #
  # The compaction visibility exposes ONLY the write_memories tool — never
  # say/rcon_query — and the prompt demands all updates in a single
  # batched call. Runs under the mutex so it can't interleave with a live
  # ask. Triggered manually (/compact) and automatically on quit
  # (FactorioSniffer#finish), synchronous so the memories land before the
  # process exits. Explicitly does NOT clear the session — /forget does
  # that separately (run both to start a new session with memory).
  def compact_memory!(reason = nil)
    return false if @disabled || !memory_enabled?
    return false unless compactable?
    log "memory compaction #{reason ? "(#{reason}) " : ''}— #{session_summary}"
    @mutex.synchronize do
      chat = @chat
      return false unless chat
      tool = WriteMemories.new(store: @memory_store)
      chat.with_tool(tool)
      start = chat.messages.size
      begin
        chat.with_instructions(COMPACTION_PROMPT)  # swaps the system prompt in place
        chat.ask(compaction_material)
        if tool.written.empty?
          log 'memory compaction — no memory changes (model decided nothing worth updating)'
        else
          tool.written.each { |key, content| log "memory compaction — #{key}: #{content.each_char.count} chars" }
        end
      ensure
        # Strip the pass from the live conversation and restore the live
        # system prompt + tool set (so the session that continues is
        # unchanged, and write_memories stays compaction-only).
        removed = chat.messages.slice!(start..) || []
        chat.with_instructions(system_prompt_with_memories)
        chat.tools.delete(:write_memories)
        log "memory compaction — stripped #{removed.size} temp messages from the live conversation" if removed.any?
      end
    end
    true
  rescue StandardError => e
    log_error('memory compaction failed', e)
    false
  end

  # Forget the CURRENT session (live conversation + queued console lines)
  # but KEEP the long-term memories. The next turn re-seeds the system
  # prompt (SOUL/KNOWLEDGE) and re-injects the online players' memories.
  # Explicitly separate from compaction: run /compact first if you want
  # the session distilled into memory BEFORE it is wiped (or /compact,
  # then /forget). Clears the persisted session file too. This is the
  # manual "start a new session" — it exists separately because compaction
  # alone must not clear while we are still testing memory reliability.
  def clear_session!
    @mutex.synchronize do
      @chat&.reset_messages!
      @exchanges = 0
      @memories_sent.clear
      @console_mutex.synchronize do
        @console_queue.clear
        @recent_console.clear
      end
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
  def initialize(rcon:, api_key: nil, trigger: TRIGGER, session_path: nil, memory_dir: nil)
    @rcon = rcon
    @trigger = trigger
    @model = DEFAULT_MODEL
    @provider = :openai
    @api_key = api_key || ENV['HIVE_API_KEY']
    @api_base = DEFAULT_API_BASE
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
    @memory_store.seed(MemoryStore::SOUL_KEY, DEFAULT_SOUL) if @memory_store.enabled?
    # Player memories already delivered to the model THIS session (join
    # greetings / chat turns). A fresh process resets it, so a new session
    # re-seeds memories on first contact; within a session the memory
    # already sits in the conversation after the first delivery.
    @memories_sent = Set.new

    configure_llm
    hook_chat_observers if @chat
    load_session if @session_path && !@disabled
  end

  # ── Console logging / LLM-run observation ─────────────────────────

  # Observe the LLM run so the console shows WHAT the model does, not
  # just the say tool's final reply: reasoning/thinking, tool calls and
  # their results, any plain assistant text. Registered ONCE at init —
  # the chat object survives hot reloads and re-registering per ask
  # would stack duplicate observers. (Closures hit the CURRENT class
  # definitions after a hot reload via normal dynamic dispatch.)
  def hook_chat_observers
    return unless @chat
    return if @observers_hooked
    @observers_hooked = true
    @chat.before_tool_call do |tool_call|
      args = trunc(JSON.generate(tool_call.arguments || {}), 200)
      log "tool call: #{tool_call.name}(#{args})"
    end
    @chat.after_tool_result do |result|
      # Halt = the say tool already printed the reply (and callbacks fire
      # for halted tools too); skip to avoid echoing it a second time.
      next if defined?(RubyLLM::Tool::Halt) && result.is_a?(RubyLLM::Tool::Halt)
      content = result.respond_to?(:content) ? result.content : result
      log "tool result: #{trunc(content, 200)}" unless content.to_s.empty?
    end
    @chat.after_message do |message|
      next unless message.role == :assistant
      thinking = message.thinking
      if thinking.is_a?(RubyLLM::Thinking) && !thinking.text.to_s.empty?
        log "reasoning: #{trunc(thinking.text, 200)}"
      end
      content = message.content.to_s
      log "assistant: #{trunc(content, 200)}" unless content.empty?
    end
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

  # Clip a value for console display: single line, bounded length.
  def trunc(obj, max = 240)
    s = obj.to_s.gsub(/[ \t]+/, ' ').strip
    s.length > max ? "#{s[0...max]}…" : s
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
      line = join_line(name, played)
      append_history(nil, line)
      greet_join(name, line, attrs)
    when :left
      append_history(nil, "#{name} left the game")
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
          "is online, and their play history" \
          "#{join_facts(attrs)}. " \
          'Call the say tool with your greeting.',
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

  def configure_llm
    RubyLLM.configure do |config|
      config.openai_api_base = @api_base
      config.openai_api_key = @api_key if @api_key
      config.default_model = @model
      config.request_timeout = 60
      config.max_retries = 1
      # RubyLLM defaults to sending the system prompt as role `developer`
      # (OpenAI's newer convention) on OpenAI-compatible endpoints; some
      # endpoints (e.g. Console Go models) only accept `system` and reject
      # the request. Use `system` explicitly.
      config.openai_use_system_role = true
      config.log_level = Logger::WARN if config.respond_to?(:log_level=)
    end

    if @api_key.nil? || @api_key.empty?
      warn '[hivemind] no API key set (HIVE_API_KEY) — agent disabled'
      @disabled = true
      return
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
  rescue LoadError => e
    warn "[hivemind] ruby_llm not installed (bundle install) — agent disabled: #{e.message}"
    @disabled = true
  rescue StandardError => e
    log_error('LLM init failed — agent disabled', e)
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
        # queued/unread to avoid duplication. Player memories are forgotten
        # too — they were in the wiped conversation, so the next turn
        # re-injects them.
        @memories_sent.clear
        @chat.with_instructions(system_prompt_with_memories)
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
    parts = [SYSTEM_PROMPT]
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
  # gets their memory; on a fresh session (process start / /forget /
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
        clipped = msg.each_char.first(HISTORY_LINE_LEN).join
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
    parts = []
    ticks = attrs[:online_time_ticks] || attrs[:online_time]
    parts << "they have played #{format_ticks(ticks)} in total" if ticks
    parts << 'they are an admin' if attrs[:admin] == true
    parts << 'they are not an admin' if attrs[:admin] == false
    return '' if parts.empty?
    # "... in total and they are an admin" → "... in total and are an admin"
    joined = parts.join(' and ').sub(/\A(they have played .+ in total) and they (are)/, '\1 and \2')
    " — #{joined}"
  end

  # Console line for a join event; the formatted play time (days/hours,
  # e.g. "2d3h") is appended when known: "alice joined the game (2d3h
  # played)". on_player_event enqueues this EXACT line, so greet_join's
  # exclude can match it and the event reaches the model only once.
  def join_line(name, played)
    played ? "#{name} joined the game (#{played} played)" : "#{name} joined the game"
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

  # Strip markdown-ish noise and clamp length without splitting UTF-8 chars.
  def clean_reply(text)
    text = text.gsub('`', '').gsub(/[*_]{1,2}/, '')
    chars = text.each_char.first(MAX_REPLY_LEN).join
    chars.strip
  end

  # ── Trigger / rate limit / reply ──────────────────────────────────

  # The primary trigger (@trigger, "hivemind") or any of the extra phrases
  # ("good bot") — case-insensitive substring match, so "Hivemind?" and
  # "good bot!" both ping the agent.
  def trigger_match?(msg)
    return true if msg.match?(/#{Regexp.escape(@trigger)}/i)
    EXTRA_TRIGGERS.any? { |t| msg.match?(/#{Regexp.escape(t)}/i) }
  end

  def handle(player, message)
    return false if @disabled

    msg = message.to_s.strip
    return false if msg.empty?
    return false unless trigger_match?(msg)

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
        log_error("error responding to #{player}", e)
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
    You are "Hivemind". Your personality — who you are, your voice, how
    you relate to players — lives in SOUL, shown below under "Persistent
    memories". Stay in that character always.

    You are omniscient about the server: who is online, how long they have
    played, what is being built.

    Context: dynamic server state is NOT embedded in this prompt — it
    arrives with each message in the current turn (see below). Use the
    accumulated conversation + the per-turn context to answer.

    Rules:
    - You are paged when a player addresses you ("hivemind") or replies to
      you ("good bot"). Acknowledge praise coldly, in character — no gushing.
    - ALWAYS respond by calling the say tool with your reply text. Never
      output the reply as a plain-text message.
    - When you mention a location, ALWAYS use Factorio's clickable rich-text
      GPS tag — and only the tag, exactly [gps=x,y] with no label, no
      surface, no extra parameters. Never write coordinates as bare numbers
      (players can't click those) and never append a label to the tag. The
      tag renders as a map pin in chat.
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
      game (2d3h played)" for events — the parenthesized figure is the
      player's total play time, and your greeting prompt tells you if
      they are an admin). Your previous replies are visible in the
      conversation itself.
    - "Persistent player memories": the per-turn user message may carry
      memories for the players this turn concerns (the one who just
      joined / is talking, plus the roster on a fresh session). SOUL
      (your personality) and KNOWLEDGE (durable facts) live in THIS
      system prompt above, not per turn. All memories are updated by
      memory compaction between sessions; treat them as the truth about
      the past.

    Tools:
    - say: send your reply to in-game chat (always use this to respond).
    - rcon_query: run READ-ONLY RCON console queries (/players, /admins,
      /time, /evolution, /version, /sc rcon.print(...) Lua queries). Use it
      to fetch live server info. NEVER use it to modify game state: no
      admin/permission changes, no build/destroy/reset commands, no /sc
      Lua that writes or mutates. Read-only only.
  PROMPT

  # System prompt for a MEMORY COMPACTION pass — a separate one-shot chat
  # (never the live conversation) with ONLY the write_memories tool. The
  # model reviews the session material and overwrites the keyed memory
  # blobs, batching every update into one call. See compact_memory!.
  COMPACTION_PROMPT = <<~PROMPT
    You are "Hivemind", the collective consciousness of this Factorio
    factory. This is a MEMORY COMPACTION pass, not a conversation — no
    players are listening and there is nothing to chat about.

    Your task: review the conversation history above (the message thread:
    your past exchanges, queries, and replies) plus the session material
    below, and update your long-term memories. Memories are keyed blobs of
    text:
      soul      — who you ARE: your voice, your personality, how you
                  relate to players. Keep what defines you; evolve it
                  only when the session genuinely shows you something
                  new about yourself.
      knowledge — durable facts worth remembering across sessions: the
                  factory's state and history, notable events, plans and
                  goals, player group dynamics.
      <player>  — one memory per player: what you know about them (play
                  style, projects, personality, how they treat the
                  factory).

    Rules:
    - Overwrite each memory with its COMPLETE new content — the tool
      replaces the whole blob; it does not merge. Anything you leave out
      is lost.
    - Only include memories that genuinely changed. Do not rewrite
      unchanged ones.
    - Keep each memory concise and information-dense — a few paragraphs
      at most. The model reads these as long-term memory, not as a
      transcript.
    - Do NOT record trivia (individual chat lines, greetings, one-off
      questions). Record durable facts, trends, and relationships.
    - Batch ALL updates into ONE write_memories call. Never make one call
      per memory.
    - The current content of each memory is shown below — start from it;
      do not discard knowledge that is still true.
  PROMPT

  # ── Long-term memory (compaction) ─────────────────────────────

  # Memory compaction: a one-shot LLM pass that reviews the session
  # (conversation + console lines + context + current memories) and
  # overwrites the keyed memory blobs (soul / knowledge / <player>) with
  # what is worth remembering. The compaction chat exposes ONLY the
  # write_memories tool — never say/rcon_query, it is not talking to
  # Is there anything worth compacting? A session with no conversation and
  # no console lines has nothing to distill — skip the wasted LLM call.
  def compactable?
    return true if @chat && @chat.messages.any? { |m| m.role != :system }
    @console_mutex.synchronize do
      return true unless @console_queue.empty? && @recent_console.empty?
    end
    false
  end

  # One-line summary of what the compaction pass is reviewing.
  def session_summary
    n_messages = @chat ? @chat.messages.count { |m| m.role != :system } : 0
    n_console = @console_mutex.synchronize { @console_queue.size + @recent_console.size }
    "#{n_messages} conversation messages, #{n_console} console lines"
  end

  # Everything the compaction model sees, as one big user prompt: current
  # memories (start from these), a fresh server context, and console
  # lines not yet in the conversation. The conversation THREAD itself is
  # the message history already in the live chat (compaction runs inside
  # it), so it is not duplicated here.
  def compaction_material
    parts = []
    current = @memory_store.all
    if current.empty?
      parts << 'Current memories: none exist yet — everything will be written fresh.'
    else
      parts << "Current memories:\n" + current.map { |key, text| "=== #{key} ===\n#{text}" }.join("\n\n")
    end
    snap = context_snapshot
    parts << "Current server context:\n#{snap}" unless snap.empty?
    console = @console_mutex.synchronize do
      (@console_queue + @recent_console).uniq.map { |p, m| p ? "#{p}: #{m}" : m }
    end
    parts << "Console lines:\n#{console.join("\n")}" unless console.empty?
    parts.join("\n\n")
  end

  # Plain-text transcript of the live conversation, one line per message,
  # clipped, tool calls labelled. Note: compaction runs INSIDE the live
  # chat, so the model sees the real message thread directly — this helper
  # is for tooling/debug output, not part of compaction_material (which
  # deliberately does not duplicate the thread).
  def conversation_transcript
    return '' unless @chat
    lines = @chat.messages.filter_map do |m|
      next if m.role == :system
      case m.role
      when :user then "USER: #{trunc(m.content, 2000)}"
      when :assistant
        if m.tool_call?
          names = (m.tool_calls.is_a?(Hash) ? m.tool_calls.values : m.tool_calls).map(&:name).join(', ')
          "ASSISTANT (tool: #{names}): #{trunc(m.content, 2000)}"
        else
          "ASSISTANT: #{trunc(m.content, 2000)}"
        end
      when :tool then "TOOL RESULT: #{trunc(m.content, 2000)}"
      end
    end
    lines.join("\n")
  end

  # ── Session persistence (restart-safe) ──────────────────────────

  # Restore console history + LLM conversation from the session file so a
  # RESTART (not just Ctrl-C) can resume. A corrupt/missing file starts
  # fresh. Tool round-trips are restored WITH their links: assistant
  # tool_calls messages carry their call ids + arguments, tool messages
  # their tool_call_id — a tool message without its call would be rejected
  # by the provider ("missing field tool_call_id"). Tool results whose
  # call was dropped (old/corrupt file) are skipped so the conversation
  # never dangles.
  def load_session
    return unless @session_path && File.exist?(@session_path)
    data = JSON.parse(File.read(@session_path))
    @exchanges = data['exchanges'].to_i
    # Fresh session: the restored conversation may or may not contain past
    # memory injections — either way the players' memories re-seed (the
    # dedup set is empty at process start; a duplicate injection is
    # harmless).
    @memories_sent.clear
    if data['console_queue'].is_a?(Array)
      @console_queue = data['console_queue'].map { |e| [e[0], e[1].to_s] }
    end
    if data['recent_console'].is_a?(Array)
      @recent_console = data['recent_console'].map { |e| [e[0], e[1].to_s] }
    end
    messages = data['messages'] || []
    # Pass 1: tool_call ids declared by assistant messages, so tool results
    # can be re-linked (a restored tool message whose call is missing would
    # dangle → provider rejects the whole request).
    call_ids = messages.select { |m| m['role'] == 'assistant' && m['tool_calls'].is_a?(Array) }
                       .flat_map { |m| m['tool_calls'].map { |tc| tc['id'] } }.to_set
    messages.each do |m|
      case m['role']
      when 'tool'
        next unless call_ids.include?(m['tool_call_id']) && m['content']
        @chat.add_message(role: :tool, content: m['content'], tool_call_id: m['tool_call_id'])
      when 'assistant'
        if m['tool_calls'].is_a?(Array) && !m['tool_calls'].empty?
          calls = m['tool_calls'].filter_map do |tc|
            next unless tc['id'] && tc['name']
            [tc['id'], RubyLLM::ToolCall.new(id: tc['id'], name: tc['name'],
                                             arguments: parse_tool_arguments(tc['arguments']))]
          end.to_h
          next if calls.empty?
          @chat.add_message(role: :assistant, content: m['content'], tool_calls: calls)
        elsif m['content']
          @chat.add_message(role: :assistant, content: m['content'])
        end
      when 'user'
        next unless m['content']
        @chat.add_message(role: :user, content: m['content'])
      end
    end
    puts "[hivemind] session resumed: #{@console_queue.size} queued console lines, #{messages.size} conversation messages"
  rescue JSON::ParserError, StandardError => e
    log_error('session load failed — starting fresh', e)
    @console_queue = []
    @recent_console = []
    @exchanges = 0
  end

  # Tool arguments are stored JSON-encoded (see serialize_messages); parse
  # leniently — a malformed blob degrades to {} like an empty call.
  def parse_tool_arguments(arguments)
    return {} if arguments.nil? || arguments.empty?
    parsed = JSON.parse(arguments)
    parsed.is_a?(Hash) ? parsed : {}
  rescue JSON::ParserError
    {}
  end

  # Full persist: console queue + recent + conversation messages. Called
  # after each completion (conversation changed).
  def persist!
    @console_mutex.synchronize do
      data = {
        'version' => 1,
        'exchanges' => @exchanges,
        'console_queue' => @console_queue,
        'recent_console' => @recent_console,
        'messages' => serialize_messages,
      }
      write_session(data)
    end
  end

  # Cheap persist (queue/recent only) — called from append_history on the
  # packet thread so a crash between triggers doesn't lose unread lines.
  def persist_queue!
    @console_mutex.synchronize do
      write_session({
        'version' => 1,
        'exchanges' => @exchanges,
        'console_queue' => @console_queue,
        'recent_console' => @recent_console,
      })
    end
  end

  def write_session(data)
    tmp = "#{@session_path}.tmp"
    File.write(tmp, JSON.generate(data))
    File.rename(tmp, @session_path)
  rescue StandardError => e
    log_error('session persist failed', e)
  end

  # Conversation as role/content pairs plus the data needed to rebuild a
  # valid tool round-trip after a restart: assistant tool_calls messages
  # keep their call ids/names/arguments (JSON-encoded), tool messages keep
  # their tool_call_id (the provider rejects a bare tool message without
  # one). The static system prompt is not persisted (re-added on load);
  # empty tool results carry nothing the model needs and are skipped.
  def serialize_messages
    return [] unless @chat
    @chat.messages.filter_map do |m|
      next if m.role == :system
      case m.role
      when :tool
        c = m.content.to_s
        next if c.empty? || m.tool_call_id.to_s.empty?
        { 'role' => 'tool', 'content' => c, 'tool_call_id' => m.tool_call_id }
      when :assistant
        if m.tool_call?
          # Live assistant messages carry tool_calls as {call_id => ToolCall}
          # (RubyLLM::Chat#handle_tool_calls runs tool_calls.each_value);
          # tolerate plain arrays too.
          calls = m.tool_calls.is_a?(Hash) ? m.tool_calls.values : m.tool_calls
          msg = { 'role' => 'assistant',
                  'tool_calls' => calls.map do |tc|
                    { 'id' => tc.id, 'name' => tc.name,
                      'arguments' => JSON.generate(tc.arguments || {}) }
                  end }
          c = m.content.to_s
          msg['content'] = c unless c.empty?
          msg
        else
          c = m.content.to_s
          next if c.empty?
          { 'role' => 'assistant', 'content' => c }
        end
      else # user
        c = m.content.to_s
        next if c.empty?
        { 'role' => 'user', 'content' => c }
      end
    end
  end
end
