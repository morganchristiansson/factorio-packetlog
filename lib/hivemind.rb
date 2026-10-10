# frozen_string_literal: true

require 'securerandom'
require 'set'
require 'time'
require 'yaml'
require 'ruby_llm'
begin
  require 'ruby_llm-responses_api'
rescue LoadError
end
require_relative 'memory_store'
# RubyLLM tool classes (HivemindReply, RconQuery, SetPlayerTag,
# ScheduleFollowUp, CancelFollowUp, SetPlayerLanguages) live in
# hivemind_tools.rb.
require_relative 'hivemind_tools'
require_relative 'hivemind_prompts'
require_relative 'agent_events'
require_relative 'plugins'

# Hivemind agent — an LLM persona that lives inside the Factorio sniffer.
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
class HivemindAgent
  include AgentEvents
  include HivemindPrompts     # DEFAULT_SOUL / SYSTEM_PROMPT / COMPACTION_PROMPT
  # Non-secret Hivemind settings live only in config-hivemind.yaml.
  # HIVE_API_KEY remains the sole environment secret; api_key: in this
  # (gitignored) file is the per-provider fallback for it.
  CONFIG_FILE = 'config-hivemind.yaml'
  # Hivemind's OWN plugins — the same convention, a prefixed file set: the
  # `plugins:` list in config-hivemind.yaml names lib/hivemind_persistence.rb,
  # lib/hivemind_compaction.rb, lib/hivemind_followups.rb,
  # lib/hivemind_logwatcher.rb, whose modules are mixed into this class. A
  # plugin that is not listed is never required and never lands on the agent,
  # so a call site asks #plugin?(:compaction) before touching one.
  #
  # The list is read where it is USED: here, in the class body, because that is
  # where the mixins are decided. A file without the key raises
  # `KeyError: key not found: "plugins"` instead of quietly producing an
  # agent with no plugins. A missing FILE is load_config's error to report
  # (in initialize) — the class body must survive a hot reload either way.
  def self.config_plugins(path = CONFIG_FILE)
    return [] unless File.file?(path)

    Array(YAML.safe_load_file(path).fetch('plugins')).map { |n| n.to_s.to_sym }
  end
  PLUGIN_OWNER = 'hivemind'
  # The list, read ONCE per load of this file: a hot reload re-reads the config
  # and re-mixes, so an edited list applies then. A module already mixed in
  # can't be un-mixed, so restarting is the clean switch.
  def self.own_plugins = (@own_plugins ||= config_plugins)
  # Features still mixed in rather than built (see the constructor).
  def self.still_modules = %i[compaction].freeze

  def self.plugin_set
    @plugin_set ||= Plugins::PluginSet.new(own_plugins, nil, dir: __dir__, owner: PLUGIN_OWNER)
  end
  self.plugin_set.mix_modules_into(self)
  # Identity headers for the OpenCode Go gateway (required, not optional):
  # a custom User-Agent (never a generic SDK/HTTP-library name) plus a
  # stable per-conversation session id (x-opencode-session) for routing
  # and prompt caching. Both are hardcoded/deterministic — no knobs.
  USER_AGENT = 'factorio-hivemind/1.0'

  # No key list and no code defaults: the file must exist (checked once, so
  # "no config at all" is a clear startup error naming the example to copy),
  # and every key is read with Hash#fetch where it is used — a missing one
  # raises `KeyError: key not found: "<key>"` at that point.
  def self.load_config(path = CONFIG_FILE)
    raise Errno::ENOENT, "missing #{path}; copy config-hivemind.yaml.example" unless File.file?(path)

    YAML.safe_load_file(path) || {}
  end

  # Responses-API-only hack: the gem chains every request onto the last
  # reply via previous_response_id, but we resend the full history every
  # time — and the gateway doesn't retain server-side responses (idle
  # expiry, restarts), so any chained id fails the ask with "referenced
  # response not found or expired". The tool-call follow-up INSIDE a
  # single ask picks up the fresh id from the just-completed reply, so
  # per-ask nil-ing can't cover it — never chain. Installed here at file
  # load (NOT from initialize — hot reloads `load` this file without ever
  # re-running initialize, so install-time gating on @provider leaves
  # reloaded processes unpatched). Scoping is structural instead: the
  # prepend targets only the OpenAIResponses class, which the
  # chat/completions provider never touches.
  module StatelessResponses
    def extract_last_response_id(*) = nil
  end
  if defined?(RubyLLM::Providers::OpenAIResponses)
    RubyLLM::Providers::OpenAIResponses.prepend(StatelessResponses) unless RubyLLM::Providers::OpenAIResponses.ancestors.include?(StatelessResponses)
  end

  # The agent's OWN name — its replies are queued with this as the player
  # and filtered from live prompts (they live in the conversation). Must
  # never become a compaction target: the agent is not a player.
  AGENT_NAME = 'hivemind'
  # rcon: an RconClient (for game.print replies). Chat completions need
  # an API key from HIVE_API_KEY (or the configured model key env).
  attr_reader :model
  attr_reader :last_trigger
  attr_reader :memory_store
  attr_reader :models
  attr_reader :triggers

  # Optional callback invoked with the clean text of every agent reply — both
  # the HivemindReply tool path (via on_sent) and the send_reply fallback. Set
  # by the sniffer. Nil-safe (no sniffer owner → no-op). Survives hot
  # reloads: the owner is set once on the persistent agent object.
  # (The reply path: @owner.publish_chat(:hivemind, 'Hivemind', text) —
  # the same relay every chat feature publishes through.)

  # Packet-derived player attributes, database, and current-tick provider.
  attr_accessor :attrs, :player_db, :current_tick
  # The parsed config-hivemind.yaml (the agent and its plugins read their
  # keys from it with fetch — a missing key raises where it is read).
  # Reload-safe like the mutexes below: a hot-reloaded agent built by older
  # code has no hash, so it re-reads the file on first use.
  def hive_config = (@hive_config ||= self.class.load_config)

  # Which of Hivemind's own plugins (config-hivemind.yaml `plugins:`) are
  # mixed in — what a call site asks before touching a plugin's methods.
  # #plugin_files is what the sniffer re-reads on a hot reload.
  # The follow-ups the model schedules (the schedule_followup /
  # cancel_followup tools) — nil-safe, so a config without the feature turns
  # them into a clear refusal instead of a crash.
  def schedule_followup(delay_seconds:, task:, name: nil)
    plugins[:followups]&.schedule_followup(delay_seconds: delay_seconds, task: task, name: name)
  end

  def cancel_followup(name: nil)
    plugins[:followups]&.cancel_followup(name: name)
  end

  # Write the session file. The FILE is the persistence feature's business —
  # every other feature (and the agent itself) asks it through here, and
  # without the `persistence` plugin this is a no-op.
  def persist!
    plugins[:persistence]&.persist!
  end

  # The features this agent was built with (config-hivemind.yaml `plugins:`),
  # keyed by their list name. A feature that is not listed is nil here.
  attr_reader :plugins

  def plugin?(name) = Plugins.enabled?(self.class.own_plugins, name)
  def plugin_files = self.class.plugin_set.files


  # Reload-safe lock accessors: a HOT-RELOADED agent keeps its boot-time
  # ivars, so an agent object built by pre-split code lacks these. `||=`
  # fills them in on first use (benign race: worst case the very first
  # calls briefly hold different Mutex instances).
  def rate_mutex = (@rate_mutex ||= Mutex.new)

  # The ask mutex: a follow-up that comes due while a conversation turn holds
  # it is put back instead of piling on (PLAYER PRIORITY, see the feature).
  attr_reader :mutex

  def max_reply_len = @max_reply_len
  def auto_compaction_min_chars = @auto_compaction_min_chars

  # A model's settings are fully resolved at load (its provider group's
  # provider/api_base/api_key_env, overridden by the model entry itself).
  def model_settings(model)
    @model_configs.find { |config| config[:name] == model } || {}
  end

  # provider/api_base live on the provider GROUP (validated at load), so
  # a model's own entry can only narrow them, never inherit a global.
  def model_provider(model)
    model_settings(model)[:provider].to_sym
  end

  def api_base_for(model)
    model_settings(model)[:api_base]
  end


  # Env wins (ops/CI injects it without editing the file), then the
  # provider group's `api_key:` (config-hivemind.yaml is gitignored), then
  # HIVE_API_KEY as the shared fallback.
  #
  # An EMPTY value counts as absent at every step. `ENV['HIVE_API_KEY']` is
  # `""` — not nil — when a shell profile, systemd unit or container env sets
  # the variable to nothing, and `"" || fallback` short-circuits: the agent
  # started, raised nothing, and every request went out with an empty
  # credential, which the gateway reports as "authentication header missing".
  def self.resolve_api_key(settings)
    settings = (settings || {}).transform_keys(&:to_sym)
    # Same precedence as before, but the first NON-EMPTY value wins: the
    # named env var, then the provider group's `api_key:`, then the bare
    # HIVE_API_KEY fallback.
    [ENV[settings[:api_key_env] || 'HIVE_API_KEY'], settings[:api_key], ENV['HIVE_API_KEY']]
      .find { |v| !v.to_s.empty? }
  end

  def api_key_for(model) = HivemindAgent.resolve_api_key(model_settings(model))

  # WHERE the key came from — env var name, or the config's own `api_key:`.
  # The key itself is never logged; this is the one line that answers "is my
  # config key actually being read?" and "which provider slot got it",
  # which is otherwise guesswork when a gateway answers
  # "authentication header missing".
  def api_key_source(model)
    settings = model_settings(model)
    name = settings[:api_key_env] || 'HIVE_API_KEY'
    return "env #{name}" unless ENV[name].to_s.empty?
    return 'config api_key:' unless settings[:api_key].to_s.empty?
    return 'env HIVE_API_KEY' unless ENV['HIVE_API_KEY'].to_s.empty?
    'none'
  end

  # Flatten provider groups into per-model settings (group fields, overridden
  # by the model entry; `provider` always from the group). Order — providers,
  # then models within a provider — IS the /model + fallback order.
  def self.model_configs(config)
    config.fetch('providers').flat_map do |group_name, fields|
      group = (fields || {}).transform_keys(&:to_sym)
      missing = %i[provider api_base models] - group.keys
      raise ArgumentError, "provider #{group_name.inspect} is missing #{missing.join(', ')}" unless missing.empty?

      Array(group[:models]).map do |entry|
        model = entry.is_a?(Hash) ? entry.transform_keys(&:to_sym) : { name: entry }
        name = model[:name].to_s
        next if name.empty?

        group.merge(model).merge(name: name, provider: group[:provider])
      end
    end.uniq { |model| model[:name] }
  end

  # Implicit on/off: the sniffer builds the agent in server mode iff the
  # STARTUP model has a key somewhere. Checked without constructing the
  # agent (a config without a key must stay silent, not raise).
  def self.key_configured?(path = CONFIG_FILE)
    config = load_config(path)
    model = model_configs(config).find { |m| m[:name] == config['model'].to_s }
    return false unless model
    !resolve_api_key(model).nil?
  rescue StandardError
    false
  end
  # Stable OpenCode session id (x-opencode-session), one per conversation.
  # Reload-safe like the mutexes above: a hot-reloaded agent keeps its
  # boot-time ivars, so an object built before this field existed mints
  # its id lazily on first use instead of sending a blank header.
  def opencode_session_id = (@opencode_session_id ||= SecureRandom.uuid)

  # sniffer_plugins: the SNIFFER's list (config.yaml `plugins:`) — the agent
  # consults it for the features it hooks (translation gates the
  # set_player_languages tool). Its OWN list is config-hivemind.yaml.
  def initialize(owner = nil, rcon: nil, attrs: nil, current_tick: nil, player_db: nil,
                 sniffer_plugins: nil, memory_dir: nil, config_file: CONFIG_FILE)
    # A plugin FEATURE (built by PluginSet as HivemindAgent.new(owner)): the
    # owner is the sniffer, which provides rcon/attrs/player_db and publishes
    # replies through publish_chat. The kwargs stay for the tests that build
    # the agent directly (no owner). Server-less runs raise here — the agent
    # needs RCON for game.print replies and join queries.
    @owner = owner
    @rcon = rcon || owner&.rcon
    raise 'HivemindAgent needs RCON (server mode) — game.print replies and join queries require it' unless @rcon

    @sniffer_plugins = Array(sniffer_plugins).map { |n| n.to_s.to_sym }
    @attrs = attrs || owner&.attrs
    @current_tick = current_tick || -> { 0 }
    @player_db = player_db || owner&.player_db
    # THIS OWNER'S FEATURES: the classes config-hivemind.yaml `plugins:`
    # names, each built with this agent. The agent drives them by name
    # (plugins[:followups].schedule(…)), so a feature that is not listed is
    # simply nil — no plugin? guard at any call site.
    # INTERIM: persistence and compaction are still modules mixed in by
    # mix_modules_into, so they are not features yet and must not be built
    # (building them would report them missing). This line goes away with
    # those two conversions.
    not_yet = self.class.own_plugins - self.class.still_modules
    @plugins = Plugins::PluginSet.new(not_yet, self, dir: __dir__, owner: PLUGIN_OWNER)
    @last_ask_at = {}           # player → last trigger time (per-player anti-spam)
    @last_trigger = nil         # [player, message] of last handled trigger (for /retry)
    @last_greet = 0.0
    @mutex = Mutex.new
    # Separate rate-limit state from completions and log-watcher callbacks.
    @rate_mutex = Mutex.new
    @chat = nil
    # Pending scheduled follow-ups (schedule_followup tool) belong to the
    # followups FEATURE now: its entries are NAME-keyed (the model picks a
    # short stable key, e.g. 'prowl') and carry a MONOTONIC due (used to fire)
    # plus an absolute unix due_at (persisted, so a restart re-arms with the
    # correct remaining delay); its own mutex + condition variable let a
    # single scheduler thread sleep until the next due time instead of
    # polling, and it survives hot reloads with the agent that owns it.
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
    # Session persistence (console history + LLM conversation saved so a full
    # RESTART resumes) is the `persistence` FEATURE: it owns the file, its
    # path and its write lock — nothing here, so nothing here knows the
    # session file exists beyond #persist!.

    # Long-term memory (keyed blobs: soul / knowledge / <player>) — the
    # compaction layer that lets a NEW session carry over what Hivemind
    # learned. Default memories/; memory_dir: false disables. The default
    # SOUL is seeded on first run.
    @memory_store = MemoryStore.new(memory_dir)
    @memory_store.seed(MemoryStore::SOUL_KEY, HivemindPrompts::DEFAULT_SOUL) if @memory_store.enabled?
    # Player memories already delivered to the model THIS session (join
    # briefings / chat turns). PERSISTED with the session file: a restored
    # conversation still contains the injection, so re-sending it after a
    # restart would duplicate a block the model has already read. Cleared
    # by compaction (the trimmed thread no longer has it), so the memories
    # re-inject into the new context exactly once each.
    @memories_sent = Set.new
    # Players encountered THIS LLM session (since last compaction/reset).
    # Persisted with the session file; drives compaction targets so they
    # can't drift from what the session actually saw. Cleared on /compact
    # compaction success; console lines afterwards re-populate it.
    # Own lock: marked from PACKET threads (must never wait on @mutex —
    # an in-flight LLM call would stall the capture loop).
    @session_players = Set.new
    @session_players_mutex = Mutex.new

    # ── LLM wiring. Every non-secret setting is required from
    #    config-hivemind.yaml; HIVE_API_KEY is the only environment secret.
    #    Missing config/key or bad provider config raises; PluginSet#build
    #    rescues and reports the feature disabled.
    hive_config = self.class.load_config(config_file)
    # Kept whole so a plugin reads its OWN keys (with fetch, at the point of
    # use) instead of the agent copying them out here.
    @hive_config = hive_config
    # Models live UNDER their provider group, and the endpoint lives with
    # the group: a model entry may override any group field (except
    # `provider` — the group names the RubyLLM provider for its models).
    # Flattened once here, so model_settings stays a plain lookup. Order
    # (providers, then models within a provider) IS the /model + fallback
    # order. api_key_env + api_key are the optional key fields (env wins,
    # api_key_env defaults to HIVE_API_KEY).
    @model_configs = self.class.model_configs(hive_config)
    raise ArgumentError, 'no models configured' if @model_configs.empty?
    @models = @model_configs.map { |config| config[:name] }
    @model = hive_config.fetch('model')
    raise ArgumentError, "model #{@model.inspect} is not present in models" unless @models.include?(@model)
    @provider = model_provider(@model)
    llm_api_key = api_key_for(@model)
    @history_size = hive_config.fetch('history_size').to_i
    @history_line_len = hive_config.fetch('history_line_len').to_i
    @max_reply_len = hive_config.fetch('max_reply_len').to_i
    @trim_tail_chars = hive_config.fetch('trim_tail_chars').to_i
    @auto_compaction_min_chars = hive_config.fetch('auto_compaction_min_chars').to_i
    @triggers = Array(hive_config.fetch('triggers')).map(&:to_s)
    @min_interval = hive_config.fetch('min_interval').to_f
    @greet_interval = hive_config.fetch('greet_interval').to_f

    raise ArgumentError, "no API key configured for #{@model} — put api_key: under its " \
                         'provider group in config-hivemind.yaml, or set HIVE_API_KEY in the env' if llm_api_key.nil?

    slot = nil
    RubyLLM.configure do |config|
      slot = apply_endpoint!(config, @model, llm_api_key)
      config.default_model = @model
      # Read timeout ceiling for EVERY request (faraday). Raised from 60s
      # because memory compaction sends the WHOLE conversation (hundreds of
      # messages — the input-token-cache reuse is the point) and the model
      # can legitimately take 1-2min to answer such a large prompt; 60s
      # killed it with Net::ReadTimeout (session kept, compaction failed).
      # Normal chat replies respond in seconds, so 300 only moves the
      # ceiling, not the latency.
      config.request_timeout = 300
      # Transient failures (5xx, 429, overload, timeouts, dropped
      # connections) retry inside faraday-retry: RubyLLM registers retry
      # OUTSIDE its error middleware, so raised RubyLLM errors bubble
      # through it — plus Timeout::Error/ETIMEDOUT/RetriableResponse,
      # which the old hand-rolled loop never covered. 4 retries, 5s x2
      # backoff ~= 5/10/20/40s delays.
      config.max_retries = 4
      config.retry_interval = 5
      config.retry_backoff_factor = 2
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
    apply_request_headers(@chat)
    register_tools

    hook_chat_observers if @chat
    # One line that makes an auth failure self-diagnosing: which key source
    # won, and WHICH provider slot RubyLLM will read it from.
    log "model #{@model} via #{@provider}/#{api_base_for(@model)} — api key from #{api_key_source(@model)}, set as #{slot}_api_key"
    plugins[:persistence]&.load!
    plugins[:followups]&.ensure_followup_scheduler
    initialize_events
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

  # Chat-relay subscriber (reached via @plugins.emit(:on_chat)). Sync-light:
  # skip own replies and defer everything else to handle_chat on this
  # agent's worker (emit runs on the capture thread; the LLM ask must not).
  # player_id is ignored — the agent resolves player names itself.
  def on_chat(source, author, text, player_id = nil, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    return if source == :hivemind  # own reply — already in context, don't duplicate
    enqueue(:handle_chat, author, text, source: source, now: now)
  end

  # The heavy chat handler, on this agent's worker: queue the message into
  # the console history and trigger the agent if it matches. Player name
  # AND message are cleaned: a Unicode name must not stay binary-flagged —
  # interpolating it into the UTF-8 prompt raises
  # Encoding::CompatibilityError inside turn_prompt.
  #
  # Slash-prefixed lines are COMMANDS, not chat — Factorio routes anything
  # starting with `/` to the command system (admin/teleport/permission
  # outputs, /shout echoes, etc.), and in-game chat can never begin with
  # `/`. Commands stay visible context (the agent should see what players
  # do, and a "/hivemind ..." line even triggers it like any mention).
  # WHISPERS (/w, /whisper) are the exception: private DMs, excluded
  # entirely — never queued into the console context and never triggering
  # the agent.
  def handle_chat(player, message, source: nil, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    player = clean_text(player)
    message = clean_text(message)  # invalid UTF-8 from the wire is safe here
    return if message.start_with?('/w ', '/whisper ')
    append_history(player, message)
    handle(player, message, now: now)
  end

  # Feed a join/leave event (player came online / went offline). Appended
  # to the rolling console history so the agent knows who was around.
  # Joins include the player's total play time from RCON (online_time,
  # ticks — formatted as days/hours like the context snapshot) and get an
  # LLM-generated personal greeting (see greet_join).
  def on_player_event(kind, player, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    enqueue(:handle_player_event, kind, player, now: now)
  end

  # The heavy join/leave handler, on this agent's worker (the sniffer emits
  # on_player_event on the bus; :joined runs an RCON attrs query and maybe a
  # greeting LLM call, so it must not run on the capture thread).
  def handle_player_event(kind, player, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
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
      greet_join(name, line, attrs, now: now)
    when :left
      append_history(nil, "#{name} left the game")
    when :timeout
      # No clean PeerDisconnect was seen — heartbeat just stopped (crash,
      # power/network loss). The player may re-join; the LLM should know the
      # roster changed either way.
      append_history(nil, "#{name} timed out (no heartbeat) — likely crashed or disconnected; may re-join")
    end
  end

  # LLM-generated run briefing WITH a personal greeting for a joining player:
  # what has happened in this run so far, said to them as they arrive, plus
  # a greeting informed by who they are (their memory rides along with the
  # prompt). Informed by the console context (recent chat, who's online),
  # their play history, and whatever the run has left in long-term memory.
  # Runs on the event worker with its own arrival-time rate limit; it can
  # delay subsequent agent events, never packet decoding.
  # `line` is the exact join console line (greet_join's exclude must match
  # it so the event reaches the model only via the instruction), `attrs`
  # the player's attribute snapshot (play time + admin) or nil.
  def greet_join(name, line, attrs = nil, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))
    rate_mutex.synchronize do
      return if now - @last_greet < @greet_interval
      @last_greet = now
    end
    prompt = turn_prompt(
      "#{name} just joined the game. Greet them personally and briefly — " \
      "you remember them (their memory rides along with this prompt) — and " \
      "brief them on the run: what has happened since it started, in one " \
      "or two short sentences (under 150 characters). They cannot see what " \
      "came before they arrived, so make it a briefing, not a welcome " \
      "speech. Use what you can see and what you remember about this run" \
      "#{join_facts(attrs)}. If you know nothing about the run yet, greet " \
      'them and stop. Call the reply tool with it.',
      exclude: [nil, line],
      player: name
    )
    reply = complete(prompt)
    send_reply(reply)
  rescue StandardError => e
    log_error('greeting error', e)
  end

  private

  # ── LLM plumbing ──────────────────────────────────────────────────

  # Stamp the OpenCode-required request headers onto a chat: the custom
  # User-Agent plus the stable per-conversation session id. with_headers
  # REPLACES, so both ride in one call. Applied at creation AND
  # defensively in ask_with_retry (every ask funnels through it), so even
  # a hot-reloaded chat that predates this code sends headers.
  def apply_request_headers(chat)
    return unless chat
    chat.with_headers(**{ 'User-Agent': USER_AGENT, 'x-opencode-session': opencode_session_id })
  end

  # Re-register the tool set with FRESH instances before every ask. Tools
  # are registered once at creation otherwise; hot reloads (Ctrl-C `load`)
  # rebind the tool CLASSES, so stale instances would keep running old
  # code and new tools wouldn't appear until restart. with_tool replaces by
  # name, so this is idempotent and cheap.
  def register_tools(chat = @chat)
    return unless chat
    chat.with_tool(HivemindReply.new(rcon: @rcon, on_sent: ->(text) { append_history('hivemind', text); @owner&.publish_chat(:hivemind, 'Hivemind', text) }))
    chat.with_tool(RconQuery.new(rcon: @rcon)) if defined?(RconQuery)
    # The state-changing tool is a feature, not a constant: with `tags` out of
    # config-hivemind.yaml's list the file is never required and the model is
    # never offered the write (no guard needed here — nil plugin, nil call).
    plugins[:tags]&.register(chat, @rcon)
    chat.with_tool(ScheduleFollowUp.new(agent: self)) if defined?(ScheduleFollowUp) && plugin?(:followups)
    chat.with_tool(CancelFollowUp.new(agent: self)) if defined?(CancelFollowUp) && plugin?(:followups)
    # The language tool edits the per-player language overrides the
    # TRANSLATION plugin relays chat for, so it is only useful (and only
    # offered) while that plugin is loaded.
    chat.with_tool(SetPlayerLanguages.new(player_db: @player_db)) if Plugins.enabled?(@sniffer_plugins, :translation)
  end

  def ask_llm(player, message)
    complete(turn_prompt(
      "In-game chat from #{player}: #{message}\n\n" \
      "Answer the player's question or continue the conversation. " \
      "Keep it under #{@max_reply_len} characters. Plain text only — " \
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
      response = nil
      begin
        response = ask_with_retry(@chat, prompt)
      rescue RubyLLM::ModelNotFoundError => e
        fallback = next_model
        raise if fallback.nil?
        log "model #{@model} unavailable (#{e.class}); falling back to #{fallback}"
        activate_model!(fallback)
        retry
      end
      text = response.respond_to?(:content) ? response.content.to_s : ''
      clean_reply(text)
    end
  ensure
    persist!  # conversation changed — save for restart
  end

  def next_model
    index = @models.index(@model)
    return nil unless index
    @models.rotate(index + 1).find { |candidate| api_key_for(candidate) }
  end

  def configure_model!(model)
    key = api_key_for(model)
    raise ArgumentError, "no API key configured for #{model}" if key.nil?
    slot = nil
    RubyLLM.configure do |config|
      config.default_model = model if config.respond_to?(:default_model=)
      slot = apply_endpoint!(config, model, key)
    end
    # The same line the startup logs, on every switch: a /model command or a
    # fallback to another model can move the endpoint and the key slot, and a
    # 401 from THAT request is otherwise indistinguishable from the first one.
    log "model #{model} via #{model_provider(model)}/#{api_base_for(model)} — " \
        "api key from #{api_key_source(model)}, set as #{slot}_api_key"
    slot
  end

  # Set the endpoint and the key on THIS model's provider slot. RubyLLM reads
  # `<provider>_api_key` / `<provider>_api_base` (openai_api_key,
  # deepseek_api_key, anthropic_api_key, …), so writing them into the openai
  # slot whatever the provider — as this used to — leaves every other
  # provider unauthenticated: the request goes out with no Authorization
  # header and the gateway answers "authentication header missing" even
  # though `api_key:` sits right there in the config. A provider RubyLLM has
  # no slot for (an OpenAI-compatible api_base under a custom name) falls
  # back to openai's.
  def apply_endpoint!(config, model, key)
    provider = model_provider(model).to_s
    provider = 'openai' unless config.respond_to?("#{provider}_api_key=")
    config.send("#{provider}_api_base=", api_base_for(model))
    config.send("#{provider}_api_key=", key)
    provider
  end

  def activate_model!(new_model)
    configure_model!(new_model)
    @model = new_model
    @provider = model_provider(@model)
    if @chat
      @chat.with_model(@model, provider: @provider, assume_exists: true)
      apply_request_headers(@chat)
    else
      @chat = RubyLLM.chat(model: @model, provider: @provider, assume_model_exists: true)
      @chat.with_instructions(system_prompt_with_memories)
      apply_request_headers(@chat)
      register_tools
      @observers_hooked = false
      hook_chat_observers
    end
  end

  # One chat.ask — retries happen INSIDE faraday-retry (see configure),
  # so no sleep loop here. On FINAL failure the half-appended user turn is
  # sliced off: chat.ask adds it BEFORE the request goes out, so without
  # this a failed prompt duplicates on the next ask and persists as an
  # orphan in the session file. Slices on ANY error (a 400 leaves the same
  # orphan the old retryable-only rescue kept). Used by live asks
  # (complete), dry runs (try_model!), and compaction (whose material
  # message stays — only the turn is stripped).
  def ask_with_retry(chat, prompt)
    # Every request carries the OpenCode identity headers (re-applied here
    # so hot-reloaded chats and throwaway forks can't miss them).
    apply_request_headers(chat)
    start = chat.messages.size
    chat.ask(prompt)
  rescue StandardError => e
    log_bad_request_proof(chat) if e.is_a?(RubyLLM::BadRequestError)
    chat.messages.slice!(start..)
    raise
  end

  # Failure-only probe for provider 400s: re-render the Responses payload
  # the gem just sent and log its server-side references
  # (previous_response_id + function_call/call_id pairs) — ids and types
  # only, never content. Decisive either way: if previous_response_id is
  # present the stateless patch isn't active; if absent the reference the
  # gateway rejects must come from the tool round-trip. Only runs when an
  # ask actually fails, so zero noise on the happy path.
  def log_bad_request_proof(chat)
    provider = chat.instance_variable_get(:@provider)
    return unless provider.is_a?(RubyLLM::Providers::OpenAIResponses)
    payload = provider.send(:render_payload, chat.messages, tools: chat.tools,
      temperature: nil, model: chat.model, stream: false)
    items = Array(payload[:input]).map do |i|
      t = i[:type].to_s
      t += "(#{i[:call_id]})" if i[:call_id]
      t += "(#{i[:name]})" if i[:type].to_s == 'function_call'
      t
    end
    log("bad-request proof: previous_response_id=#{payload[:previous_response_id].inspect} input=[#{items.join(', ')}]")
  rescue StandardError => e
    log("bad-request proof unavailable: #{e.class}: #{e.message}")
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
    parts = [HivemindPrompts::SYSTEM_PROMPT]
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
    candidates = ([player].compact + online_player_list).reject { |n| memories_sent.include?(n) }
    candidates.uniq.each do |name|
      mem = @memory_store.player(name)
      next unless mem && !mem.strip.empty?
      lines << "=== memory of #{name} ===\n#{mem}"
      mark_memory_sent(name)
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
    return if name.empty? || name == HivemindAgent::AGENT_NAME
    @session_players_mutex.synchronize { @session_players << name }
  end

  # ── memories_sent ────────────────────────────────────────────────
  #
  # WHICH players' long-term memories this session has already handed the
  # model. Once per session AND context: the injection stays in the
  # conversation until compaction trims it away, so a player who rejoins
  # (or simply speaks again) must not get the same block twice. It is
  # persisted, so a restart that restores the conversation also restores
  # this; compaction clears it (the trimmed thread lost the injection).
  #
  # Read, mark and reset all take @session_players_mutex — the packet thread
  # snapshots it for the session file while the ask path injects.
  def memories_sent
    @session_players_mutex.synchronize { @memories_sent.dup }
  end

  def mark_memory_sent(name)
    @session_players_mutex.synchronize { @memories_sent << clean_text(name).strip }
  end

  # Replace the set (session restore) or empty it (compaction).
  def reset_memories_sent(names = [])
    @session_players_mutex.synchronize { @memories_sent = Set.new(Array(names).map(&:to_s)) }
  end

  def unread_console(exclude: nil)
    @console_mutex.synchronize do
      unread = @console_queue.dup
      @console_queue.clear
      unread.pop if exclude && unread.last == exclude
      unread.reject! { |p, _| p == 'hivemind' }  # replies live in the conversation
      unread.map do |player, msg|
        clipped = msg[0, @history_line_len]
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

  # ── Session state ↔ the persistence feature ───────────────────────
  #
  # The session FILE belongs to lib/hivemind_persistence.rb; these two
  # methods are the whole interface between it and the state it snapshots.
  # Nothing else on the agent (compaction, followups, the log watcher) knows
  # the file exists — they call #persist! / #persist_queue! and are done.

  # The conversation object (messages, tools, observers). Features read it;
  # only the persistence feature adds messages back on restore.
  attr_reader :chat

  # The queued console lines (a copy — the queue is drained per prompt).
  def console_queue = @console_mutex.synchronize { @console_queue.dup }

  def clear_console_queue = @console_mutex.synchronize { @console_queue = [] }

  # Everything of the session that is not the conversation itself: the
  # OpenCode session id (routing/prompt-cache identity), the console queue,
  # the players this LLM session has met (compaction targets) and the ones
  # whose long-term memory it already carries. The console queue is copied
  # under its lock, so JSON.generate in the caller cannot race an append.
  def session_snapshot
    {
      'opencode_session' => opencode_session_id,
      'console_queue' => console_queue,
      'session_players' => @session_players_mutex.synchronize { @session_players.to_a },
      'memories_sent' => memories_sent.to_a,
    }
  end

  # Replace that state from a loaded session file. `memories_sent` is
  # RESTORED, not cleared: the conversation we resume still contains those
  # injections, so re-sending them would duplicate a block the model has
  # read. An older file without the key re-seeds them (one harmless
  # duplicate). Missing/invalid keys keep the current value.
  def restore_session_state(data)
    reset_memories_sent(data['memories_sent'])
    @console_mutex.synchronize { @console_queue = data['console_queue'].map { |e| [e[0], e[1].to_s] } } if data['console_queue'].is_a?(Array)
    # Resume the OpenCode session id so the restored conversation keeps its
    # routing/caching identity; a missing key (older file) mints fresh.
    id = data['opencode_session']
    @opencode_session_id = id if id.is_a?(String) && !id.empty?
    return unless data['session_players'].is_a?(Array)
    @session_players_mutex.synchronize do
      @session_players = Set.new(data['session_players'].map(&:to_s))
      @session_players.delete(HivemindAgent::AGENT_NAME)
    end
  end
  # Both seams, plus the three accessors above, are the persistence feature's
  # whole surface on this object — explicit publicity, because the middle of
  # this file is a private section.
  public :chat, :console_queue, :clear_console_queue, :session_snapshot, :restore_session_state,
         :apply_request_headers

  # Enqueue a chat/console line. player is nil for bare console lines
  # (join/leave events); chat and replies carry the speaker name. When the
  # queue exceeds the configured history limit (no hivemind trigger in a long while), the
  # OLDEST unread lines are dropped with a warning — the next prompt stays
  # bounded.
  def append_history(player, message)
    msg = clean_text(message)
    return if msg.empty?
    # Track who appeared in this LLM session (persisted; drives compaction
    # targets so they can't drift from what the session actually saw).
    if player
      mark_player_seen(player) unless player == HivemindAgent::AGENT_NAME
    elsif msg =~ /\A(\S+) (?:joined|left) the game/
      mark_player_seen(Regexp.last_match(1))
    end
    @console_mutex.synchronize do
      @console_queue << [player, msg]
      if @console_queue.size > @history_size
        dropped = @console_queue.shift(@console_queue.size - @history_size)
        if dropped.any?
          warn "[hivemind] console history truncated: #{dropped.size} oldest lines dropped (no trigger in a while)"
        end
      end
    end
    plugins[:persistence]&.persist_queue!
  end

  # Names of players currently in-game from packet-derived tracking.
  # Names are force-cleaned so wire-derived bytes cannot taint the prompt.
  def online_player_list
    @attrs.online_names.map { |n| clean_text(n) }
  rescue StandardError => e
    log_error('online-player snapshot failed', e)
    []
  end

  def current_tick_value
    @current_tick.call
  end

  # Attribute snapshot for a specific player. Seeded players use the
  # packet-derived cache; new players get one targeted RCON enrichment
  # query (RconClient#player_attributes_for) folded into PlayerAttrs.
  def player_attrs_for(name)
    if @attrs.rcon_seeded?(name)
      return {
        name: name,
        admin: @player_db[name]&.fetch(:admin, false),
        online_time_ticks: @attrs.online_time_ticks(name, current_tick_value),
      }
    end
    attrs = @rcon.player_attributes_for(name)
    return nil unless attrs
    @attrs.connect(name, current_tick_value, attrs)
    @player_db[attrs[:index]] = {name: name, admin: attrs[:admin]}
    {
      name: name,
      admin: @player_db[name]&.fetch(:admin, false),
      online_time_ticks: @attrs.online_time_ticks(name, current_tick_value),
    }
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

  # One "Name: total-play-time (flags)" fragment per connected player.
  # Offline players and lifetime stats for players not currently online are
  # intentionally omitted. Flags: admin; afk while connected and idle.
  def player_stat_lines
    tick = current_tick_value
    list = @attrs.online_names.map do |name|
      {
        name: name,
        connected: true,
        admin: @player_db[name]&.fetch(:admin, false),
        online_time_ticks: @attrs.online_time_ticks(name, tick),
        afk_time_ticks: @attrs.afk_time_ticks(name, tick),
      }
    end
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
    text.gsub('`', '').gsub(/[*_]{1,2}/, '')[0, @max_reply_len].strip
  end

  # ── Trigger / rate limit / reply ──────────────────────────────────

  # Any of the trigger phrases (TRIGGERS) — case-insensitive whole-word
  # match, so "Hivemind?", "good bot!" and "hm, hello" all ping the agent
  # while "shmoose" or "HivemindFan" can't accidentally do it.
  def trigger_match?(msg)
    @triggers.any? { |t| msg.match?(/\b#{Regexp.escape(t)}\b/i) }
  end

  def handle(player, message, now: Process.clock_gettime(Process::CLOCK_MONOTONIC))

    msg = message.to_s.strip
    return false if msg.empty?
    return false unless trigger_match?(msg)

    # Rate-limit by event arrival, not execution time: a slow completion
    # must not turn a queued spam burst into separately accepted triggers.
    rate_mutex.synchronize do
      last = @last_ask_at[player]
      return false if last && now - last < @min_interval
      @last_ask_at[player] = now
    end

    @last_trigger = [player, msg]

    # Already on the agent's FIFO worker; never spawn a thread per trigger.
    begin
      reply = ask_llm(player, msg)
      send_reply(reply)
    rescue StandardError => e
      log_error("error responding to #{player}", e)
    end
    true
  end

  public

  # ── Runtime model switching (/model, /try) ───────────────────────

  # Switch the persistent model at runtime (without changing the config file).
  # Uses RubyLLM::Chat#with_model which mutates the SAME chat in place —
  # messages, tools, and observers stay, only the model+provider changes.
  # Survives hot reloads (ivar) but not a full restart (reverts to config).
  def switch_model!(new_model)
    cleaned = clean_text(new_model.to_s).strip
    return "Error: model name empty — usage: /model <model-id>" if cleaned.empty?
    return "Error: model #{cleaned.inspect} is not configured. Available: #{@models.join(', ')}" unless @models.include?(cleaned)
    return "Model already #{@model}." if cleaned == @model
    begin
      @mutex.synchronize { activate_model!(cleaned) }
      persist!
      log "model switched to #{@model}"
      "Model switched to #{@model}. Future replies will use it (persists until restart; reverts to config-hivemind.yaml on restart)."
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
    return "Error: model name empty — usage: /try <configured-model> [message]" if m.empty?
    return "Error: model #{m.inspect} is not configured. Available: #{@models.join(', ')}" unless @models.include?(m)
    if message.nil? || clean_text(message.to_s).strip.empty?
      trig = @last_trigger
      return "No previous trigger to try (no hivemind message yet) — pass a message: /try <model> <message>" unless trig
      player, message = trig
    end
    msg = clean_text(message.to_s).strip
    msg = "hivemind #{msg}" unless trigger_match?(msg)
    # Build prompt without mutating real state (queue / memories_sent).
    saved_queue = @console_mutex.synchronize { @console_queue.dup }
    saved_memories = memories_sent
    saved_players = @session_players_mutex.synchronize { @session_players.dup }
    prompt = nil
    begin
      prompt = turn_prompt(
        "In-game chat from #{player}: #{msg}\n\n" \
        "Answer the player's question or continue the conversation. " \
        "Keep it under #{@max_reply_len} characters. Plain text only — " \
        'no markdown, no code blocks, no emoji.',
        exclude: [player, msg],
        player: player
      )
    ensure
      @console_mutex.synchronize { @console_queue.replace(saved_queue) }
      reset_memories_sent(saved_memories)
      @session_players_mutex.synchronize { @session_players.replace(saved_players) } if saved_players
    end
    snapshot = @mutex.synchronize { @chat ? @chat.messages.dup : [] }
    Thread.new do
      original_model = @model
      begin
        @mutex.synchronize do
          configure_model!(m)
          tmp_provider = model_provider(m)
          tmp = RubyLLM.chat(model: m, provider: tmp_provider, assume_model_exists: true)
          apply_request_headers(tmp)
          tmp.messages.replace(snapshot.dup)
          register_tools(tmp)
          observe_chat(tmp)
          start_t = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          response = ask_with_retry(tmp, prompt)
          elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start_t
          text = clean_reply(response.respond_to?(:content) ? response.content.to_s : '')
          usage = tmp.messages.last ? usage_line(tmp.messages.last) : ''
          if text.empty?
            log "[try #{m}] (#{elapsed.round(1)}s) → (no reply — model stayed silent)#{usage}"
          else
            log "[try #{m}] (#{elapsed.round(1)}s) → #{text}#{usage}"
          end
        end
      rescue StandardError => e
        log_error("try (#{m}) failed", e)
      ensure
        @mutex.synchronize { configure_model!(original_model) } rescue nil
      end
    end
    "[try] Running '#{msg}' with model #{m} — one-off, not persisted, not sent to game. See [hivemind] logs for result..."
  end

  # Fallback reply path: only fires when the model answered with plain text
  # instead of calling the reply tool (HivemindReply). Lua-quoted so arbitrary text
  # can't break out of the /sc game.print(...) string.
  def send_reply(text)
    return if text.nil? || text.empty?
    append_history('hivemind', text)
    @owner&.publish_chat(:hivemind, 'Hivemind', text)
    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{text}"
    @rcon.say("#{HivemindReply::REPLY_PREFIX}#{text}")
  end
  # ── What a FEATURE may call on the agent ──────────────────────────
  # A feature is a class built with this agent as its owner, so these are
  # the published interface: the LLM entry points (complete, turn_prompt,
  # send_reply, append_history, enqueue), the text helper, the log helpers
  # and the rate mutex. Public because a feature is not a mixin any more —
  # it reaches the agent through these, not through its ivars.
  public :complete, :turn_prompt, :send_reply, :append_history, :enqueue,
         :clean_text, :log, :log_error, :rate_mutex, :hive_config,
         :current_tick_value, :player_attrs_for

end
