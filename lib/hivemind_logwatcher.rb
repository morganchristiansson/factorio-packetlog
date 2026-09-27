# frozen_string_literal: true

require_relative 'log_tail'

# Hivemind plugin `logwatcher` — the file is lib/hivemind_logwatcher.rb (the
# manager's `hivemind_` prefix), the module takes its CamelCase name. Listed
# in config-hivemind.yaml `plugins:`; mixed into HiveMindAgent by
# Plugins.apply_mixins. The game server log watcher: tails the running
# server's factorio-current.log
# (scenario `log()` events in the common `event=<name>, k=v, ...` format from
# freeplay.lua/reset.lua: player-died, map-reset, research-finished,
# evo-stage, apex-spitter, artillery-target, fluid-flushed) and feeds the
# interesting lines to the agent. Every `event=` line is QUEUED for the next
# prompt; only TURN_EVENTS additionally fire a dedicated turn, so the model
# can react now — a map reset closes a round, so that one is followed by an
# auto-compaction. Repeats inside the configured log-event interval stay
# queue-only.
#
# Optional input to the agent (not cross-cutting state like persistence /
# compaction / followups): switch it off and the agent simply never hears the
# game log. Its two knobs — `log_turn_events` and `log_event_interval` — stay
# required keys of config-hivemind.yaml, read by the agent.
module HiveMindLogwatcher
  # This plugin's own config keys, read where they are used (no list, no
  # code default): switch the plugin off and nobody reads them.
  def log_turn_events = (@log_turn_events ||= hive_config.fetch('log_turn_events').map(&:to_s))
  def log_event_interval = @log_event_interval ||= hive_config.fetch('log_event_interval').to_f

  # Game-log watcher (factorio-current.log tail): scenario `log()` events
  # in the common `event=<name>, k=v, ...` format from freeplay.lua/reset.lua
  # (player-died, map-reset, research-finished, evo-stage, apex-spitter,
  # artillery-target, fluid-flushed) are QUEUED for the next prompt.
  # Only TURN_EVENTS additionally fire a dedicated turn (so the model can
  # react now) followed by an auto-compaction — a map reset closes a
  # round; other events stay queue-only. Repeats inside
  # the configured log-event interval stay queue-only. Matching is by parsed event name
  # (see #log_event_name), so adding a turn event is one entry here.
  LOG_EVENT_PREFIX = 'event='

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
    log "watching #{path} for #{LOG_EVENT_PREFIX}... (turn on #{log_turn_events.join(', ')})"
    true
  end

  # One tailed log line. Any `event=<name>, ...` line is QUEUED
  # (append_history) so it rides along with whatever prompt comes next;
  # only TURN_EVENTS (a map reset closes a round: distill memories while
  # the session is fresh) additionally fire a dedicated turn on the FIRST
  # match within the configured log-event interval — react in chat if players would care —
  # and then an auto-compaction. Rate limit runs on rate_mutex (packet-style
  # thread — never touches @mutex). async:false runs the turn inline
  # (tests / synchronous callers).
  def handle_log_line(line, async: true)
    text = clean_text(strip_log_prefix(line))
    name = log_event_name(text)
    return if name.nil?
    append_history(nil, text)
    return unless log_turn_events.include?(name)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    rate_mutex.synchronize do
      return if now - @last_log_event < log_event_interval
      @last_log_event = now
    end
    return run_log_event_turn(text) unless async
    enqueue(:run_log_event_turn, text)
    nil
  end

  # The dedicated reaction turn for one log event: build the prompt, get a
  # reply, then distill the round into long-term memory. Compaction is
  # skipped when there is little to compact (configured auto-compaction gate) or
  # a pass is already running (compact_memory! guards that itself). On
  # success the session is TRIMMED (same as /compact) so a repeated map
  # reset finds a thin session and skips — without the trim every reset
  # would re-compact the same material.
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
      # when there is little to compact (configured auto-compaction gate) or a
      # pass is already running (compact_memory! guards that itself).
      # Trim on success (session_players cleared, compacted history dropped)
      # so repeated resets don't re-compact the same round.
      trim_session_after_compaction! if plugin?('compaction') && auto_compaction_worthwhile? && compact_memory!('map reset')
    rescue StandardError => e
      log_error('log-event error', e)
    end
  end

  # Strip Factorio's log-line decoration so only the content is enqueued:
  # "4279.523 Script @__level__/freeplay.lua:113:
  # event=player-died, actor=morganc, ..." → "event=player-died, ...".
  def strip_log_prefix(line)
    line.sub(/\A\s*[\d.]+\s+(?:Script\s+\S+:\s*)?/, '')
  end

  # Generic event-name match on the stripped line: "event=player-died, ..."
  # → "player-died". Returns nil for non-event lines. Case-insensitive so
  # a future `EVENT=...` emitter still matches.
  def log_event_name(text)
    text[/\A#{Regexp.escape(LOG_EVENT_PREFIX)}([a-z0-9-]+)/i, 1]&.downcase
  end
end
