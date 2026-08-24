# frozen_string_literal: true

# Scheduled follow-ups (the schedule_followup / cancel_followup tools'
# backing logic, JS setTimeout/clearTimeout analog). A MIXIN on
# HiveMindAgent — deliberately NOT part of the tool classes: the pending
# entries are shared state (persisted by persist!/load_session, dropped by
# clear_session!, listed by compaction) and must survive hot reloads and
# restarts, while tools are rebuilt fresh per ask.
module HiveMindFollowUps
  # Scheduled follow-ups (the schedule_followup tool, JS-setTimeout-like).
  MIN_FOLLOWUP_DELAY = 15.0     # min seconds before a follow-up can fire (anti ping-pong/abuse)
  MAX_PENDING_FOLLOWUPS = 5     # cap on pending follow-ups (the model cancels stale ones)
  MAX_FOLLOWUP_NAME_LEN = 40    # clamp for user-chosen timer keys ('prowl', 'mall-check')
  FOLLOWUP_YIELD_DELAY = 15.0   # re-check delay when a conversation turn holds @mutex
                                # (player triggers get priority over self-churn)

  # Schedule a follow-up turn (like JavaScript setTimeout with a named
  # handle). delay_seconds: seconds from now; task: what your future self
  # should check/do; name: short stable key (e.g. 'prowl'). Scheduling the
  # SAME name again REPLACES the pending entry (upsert) — no cancel-first
  # dance. Returns the tool-result string for the model. Enforces a minimum
  # delay (anti ping-pong/abuse) and a cap on pending follow-ups (a re-sched
  # ule of an existing name never counts toward the cap). Callable from the
  # LIVE conversation only (the tool is registered there) — the compaction
  # chat never sees it.
  def schedule_followup(delay_seconds:, task:, name:)
    return 'Error: the agent is disabled.' if @disabled
    delay = delay_seconds.to_f
    return 'Error: delay_seconds must be a positive number of seconds.' if delay <= 0
    return "Error: minimum delay is #{MIN_FOLLOWUP_DELAY.to_i} seconds." if delay < MIN_FOLLOWUP_DELAY
    task_text = clean_text(task)
    return 'Error: task is empty.' if task_text.empty?
    name_text = clean_text(name).to_s[0, MAX_FOLLOWUP_NAME_LEN]
    return "Error: name is empty — give this timer a short stable key (e.g. 'prowl')." if name_text.empty?

    now_mono = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    entry = { name: name_text,
              due: now_mono + delay,              # monotonic — fires this process
              due_at: Time.now.to_f + delay,      # absolute unix — persisted, restart-safe
              task: task_text }
    replaced = full = false
    @followup_mutex.synchronize do
      # Cap counts only OTHER names: replacing your own timer is always ok.
      matches = @followups.count { |f| f[:name] == name_text }
      full = (@followups.size - matches) >= MAX_PENDING_FOLLOWUPS
      unless full
        @followups.reject! { |f| f[:name] == name_text }
        replaced = matches.positive?
        @followups << entry
        @followup_cond.signal  # wake the scheduler if this became the soonest
      end
    end
    if full
      return "Error: #{MAX_PENDING_FOLLOWUPS} follow-ups already pending (max #{MAX_PENDING_FOLLOWUPS}) — cancel one first."
    end
    # Task text is NOT echoed here — the tool-call line already logged the
    # full arguments; repeating it just duplicates long lines.
    verb = replaced ? 'rescheduled' : 'scheduled'
    log "follow-up '#{name_text}' #{verb} (in #{delay.round}s)"
    persist! if @session_path
    "Follow-up '#{name_text}' #{verb} for +#{delay.round}s."
  end

  # Cancel a pending follow-up by NAME (the key given to schedule_followup).
  # A follow-up the scheduler has already popped for firing can't be
  # cancelled. Returns the tool-result string for the model.
  def cancel_followup(name:)
    name_text = clean_text(name).to_s[0, MAX_FOLLOWUP_NAME_LEN]
    removed = @followup_mutex.synchronize do
      before = @followups.size
      @followups.reject! { |f| f[:name] == name_text }
      @followup_cond.signal if @followups.size < before
      before - @followups.size
    end
    return "Error: no follow-up named '#{name_text}' (already fired, cancelled, or never scheduled)." if removed.zero?
    log "follow-up '#{name_text}' cancelled"
    persist! if @session_path
    "Follow-up '#{name_text}' cancelled."
  end

  # Start the follow-up scheduler thread unless one is already running.
  # Called at the sniffer's reconstruction seam after every reload; also
  # revives a thread that died. Safe to call repeatedly.
  def ensure_followup_scheduler
    return if @disabled
    start_scheduler if @scheduler.nil? || !@scheduler.alive?
  end

  private

  # Per-turn prompt for a firing follow-up: the scheduled task + whatever
  # turn_prompt injects (fresh context snapshot, console lines queued since
  # the last prompt, player memories). The model may reply, query, schedule
  # again, or stay silent.
  def followup_prompt(task)
    turn_prompt(
      "SCHEDULED FOLLOW-UP — you set this for yourself earlier, and the time has come.\n" \
      "Task: #{task}\n\n" \
      'The context above is fresh (online players, console lines since your last turn). ' \
      'Check on the situation and act as you see fit: send a chat message (reply tool), ' \
      'run read-only queries (rcon_query), schedule another follow-up, or stay silent ' \
      "if nothing needs doing. Keep any message under #{HiveMindAgent::MAX_REPLY_LEN} characters.",
      player: nil
    )
  end

  # Fire a scheduled follow-up: one fresh LLM turn with the current context
  # + the task. Runs on the scheduler thread; complete() serializes with
  # player asks/greets via @mutex, so a follow-up never interleaves with a
  # live conversation — lines queued meanwhile are drained into its prompt.
  def fire_followup(entry)
    return if @disabled
    # Persist the pop BEFORE running the turn: the scheduler already deleted
    # the entry from @followups, so this drops it from the session file —
    # a crash mid-turn can't resurrect an already-fired follow-up on restart.
    persist! if @session_path
    log "follow-up '#{entry[:name]}' firing"
    reply = complete(followup_prompt(entry[:task]))
    send_reply(reply)
  rescue StandardError => e
    log_error("follow-up '#{entry[:name]}' failed", e)
  end

  # PLAYER PRIORITY: a follow-up that comes due while a conversation turn
  # (player ask, greeting, or another follow-up) holds @mutex is put back
  # with a pushed-out due time instead of piling onto the lock — an agentic
  # turn (tool loops run tens of seconds) must not make players queue
  # behind self-churned heartbeats, and back-to-back follow-ups must not
  # monopolize the agent between player messages. Re-checked on the next
  # wakeup; fires once the agent goes idle. Not persisted (due_at keeps the
  # original deadline — after a restart it simply fires then). Returns
  # true when the entry should fire NOW.
  def yield_to_conversation(entry)
    return true unless @mutex.locked?
    @followup_mutex.synchronize do
      entry[:due] = Process.clock_gettime(Process::CLOCK_MONOTONIC) + FOLLOWUP_YIELD_DELAY
      @followups << entry
      @followup_cond.signal
    end
    false
  end

  # Background thread that fires due follow-ups. Holds @followup_mutex for
  # the check-and-sleep atomically (ConditionVariable#wait releases it while
  # sleeping), so schedule_followup's signal can never be lost: it either
  # wakes the wait or the loop re-checks right after. The thread survives
  # hot reloads (the agent object persists — the block still resolves
  # methods against the reloaded classes) and is recreated on a full
  # restart when pending follow-ups are re-armed from the session file.
  def start_scheduler
    @scheduler = Thread.new do
      loop do
        begin
          entry = @followup_mutex.synchronize do
            now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
            idx = @followups.index { |f| f[:due] <= now }
            if idx
              @followups.delete_at(idx)
            else
              next_due = @followups.map { |f| f[:due] }.min
              wait = next_due ? [next_due - now, 60.0].min : 60.0
              @followup_cond.wait(@followup_mutex, wait)
              nil
            end
          end
          fire_followup(entry) if entry && yield_to_conversation(entry)
        rescue StandardError => e
          log_error('follow-up scheduler error', e)
        end
      end
    end
  end
end
