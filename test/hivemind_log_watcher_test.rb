#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the game-log watcher (lib/hivemind_logwatcher.rb + log_tail.rb wiring):
# keyed lines reach the console queue, first match in the window fires a
# turn (repeats stay queue-only), and auto-compaction is gated on history.
# Run: ruby -Ilib test/hivemind_log_watcher_test.rb

require_relative 'hivemind_helper'

class TestHivemindLogWatcher < Minitest::Test
  include HivemindSpecHelpers

  # Real log lines (factorio-current.log, reset.lua), reduced to the fields
  # this feature reads: a 0-minute /reset, a 9-minute round, and real ones.
  RESET_0 = '1.0 Script @__level__/reset.lua:28: event=map-reset, actor=morganc, victory=false, science=0, minutes=0'
  RESET_9 = '1.0 Script @__level__/reset.lua:28: event=map-reset, actor=morganc, victory=false, science=0, minutes=9'
  RESET_10 = '1.0 Script @__level__/reset.lua:28: event=map-reset, actor=morganc, victory=false, science=0, minutes=10'
  RESET_45 = '2.0 Script @__level__/reset.lua:30: event=map-reset, actor=morganc, victory=false, science=0, minutes=45'
  RESET_44 = '2541.706 Script @__level__/reset.lua:291: event=map-reset, actor=morganc, victory=false, science=0, minutes=44'

  def setup
    @agent = make_agent
    @logwatcher = @agent.plugins[:logwatcher] # the FEATURE (a class), not the agent
    reset_window!
    collect_completions
  end


  # ── Line handling ──────────────────────────────────────────────

  def test_map_reset_line_is_queued_and_fires_turn
    @logwatcher.handle_log_line(RESET_44, async: false)
    assert_equal 1, captured_prompts.size, 'first match in the window fires a dedicated turn'
    prompt = captured_prompts.first
    assert_includes prompt, 'Game server log event'
    assert_includes prompt, 'event=map-reset, actor=morganc', 'event reaches the model'
    # prefix stripped (no timestamp / Script path anywhere)
    refute_includes prompt, '2541.706'
    refute_includes prompt, 'reset.lua'
  end

  def test_uninteresting_lines_are_ignored
    @logwatcher.handle_log_line('   3.200 Connection Accept from 1.2.3.4', async: false)
    assert_empty captured_prompts
    assert_empty queued_lines
  end

  def test_repeats_within_interval_stay_queue_only
    # real rounds (>= MIN_ROUND_MINUTES) so this is the INTERVAL under test,
    # not the short-round filter
    @logwatcher.handle_log_line(RESET_44, async: false) # fires + drains queue
    assert_empty queued_lines
    @logwatcher.handle_log_line(RESET_45, async: false) # repeat: queue only
    assert_equal 1, captured_prompts.size, 'repeat must not trigger a turn'
    assert_includes queued_lines.join("\n"), 'minutes=45'
  end


  # ── Auto-compaction gate ───────────────────────────────────────

  def test_auto_compaction_skipped_on_thin_session
    compacted = collect_compactions
    @logwatcher.handle_log_line(RESET_44, async: false)
    wait_for_turn_thread
    assert_empty compacted, 'thin session must not waste a compaction pass'
  end

  def test_auto_compaction_runs_after_trigger_when_history_sufficient
    compacted = collect_compactions
    pad = 'x' * @agent.auto_compaction_min_chars
    @agent.instance_variable_get(:@chat).add_message(role: :user, content: pad)
    @logwatcher.handle_log_line(RESET_44, async: false)
    wait_for_turn_thread
    assert_includes compacted, 'map reset'
  end

  # A reset that is not a round ending: still context for the next prompt,
  # but no turn and no compaction (both are paid LLM calls).
  def test_short_rounds_are_queued_but_fire_nothing
    compacted = collect_compactions
    3.times { @logwatcher.handle_log_line(RESET_0, async: false) }
    @logwatcher.handle_log_line(RESET_9, async: false)
    @logwatcher.handle_log_line('1.0 Script x.lua:1: event=player-died, actor=a', async: false)

    assert_empty captured_prompts, 'a /reset fires no turn'
    assert_empty compacted, 'and no compaction'
    assert_equal 5, queued_lines.size, 'but every event line is still context for the next prompt'
    assert_includes queued_lines.first, 'minutes=0'
  end

  def test_a_round_of_ten_minutes_still_reacts
    compacted = collect_compactions
    pad = 'x' * @agent.auto_compaction_min_chars
    @agent.instance_variable_get(:@chat).add_message(role: :user, content: pad)
    @logwatcher.handle_log_line(RESET_10, async: false)
    wait_for_turn_thread

    assert_includes compacted, 'map reset', 'ten minutes is a real round'
  end

  def test_successful_auto_compaction_trims_so_repeated_reset_skips
    collect_completions
    chat = @agent.instance_variable_get(:@chat)
    # Many normal-sized turns totalling the gate (a single huge message
    # would survive the trim's keep-at-least-one rule — real sessions
    # are many messages, and the trim keeps only a ~20k tail of those).
    # ~400 x 1k messages to clear the 10x gate (~400k chars).
    400.times { |i| chat.add_message(role: :user, content: "turn #{i} #{'x' * 1000}") }
    assert @agent.send(:auto_compaction_worthwhile?), 'setup: session above the gate'
    # Real compact_memory! would hit the network — stub a SUCCESSFUL pass
    # but mirror its side effect (recording how much it saw) so the real
    # trim that run_log_event_turn performs drops the compacted range.
    chat = @agent.instance_variable_get(:@chat)
    @agent.stubs(:compact_memory!).with do
      @agent.instance_variable_set(:@compaction_included_count, chat.messages.size)
      true
    end.returns(true)
    @logwatcher.handle_log_line(RESET_44, async: false)
    refute @agent.send(:auto_compaction_worthwhile?), 'trimmed session must fall below the auto-compaction gate so a repeated reset skips'
  end


  # ── Watcher thread lifecycle ───────────────────────────────────

  def test_ensure_log_watcher_requires_existing_file
    refute @logwatcher.ensure_log_watcher('/nonexistent/factorio-current.log')
  end


  private

  def reset_window!
    @agent.instance_variable_set(:@last_log_event, 0.0)
  end

  # Collect prompts the handler builds instead of hitting the network.
  # define_singleton_method, not stub: the handler's turn runs on its OWN
  # thread and may call in after this helper returns, so the override has to
  # live for the rest of the test (a block-scoped stub would be gone).
  def collect_completions
    @agent.define_singleton_method(:complete) do |p|
      ivars = instance_variables.include?(:@captured_prompts) ? @captured_prompts : []
      @captured_prompts = ivars << p
      ''
    end
  end

  def captured_prompts
    @agent.instance_variable_get(:@captured_prompts) || []
  end

  # same: the turn thread may fire the compaction after we hand back
  def collect_compactions
    seen = []
    @agent.define_singleton_method(:compact_memory!) { |reason = nil| seen << reason; true }
    seen
  end

  # The handler runs its turn on its own thread; give it a moment.
  def wait_for_turn_thread = sleep 0.2

  def queued_lines
    @agent.instance_variable_get(:@console_queue).map { |_p, m| m }
  end
end
