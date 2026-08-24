#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the game-log watcher (hivemind.rb + log_tail.rb wiring):
# keyed lines reach the console queue, first match in the window fires a
# turn (repeats stay queue-only), and auto-compaction is gated on history.
# Run: ruby -Ilib test/hivemind_log_watcher_spec.rb

require_relative 'hivemind_helper'

class TestHivemindLogWatcher < Minitest::Test
  include HivemindSpecHelpers

  def setup
    @agent = make_agent
    reset_window!
    collect_completions
  end


  # ── Line handling ──────────────────────────────────────────────

  def test_map_reset_line_is_queued_and_fires_turn
    @agent.handle_log_line('   14.511 Script @__level__/reset.lua:284: map reset: victory=false, science=29255, minutes=1025', async: false)
    assert_equal 1, captured_prompts.size, 'first match in the window fires a dedicated turn'
    prompt = captured_prompts.first
    assert_includes prompt, 'Game server log event'
    assert_includes prompt, 'map reset: victory=false', 'event reaches the model'
    # prefix stripped (no timestamp / Script path anywhere)
    refute_includes prompt, '14.511'
    refute_includes prompt, 'reset.lua'
  end

  def test_uninteresting_lines_are_ignored
    @agent.handle_log_line('   3.200 Connection Accept from 1.2.3.4', async: false)
    assert_empty captured_prompts
    assert_empty queued_lines
  end

  def test_repeats_within_interval_stay_queue_only
    @agent.handle_log_line('1.0 Script x.lua:1: map reset: one', async: false) # fires + drains queue
    assert_empty queued_lines
    @agent.handle_log_line('2.0 Script x.lua:2: map reset: two', async: false) # repeat: queue only
    assert_equal 1, captured_prompts.size, 'repeat must not trigger a turn'
    assert_includes queued_lines.join("\n"), 'map reset: two'
  end


  # ── Auto-compaction gate ───────────────────────────────────────

  def test_auto_compaction_skipped_on_thin_session
    compacted = collect_compactions
    @agent.handle_log_line('1.0 Script x.lua:1: map reset: fresh world', async: false)
    wait_for_turn_thread
    assert_empty compacted, 'thin session must not waste a compaction pass'
  end

  def test_auto_compaction_runs_after_trigger_when_history_sufficient
    compacted = collect_compactions
    pad = 'x' * HiveMindAgent::AUTO_COMPACTION_MIN_CHARS
    @agent.instance_variable_get(:@chat).add_message(role: :user, content: pad)
    @agent.handle_log_line('1.0 Script x.lua:1: map reset: end of round', async: false)
    wait_for_turn_thread
    assert_includes compacted, 'map reset'
  end


  # ── Watcher thread lifecycle ───────────────────────────────────

  def test_ensure_log_watcher_requires_existing_file
    refute @agent.ensure_log_watcher('/nonexistent/factorio-current.log')
  end


  private

  def reset_window!
    @agent.instance_variable_set(:@last_log_event, 0.0)
  end

  # Collect prompts the handler builds instead of hitting the network.
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
