#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the game-log tail (lib/log_tail.rb): starts at EOF, yields new
# lines, survives truncation/rotation and file-disappeared races.
# Run: ruby -Ilib test/log_tail_spec.rb

require 'minitest/autorun'
require 'tmpdir'
require_relative '../lib/log_tail'

class TestLogTail < Minitest::Test
  def read_for(path, lines_wanted, timeout: 3.0)
    got = []
    t = Thread.new { LogTail.follow(path) { |line| got << line } }
    deadline = Time.now + timeout
    t.join(0.05) while got.size < lines_wanted && Time.now < deadline
    t.kill
    got
  end

  def test_yields_lines_appended_after_follow_started
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'factorio-current.log')
      File.write(path, "old line that must NOT be replayed\n")
      thread = Thread.new do
        sleep 0.2 # let follow seek to EOF first
        File.open(path, 'a') { |f| f.puts('first new line'); f.puts('second new line') }
      end
      got = read_for(path, 2)
      thread.join
      assert_equal ['first new line', 'second new line'], got
    end
  end

  def test_survives_truncation_and_replays_new_content
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'log.txt')
      File.write(path, "seed line to make the file non-empty\n")
      appender = Thread.new do
        sleep 0.3
        # Simulate a rotated/truncated log: same path, fresh short content.
        File.write(path, "post-rotate line\n")
      end
      got = read_for(path, 1)
      appender.join
      assert_includes got, 'post-rotate line'
    end
  end

  def test_starts_when_file_appears_later
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'later.log')
      # follow() requires the file to exist at start (caller decides when);
      # verify it raises SystemCallError rather than hanging silently.
      assert_raises(SystemCallError) { LogTail.follow(path) {} }
    end
  end
end
