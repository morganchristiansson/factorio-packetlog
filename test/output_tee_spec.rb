# frozen_string_literal: true

# Tests for the console history tee (OutputTee in factorio-sniffer.rb):
# everything printed lands in both streams, puts keeps its newline
# semantics, and concurrent threads never interleave mid-line.
# Run: ruby -Ilib test/output_tee_spec.rb

# Entry first: its bundler/setup must run before any gem activation.
require_relative '../factorio-sniffer'
require 'minitest/autorun'
require 'stringio'

class TestOutputTee < Minitest::Test
  def tee
    a = StringIO.new
    b = StringIO.new
    [OutputTee.new(a, b, Mutex.new), a, b]
  end

  def test_write_goes_to_both
    t, a, b = tee
    t.write('hi')
    assert_equal 'hi', a.string
    assert_equal 'hi', b.string
  end

  def test_puts_newline_semantics
    t, a, b = tee
    t.puts('x', "y\n", nil, %w[p q])
    assert_equal "x\ny\n\np\nq\n", a.string
    assert_equal a.string, b.string
  end

  def test_concurrent_puts_stay_whole
    t, a, _b = tee
    threads = 2.times.map do |tno|
      Thread.new { 200.times { |i| t.puts("t#{tno}-#{i}") } }
    end
    threads.each(&:join)
    lines = a.string.lines
    assert_equal 400, lines.size
    assert(lines.all? { |l| l.match?(/\At[01]-\d+\n\z/) })
    assert_equal 400, lines.uniq.size
  end
end
