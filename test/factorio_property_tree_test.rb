#!/usr/bin/env ruby
# frozen_string_literal: true

# FactorioPropertyTree — the mod-settings.dat / msg-4 settings container,
# implemented from the reference codec (whitequark/factorio-data-codec, pinned
# by /factorio-legendary-deathworld/tools/sync-mod-settings) and verified
# against a real client's join (test/fixtures/frag_confirm_{0..5}.bin).
require 'minitest/autorun'
require 'mocha/minitest'
require 'factorio_protocol'
require 'factorio_property_tree'

class TestFactorioPropertyTree < Minitest::Test
  def blob(*parts)
    parts.join.b
  end

  def dict(entries)
    "\x05\x00".b + [entries.size].pack('V') +
      entries.map { |k, v| "\x00#{k.bytesize.chr}#{k}".b + v }.join
  end

  def bool(v) = "\x01\x00#{v.zero? ? "\x00" : "\x01"}".b
  def string(s) = s.bytesize >= 0xFF ? "\x03\x00\x00\xff#{[s.bytesize].pack('V')}".b + s.b : "\x03\x00\x00#{s.bytesize.chr}#{s}".b

  def test_reads_bools_strings_and_nested_dictionaries
    data = dict([['off', bool(0)], ['on', bool(1)], ['name', string('morganc')],
                 ['nested', dict([['inner', string('x')]])]])
    value, after = FactorioPropertyTree.value(data, 0)
    assert_equal({ 'off' => false, 'on' => true, 'name' => 'morganc',
                   'nested' => { 'inner' => 'x' } }, value)
    assert_equal data.bytesize, after, 'the walk consumes exactly the blob'
  end

  def test_numbers_and_ints
    data = "\x02\x00".b + [1.5].pack('E') + "\x06\x00".b + [-7].pack('q<') + "\x07\x00".b + [9].pack('Q<')
    assert_equal [1.5, 10], FactorioPropertyTree.value(data, 0)
    assert_equal(-7, FactorioPropertyTree.value(data, 10)[0])
    assert_equal [9, 30], FactorioPropertyTree.value(data, 20)
  end

  # The 0xFF escape: a settings string of 1708 bytes (the mod-tech
  # description in the real join) — without it the walk loses alignment.
  def test_a_long_string_uses_the_escape_and_keeps_the_walk_aligned
    long = 'x' * 300
    data = dict([['k', string(long)]])
    value, after = FactorioPropertyTree.value(data, 0)
    assert_equal({ 'k' => long }, value)
    assert_equal data.bytesize, after
  end

  def test_a_null_string_is_a_present_value_pair
    assert_equal [nil, 1], FactorioPropertyTree.string("\x01".b, 0)
    assert_equal ['', 2], FactorioPropertyTree.string("\x00\x00".b, 0)
  end

  def test_a_malformed_blob_is_refused_rather_than_guessed
    assert_nil FactorioPropertyTree.value("\x7f\x00\x00\x00".b, 0), 'unknown type'
    assert_nil FactorioPropertyTree.value("\x01\x00".b, 0), 'truncated bool'
    assert_nil FactorioPropertyTree.value("\x05\x00\xff\xff\xff\xff".b, 0), 'absurd count'
  end

  # ── the real thing ────────────────────────────────────────────────
  # morganc's join: the 10 settings his client sent, decoded to the end of
  # the message. This is what pinned the format (the spec's `is_none` byte is
  # 0 for a PRESENT string) — the keys and values line up with the mod's
  # data/mod-settings.json template on the server.
  def test_the_real_join_settings_decode_to_the_end_of_the_message
    msg = FactorioProtocol.reassemble_fragments((0..5).map { |n| fixture(n) })
    at = 12
    len = msg.getbyte(at)
    at += 1 + len + 11
    count = msg.getbyte(at)
    at += 1
    count.times { at += 1 + msg.getbyte(at) + 7 } # skip the mods (the packet's own framing)
    settings, after = FactorioPropertyTree.value(msg, at)
    assert_equal msg.bytesize, after, 'the settings run to the exact end of the message'
    assert_equal 10, settings.size
    assert_equal({ 'value' => false }, settings['eon-holmium-ore'])
    assert_equal '', settings['wall-repair-ignore']['value']
    assert_includes settings['custom-spawn-rates-tech']['value'], '# Fulgora; recycling:'
    # his own edited value (the template default is 0.0001, this is 0.0025)
    assert_includes settings['custom-spawn-rates-biter-spawner']['value'], '0.35=0.0025'
  end

  def fixture(n)
    File.binread(File.join(__dir__, 'fixtures', "frag_confirm_#{n}.bin"))
  end

  # The mod-settings.dat envelope: version(4×u16) + has_quality + the data
  # tree. A client's msg 4 carries the data tree only (no envelope), which is
  # why the join payload starts straight at `05 00`.
  def test_the_mod_settings_envelope
    data = [2, 0, 77, 0].pack('v4') + "\x00" +
           dict([['startup', dict([['k', dict([['value', string('v')]])]])],
                 ['runtime-global', dict([])], ['runtime-per-user', dict([])]])
    env, after = FactorioPropertyTree.mod_settings(data)
    assert_equal [2, 0, 77, 0], env[:version]
    refute env[:has_quality]
    assert_equal %w[startup runtime-global runtime-per-user], env[:data].keys
    assert_equal({ 'value' => 'v' }, env[:data]['startup']['k'])
    assert_equal data.bytesize, after
  end
end
