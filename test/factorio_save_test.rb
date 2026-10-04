#!/usr/bin/env ruby
# frozen_string_literal: true

# The save format's string container and the player-record scanner
# (lib/factorio_save.rb). The CLI over it is test/save_roster_test.rb.
require 'minitest/autorun'
require 'mocha/minitest'
require 'factorio_save'

class TestFactorioSave < Minitest::Test
  def s(str, nul: true)
    "#{str.bytesize.chr}#{str}#{nul ? "\0" : ''}".b
  end

  # ── the string container ───────────────────────────────────────────

  def test_reads_a_length_prefixed_nul_terminated_string
    data = "\xAA".b + s('Jeff-nf') + 'tail'
    assert_equal ['Jeff-nf', 10], FactorioSave.string_at(data, 1), 'consumed the NUL'
    assert_equal Encoding::UTF_8, FactorioSave.string_at(data, 1)[0].encoding
  end

  def test_non_ascii_survives_as_utf8
    data = s('sévérin')
    assert_equal 'sévérin', FactorioSave.string_at(data, 0)[0]
  end

  # A string whose terminator is missing is a MISDECODE, not a short read:
  # nil, so the caller can keep the frame instead of logging garbage.
  def test_a_missing_nul_terminator_is_refused
    assert_nil FactorioSave.string_at(s('alice', nul: false), 0)
    assert_nil FactorioSave.string_at("\x07al".b, 0), 'truncated body'
    assert_nil FactorioSave.string_at('x'.b, 5), 'offset past the end'
    assert_nil FactorioSave.string_at("\x00\x00".b, 0), 'a zero length is a nil field'
    # 0xFF is the varint escape, not a length: [0xFF][u32 LE]
    assert_equal ["abcd", 10], FactorioSave.string_at("\xFF\x04\x00\x00\x00abcd\0".b, 0)
  end

  # The 0xFF escape in a SAVE string is unverified in the wild (every length we
  # have seen is one byte), so the shared reader decodes it as the varint the
  # packet protocol uses rather than refusing it.
  def test_a_long_string_uses_the_varint_escape
    long = 'x' * 300
    data = "\xFF".b + [long.bytesize].pack('V') + long.b + "\x00".b
    assert_equal [long, 306], FactorioSave.string_at(data, 0)
  end

  # The PACKET protocol uses the same length-prefixed shape with no verified
  # terminator (msg 4: `04 "base" 02 00`), so the reader is told, not guessed.
  def test_packet_style_strings_skip_the_terminator_check
    data = "\x04base\x02\x00".b
    assert_equal ['base', 5], FactorioSave.string_at(data, 0, nul: false)
    assert_nil FactorioSave.string_at(data, 0), 'with nul: true this is a bad read'
  end

  def test_string_chain_reads_a_run_and_stops_at_the_first_non_string
    data = s('Foundry') + s('djimbro') + s('Q') + "\x01\x01\x00\x01\x01".b
    strings, after = FactorioSave.string_chain(data, 0)
    assert_equal %w[Foundry djimbro Q], strings
    assert_equal 21, after, 'the chain stops where a string cannot start'
    assert_equal [], FactorioSave.string_chain("\x01\x01".b, 0)[0], 'an empty run is not a run'
  end

  def test_tags_at_is_nil_without_tags
    assert_equal %w[Foundry Q], FactorioSave.tags_at(s('Foundry') + s('Q'), 0)
    assert_nil FactorioSave.tags_at("\x00\x00".b, 0)
  end

  # ── the player-record scanner ──────────────────────────────────────

  # filler, then LuaPlayer.color 33 bytes before the name (four f32), the
  # [play][0][last][0] u64 pair, the name field, and the locale in its
  # `01 00 [len][bytes] 00 00 00 00 ff ff ff` framing
  def record(name, play = nil, last_seen = nil, locale = 'en', color = [0.815, 0.024, 0.0, 0.5])
    stats = play ? [play, 0, last_seen, 0].pack('V4') : ("\xa5" * 16)
    col = color ? color.pack('f4') : ("\xa5" * 16)
    loc = locale ? "\x01\x00#{locale.bytesize.chr}#{locale}\x00\x00\x00\x00\xff\xff\xff".b : ''.b
    # the colour starts exactly 33 bytes before the name (4 + 13 + 16)
    ("\xa5" * 200).b + stats.b + col.b + ("\xa5" * 13).b +
      "\x00\x80\x3f".b + name.bytesize.chr.b + name.b + "\x00\x00".b + loc
  end

  def roster_of(stream)
    FactorioSave::Roster.new([stream]).records
  end

  def test_reads_name_play_time_last_online_locale_and_colour
    records = roster_of(record('alice', 1000, 90_000, 'de', [0.815, 0.024, 0.0, 0.5]) +
                        record('bob', 2000, 91_000, 'pl', [1.0, 1.0, 0.0, 0.5]))
    players = records.select { |r| r[:online_time_ticks] } # the roster
    assert_equal %w[alice bob], players.map { |r| r[:name] }
    assert_equal [1000, 2000], players.map { |r| r[:online_time_ticks] }
    assert_equal [90_000, 91_000], players.map { |r| r[:last_online_tick] }
    assert_equal %w[de pl], players.map { |r| r[:locale] }
    assert_equal [[0.815, 0.024, 0.0, 0.5], [1.0, 1.0, 0.0, 0.5]], players.map { |r| r[:color] }
  end

  # The name signature alone also matches prototype/chat strings; the stat
  # pair is what makes a record a PLAYER record (client mode, no cache).
  def test_a_name_without_the_pair_is_not_a_player_record
    records = roster_of(record('coal') + record('alice', 1000, 90_000) + record('Gleba'))
    assert_equal %w[coal alice Gleba], records.map { |r| r[:name] }
    assert_equal ['alice'], records.select { |r| r[:online_time_ticks] }.map { |r| r[:name] }
  end

  # A locale match belongs to the record it falls inside: the next record's
  # name is the boundary (the search window reaches past it).
  def test_a_locale_is_never_borrowed_from_the_next_record
    records = roster_of(record('alice', 1, 900, 'de') + record('bob', 2, 901, nil))
    assert_equal 'de', records[0][:locale]
    assert_nil records[1][:locale], 'bob has no locale field of his own'
  end

  def test_scanning_survives_chunk_boundaries
    stream = record('alice', 1000, 90_000) + record('bob', 2000, 91_000)
    chunks = (0...stream.bytesize).step(7).map { |i| stream.byteslice(i, 7) } # tear every field
    records = FactorioSave::Roster.new(chunks).records.select { |r| r[:online_time_ticks] }
    assert_equal %w[alice bob], records.map { |r| r[:name] }
    assert_equal [1000, 2000], records.map { |r| r[:online_time_ticks] }
  end
end
