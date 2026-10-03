# frozen_string_literal: true
require 'minitest/autorun'
require 'json'
require 'tmpdir'
require 'open3'

# tools/extract_players_from_save.rb — recovering the roster (index -> name)
# from a save. The record layout is the save's, so the fixture is the little
# that matters: a name field is `[len][name]` preceded by the tail of a 1.0f.
class TestExtractPlayersFromSave < Minitest::Test
  TOOL = File.expand_path('../tools/extract_players_from_save.rb', __dir__)

  # 300 bytes of filler, then the [play][0][last_online][0] u64 pair, then
  # the name field (the anchor the tool looks for), then the locale string in
  # its `01 00 [len][bytes] 00 00 00 00 ff ff ff` framing. The filler is
  # non-zero so a byte-shifted decoy pair can't be formed out of it, and 300
  # bytes keeps each record out of the next one's 140-byte stats window (real
  # records are 8 KB … 2.4 MB apart).
  def record(name, play = nil, last_seen = nil, locale = 'en')
    stats = play ? [play, 0, last_seen, 0].pack('V4') : "\xa5" * 16
    loc = "\x01\x00#{locale.bytesize.chr}#{locale}\x00\x00\x00\x00\xff\xff\xff".b
    ("\xa5" * 300).b + stats.b + "\x00\x80\x3f".b + name.bytesize.chr.b + name.b + "\x00\x00".b + loc
  end

  # prototype names (the rest of the stream), the roster, then a chat message
  def stream
    [record('coal'), record('copper-ore'), record('Base Supplies'),
     record('alice', 1000, 90_000, 'de'), record('bob', 2000, 91_000, 'pl'),
     record('carol', 3000, 92_000), record('Gleba')].join.b
  end

  def run_tool(cache, level = stream)
    Dir.mktmpdir do |dir|
      dat = File.join(dir, 'level.dat')
      File.binwrite(dat, level)
      cache_file = File.join(dir, 'players-cache.json')
      File.write(cache_file, JSON.generate(cache)) if cache
      ruby = RbConfig.ruby
      out, err, status = Open3.capture3(ruby, TOOL, dat, cache_file)
      Open3.capture3(ruby, TOOL, dat, cache_file, '--merge') # merge into cache_file
      brace = out.index('{')
      roster = brace ? JSON.parse(out[brace..]) : nil
      yield JSON.parse(File.read(cache_file)), roster, out, err, status
    end
  end

  # Client mode: nobody has joined yet, so the cache is empty and the run has
  # to be found from the records alone — a player record is one with the
  # play-time pair in front of the name, which the prototype names lack.
  def test_finds_the_roster_with_no_cache_at_all
    run_tool(nil) do |merged, roster, out, _err, status|
      assert_predicate status, :success?, out
      assert_includes out, 'record structure alone'
      assert_equal %w[alice bob carol], roster.values.map { |r| r['name'] }
      assert_equal({'1' => 'alice', '2' => 'bob', '3' => 'carol'},
                   merged.transform_values { |v| v['name'] })
    end
  end

  def test_recovers_the_whole_roster_around_the_known_anchors
    run_tool({'3' => {'name' => 'carol'}}) do |merged, _roster, out, _err, status|
      assert_predicate status, :success?, out
      assert_includes out, 'new: 2'
      # indexes come from the record's position, not from the cache
      assert_equal({'1' => 'alice', '2' => 'bob', '3' => 'carol'},
                   merged.transform_values { |v| v['name'] })
    end
  end

  def test_reads_play_time_and_last_online_tick_per_record
    run_tool({'3' => {'name' => 'carol'}}) do |_merged, roster, _out, _err, status|
      assert_predicate status, :success?
      assert_equal({'name' => 'bob', 'online_time_ticks' => 2000, 'last_online_tick' => 91_000, 'locale' => 'pl'},
                   roster['2'])
      assert_equal [1000, 2000, 3000], roster.values.map { |p| p['online_time_ticks'] }
    end
  end

  # The locale is a plain string in the record, so it comes out with the rest
  # of it — and a merge only fills a locale the cache does not have.
  def test_locale_is_read_and_merged_without_overwriting
    run_tool({'1' => {'name' => 'alice', 'locale' => 'fr'}}) do |merged, roster, out, _err, _status|
      assert_equal 'de', roster['1']['locale']
      assert_equal 'en', roster['3']['locale']
      assert_includes out, 'locale: 3/3'
      assert_equal 'fr', merged['1']['locale'], 'a known locale is never overwritten'
      assert_equal 'pl', merged['2']['locale'], 'a missing one is filled'
    end
  end

  def test_refuses_to_merge_a_save_from_another_world
    cache = {'2' => {'name' => 'bob', 'locale' => 'de'}, '9' => {'name' => 'alice'}}
    run_tool(cache) do |merged, _roster, out, err, status|
      refute_predicate status, :success?
      assert_includes out + err, 'disagree'
      assert_equal cache, merged # untouched
    end
  end
end
