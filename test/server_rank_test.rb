#!/usr/bin/env ruby
# Checks for tools/server_rank.rb: ranking/report + msg-17 parser.
require 'minitest/autorun'
require_relative '../tools/server_rank'

def fake_server(name, n, version = '2.0.77')
  { 'name' => name, 'players' => Array.new(n) { 'p' },
    'application_version' => { 'game_version' => version } }
end

# Minimal synthetic msg-17 payload (no desc/tags, 1 mod, 2 players).
def fake_reply
  p = "\x00" * 12
  p += [4, 'Test'].pack('Ca4')
  p += [2, 0, 77].pack('C3')
  p += [84539].pack('V')
  p += [0].pack('C')
  p += [4 * 65536, 0].pack('V2')
  p += [9, '1.2.3.4:5'].pack('Ca9')
  p += "\x01\x00\x01"
  p += [1].pack('C')
  p += [4, 'base', 2, 0, 77, 0x70059c86].pack('Ca4C3V')
  p += [0].pack('C')
  p += [2, 3, 'bob', 5, 'alice'].pack('CCa3Ca5')
  p += "\x01"
  p.b
end

class ServerRankSpec < Minitest::Test
  def test_sorted_by_player_count_missing_players_is_zero
    sorted = ranked_servers([fake_server('a', 1), { 'name' => 'b', 'application_version' => { 'game_version' => '2.0.77' } }, fake_server('c', 5)])
    assert_equal %w[c a b], sorted.map { |s| s['name'] }
  end

  def test_strip_tags_and_match_report
    list = ranked_servers([fake_server('[color=red]Mine[/color]', 3), fake_server('other', 9)])
    lines = rank_report(list, top: 1, match: 'mine')
    assert_match(/#1 other/, lines.first)
    assert_match(/Mine is #2 with 3 players/, lines.join("\n"))
    assert_equal 'Mine', strip_tags('[color=red]Mine[/color]')
  end

  def test_locked_hidden_by_default
    list = [fake_server('Open', 5).merge('has_password' => false), fake_server('Shut', 9).merge('has_password' => true)]
    assert_equal %w[Open], ranked_servers(list).map { |s| s['name'] }
    assert_equal %w[Shut Open], ranked_servers(list, include_locked: true).map { |s| s['name'] }
    lines = rank_report(ranked_servers(list), top: 5, match: 'shut',
                         pool: ranked_servers(list, include_locked: true))
    assert_match(/Shut is #1 with 9 players.*🔒/, lines.join("\n"))
  end

  def test_version_filter_and_no_match
    sorted = ranked_servers([fake_server('a', 9, '2.1.17'), fake_server('b', 1, '2.0.77')], '2.0')
    assert_equal %w[b], sorted.map { |s| s['name'] }
    assert_match(/No server matching/, rank_report(sorted, top: 5, match: 'zzz').join("\n"))
  end

  def test_parse_server_info
    info = FactorioProtocol.parse_game_info(fake_reply)
    assert_equal 'Test', info[:name]
    assert_equal '2.0.77', info[:version]
    assert_equal 84539, info[:build]
    assert_equal '1.2.3.4:5', info[:host]
    assert_equal 4.0, info[:time_min]
    assert_equal [['base', '2.0.77']], info[:mods]
    assert_equal %w[bob alice], info[:players]
    assert_equal [], info[:tags]
  end

  def test_normalize_addr
    require_relative '../tools/query_server'
    assert_equal '1.2.3.4:34197', normalize_addr('1.2.3.4:34197')
    assert_equal '1.2.3.4:34197', normalize_addr('1.2.3.4')
    assert_equal '[2003:dd::1]:34197', normalize_addr('2003:dd::1')
    assert_equal '[2003:dd::1]:34197', normalize_addr('[2003:dd::1]:34197')
    assert_nil normalize_addr('chill')
  end

  def test_parse_server_info_truncated_returns_nil
    assert_nil FactorioProtocol.parse_game_info(fake_reply[0, 20])
    assert_nil FactorioProtocol.parse_game_info(fake_reply[0, 60])
  end

  def test_parse_server_info_uint32v_counts
    # Heavily-modded servers send counts in uint32v long form (0xFF + u32 LE
    # — a 505-mod server sends FF F9 01 00 00); a plain-u8 read decodes 255
    # and desyncs tags/players into garbage ("114 players" of mod-list bytes).
    ext = fake_reply.sub("\x01\x00\x01\x01".b, "\x01\x00\x01\xff\x01\x00\x00\x00".b)
                     .sub("\x00\x02\x03bob".b, "\x00\xff\x02\x00\x00\x00\x03bob".b)
    assert_equal fake_reply.bytesize + 8, ext.bytesize # anchors hit
    info = FactorioProtocol.parse_game_info(ext)
    assert_equal [['base', '2.0.77']], info[:mods]
    assert_equal %w[bob alice], info[:players]
  end

  def test_resolve_version_implies_server_version
    list = [fake_server('Mine', 3, '2.0.77'), fake_server('Other', 9, '2.1.17')]
    v, note = resolve_version(list, server: 'mine', version: nil, all_versions: false)
    assert_equal '2.0.77', v
    assert_match(/2\.0\.77 servers only/, note)
    v, = resolve_version(list, server: 'mine', version: '2.1', all_versions: false)
    assert_equal '2.1', v
    v, note = resolve_version(list, server: 'mine', version: nil, all_versions: true)
    assert_nil v
    assert_nil note
    v, = resolve_version(list, server: 'zzz', version: nil, all_versions: false)
    assert_nil v
  end

  def test_live_counts_annotated_in_report
    s = { 'name' => 'Mine', 'host_address' => '1.2.3.4:5', 'players' => %w[a b c],
          'application_version' => { 'game_version' => '2.0.77' } }
    lines = rank_report([s], top: 1, match: 'mine', live: { '1.2.3.4:5' => 5 })
    assert_match(/live: 5/, lines.first)
    assert_match(/with 5 players @ 1\.2\.3\.4:5 \(live\)/, lines.join("\n"))
  end
end
