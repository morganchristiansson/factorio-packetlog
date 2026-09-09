#!/usr/bin/env ruby
# frozen_string_literal: true
# Server rank by player count — without leaving the game, without hammering
# Wube's API.
#
# Seed once from the matchmaking API (cached at ~/.cache/factorio-server-list.json),
# then refresh counts directly from the servers over UDP (ServerQuery).
# Cache hits mean zero official-API traffic. `--say` prints in-game via RCON.
#
# Usage:
#   ruby tools/server_rank.rb --server "my server"              # rank + top 10 (snapshot)
#   ruby tools/server_rank.rb --server foo --live               # re-check shown servers via UDP
#   ruby tools/server_rank.rb --server foo --live --say         # also print in-game via RCON
#   ruby tools/server_rank.rb --refresh-all --live              # full UDP sweep (minutes), purely live rank
#   ruby tools/server_rank.rb --reseed                          # force fresh API seed, rewrite cache
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'optparse'
require 'matchmaking'
require 'server_query'

# Server names carry Factorio rich-text ([color=...], [img=...]); strip for chat/stdout.
def strip_tags(s)
  s.to_s.gsub(/\[[^\]]*\]/, '').strip.squeeze(' ')
end

def player_count(s)
  (s['players'] || []).length
end

# Descending by player count. Missing "players" key = empty server (0).
# Passworded servers hidden by default (like browsing for a server to join).
def ranked_servers(list, version = nil, include_locked: false)
  list = list.reject { |s| s['has_password'] } unless include_locked
  list = list.select { |s| (gv = s.dig('application_version', 'game_version')) && (gv == version || gv.start_with?("#{version}.")) } if version
  list.sort_by { |s| -player_count(s) }
end

# Lines to print: top N plus the rank of every --server match (even outside top N).
# live: {host_address => Integer or nil} — nil = UDP unanswered, keep snapshot.
# pool: list matches are searched/ranked in (defaults to sorted); pass the
# unfiltered list so named matches show even when locked/hidden from the top.
def rank_report(sorted, top:, match: nil, live: {}, pool: nil)
  pool ||= sorted
  lines = sorted.first(top).each_with_index.map do |s, i|
    n = live.fetch(s['host_address'], player_count(s))
    extra = live.key?(s['host_address']) ? (n.nil? ? ' (offline?)' : " (live: #{n})") : ''
    "##{i + 1} #{strip_tags(s['name'])} — #{n || player_count(s)} players (#{s.dig('application_version', 'game_version')}#{', 🔒' if s['has_password']}) @ #{s['host_address']}#{extra}"
  end
  if match
    hits = pool.each_with_index.select { |s, _| strip_tags(s['name']).downcase.include?(match.downcase) }
    if hits.empty?
      lines << "No server matching #{match.inspect} in list (#{sorted.length} servers)."
    else
      hits.each do |s, i|
        n = live.fetch(s['host_address'], player_count(s))
        lines << "=> #{strip_tags(s['name'])} is ##{i + 1} with #{n.nil? ? player_count(s) : n} players @ #{s['host_address']}#{', 🔒' if s['has_password']}#{' (live)' if live.key?(s['host_address']) && !n.nil?}."
      end
    end
  end
  lines << "(#{sorted.length} servers listed)"
  lines
end

# Version filter: explicit --version wins; otherwise --server ranks within the
# matched server's version (like the in-game browser, which shows only your
# exact version); --all-versions keeps the global list. Returns [version, note].
def resolve_version(list, server:, version:, all_versions:)
  return [version, nil] if version || all_versions || server.nil?
  hit = ranked_servers(list, include_locked: true).find { |s| strip_tags(s['name']).downcase.include?(server.downcase) }
  hit ? [hit.dig('application_version', 'game_version'), "(#{hit.dig('application_version', 'game_version')} servers only)"] : [nil, nil]
end

if $PROGRAM_NAME == __FILE__
  opts = { top: 10, version: nil, server: nil, say: false, live: false, refresh_all: false, reseed: false, all_versions: false, interactive: false }
  OptionParser.new do |o|
    o.banner = 'Usage: ruby tools/server_rank.rb --server NAME [--top N] [--version 2.0] [--all-versions] [--live] [--refresh-all] [--say] [--reseed] [--interactive]'
    o.on('--top N', Integer, 'show top N (default 10)') { |v| opts[:top] = v }
    o.on('--version V', 'filter by game version (e.g. 2.0)') { |v| opts[:version] = v }
    o.on('--server NAME', 'your server name (substring, case-insensitive; implies same-version filter)') { |v| opts[:server] = v }
    o.on('--include-locked', 'show passworded servers (hidden by default)') { opts[:include_locked] = true }
    o.on('--all-versions', 'rank across all versions (default with --server: its version only)') { opts[:all_versions] = true }
    o.on('--live', 're-check shown servers via UDP (no API hit for counts)') { opts[:live] = true }
    o.on('--refresh-all', 'UDP-refresh every server (minutes); implies --live') { opts[:refresh_all] = true; opts[:live] = true }
    o.on('--say', 'also print in-game via RCON game.print') { opts[:say] = true }
    o.on('--reseed', 'force fresh API seed, rewrite cache') { opts[:reseed] = true }
    o.on('--interactive', 'prompt for row numbers to expand details via UDP (implies --live)') { opts[:interactive] = true; opts[:live] = true }
  end.parse!
  list = Matchmaking.seed(reseed: opts[:reseed])
  version, note = resolve_version(list, server: opts[:server], version: opts[:version], all_versions: opts[:all_versions])
  in_scope = version ? list.select { |s| (gv = s.dig('application_version', 'game_version')) && (gv == version || gv.start_with?("#{version}.")) } : list
  hidden = opts[:include_locked] ? 0 : in_scope.count { |s| s['has_password'] }
  sorted = ranked_servers(list, version, include_locked: opts[:include_locked])
  pool = opts[:server] ? ranked_servers(list, version, include_locked: true) : sorted
  live = {}
  if opts[:live]
    addrs = if opts[:refresh_all]
              sorted.map { |s| s['host_address'] }.compact.uniq
            else
              shown = sorted.first(opts[:top])
              shown += pool.select { |s| strip_tags(s['name']).downcase.include?(opts[:server].downcase) } if opts[:server]
              shown.map { |s| s['host_address'] }.compact.uniq
            end
    live = ServerQuery.refresh_counts(addrs)
    # Purely live ranking on full refresh: re-sort by live counts (nil keeps snapshot).
    sorted = sorted.sort_by { |s| -(live.fetch(s['host_address'], player_count(s)) || player_count(s)) } if opts[:refresh_all]
  end
  lines = rank_report(sorted, top: opts[:top], match: opts[:server], live: live, pool: pool)
  lines << note if note
  lines << "(#{hidden} 🔒 hidden, --include-locked to show)" if hidden > 0
  puts lines
  if opts[:interactive] && $stdin.tty?
    by_rank = {}
    sorted.first(opts[:top]).each_with_index { |s, i| by_rank[i + 1] = s }
    if opts[:server]
      sorted.each_with_index.select { |s, _| strip_tags(s['name']).downcase.include?(opts[:server].downcase) }
            .each { |s, i| by_rank[i + 1] = s }
    end
    loop do
      print 'row (q)? '
      ans = $stdin.gets.to_s.strip
      break if ans.empty? || ans.downcase.start_with?('q')
      s = by_rank[ans.to_i]
      if s.nil?
        puts 'no such row'
        next
      end
      info = ServerQuery.info(s['host_address'])
      puts(info.nil? ? "#{s['host_address']}: no reply" : ServerQuery.format_info(info))
    end
  end
  if opts[:say]
    require_relative '../lib/server_detect'
    require_relative '../lib/rcon_client'
    rcon = RconClient.from_detected(ServerDetect.detect)
    abort 'RCON unavailable (no server detected)' unless rcon
    lines.each { |l| rcon.say(l) }
  end
end
