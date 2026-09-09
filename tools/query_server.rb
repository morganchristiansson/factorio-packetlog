#!/usr/bin/env ruby
# frozen_string_literal: true
# Query Factorio servers directly over UDP (msg 16 → 17) — full info for
# one or more servers, no account, no matchmaking API: name, version,
# description, play time, mods + versions, tags, players.
#
# Args are "ip:port" addresses or name substrings (resolved via the cached
# API seed — no API hit — see lib/matchmaking.rb).
#
# Usage:
#   ruby tools/query_server.rb 5.9.193.28:34197
#   ruby tools/query_server.rb chill "deathworld"
$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'matchmaking'
require 'server_query'

# Args → addresses: IPs/hosts get the default port when bare, anything else
# is a case-insensitive substring over cached seed names (first 5 hits).
def normalize_addr(a)
  return a if a.count(':') == 1 && a.match?(/:\d+$/) # v4 + port
  return a if a.match?(/\[.*\]:\d+$/) # bracketed v6 + port
  return "#{a}:34197" if a.match?(/\A[\d.]+\z/) # bare v4
  return "[#{a}]:34197" if a.count(':') > 1 # bare v6
  host, _, port = a.rpartition(':')
  return a if port.match?(/\A\d+\z/) && !ServerQuery.resolve(host, 34197).empty? # hostname + port
  return "#{a}:34197" if !ServerQuery.resolve(a, 34197).empty? # bare hostname
  nil
end

def resolve_addrs(args)
  seed = Matchmaking.seed
  args.flat_map do |a|
    next normalize_addr(a) if normalize_addr(a)
    seed.select { |s| ServerQuery.strip_tags(s['name']).downcase.include?(a.downcase) }
        .first(5).map { |s| s['host_address'] }
  end.compact.uniq
end

if $PROGRAM_NAME == __FILE__
  abort 'Usage: ruby tools/query_server.rb HOST:PORT|NAME [HOST:PORT|NAME ...]' if ARGV.empty?
  addrs = resolve_addrs(ARGV)
  abort 'No cached server matches that name (run server_rank once to seed).' if addrs.empty?
  addrs.each do |addr|
    info = ServerQuery.info(addr)
    puts(info.nil? ? "#{addr}: no reply" : ServerQuery.format_info(info))
  end
end
