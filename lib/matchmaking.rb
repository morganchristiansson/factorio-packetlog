# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'net/http'
require 'uri'

# Matchmaking HTTP API client (https://multiplayer.factorio.com/get-games).
# One endpoint, one purpose: seed the server list. Everything live after
# that comes straight from the servers via UDP (see server_query.rb), so a
# cached seed means zero official-API traffic.
#
# Every get-games entry already carries host_address ("ip:port") — no
# per-server details call is ever needed to refresh counts directly.
class Matchmaking
  API_ROOT = 'https://multiplayer.factorio.com'
  CACHE_PATH = File.expand_path('~/.cache/factorio-server-list.json')
  PLAYER_DATA_CANDIDATES = [
    File.expand_path('~/factorio/player-data.json'),
    '/factorio/player-data.json', # sandbox layout
    File.expand_path('~/.factorio/player-data.json')
  ].freeze

  # Credentials: env override, else the local Factorio login
  # (player-data.json service-username/service-token — the same pair the
  # game client itself uses). Returns [user, token].
  def self.credentials
    user = ENV['FACTORIO_USERNAME']
    token = ENV['FACTORIO_TOKEN']
    return [user, token] if user && token
    path = PLAYER_DATA_CANDIDATES.find { |p| File.exist?(p) }
    raise "no credentials: set FACTORIO_USERNAME/FACTORIO_TOKEN or log into Factorio (#{PLAYER_DATA_CANDIDATES.join(' / ')})" unless path
    d = JSON.parse(File.read(path))
    [d['service-username'], d['service-token']]
  end

  # Single authenticated GET. Raises on non-200 (401 = bad/expired token).
  def self.fetch(user, token)
    uri = URI("#{API_ROOT}/get-games?username=#{URI.encode_www_form_component(user)}&token=#{URI.encode_www_form_component(token)}")
    res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 10, read_timeout: 30) do |h|
      h.get(uri.request_uri, { 'User-Agent' => 'factorio-server-rank' })
    end
    raise "matchmaking API: HTTP #{res.code} (bad username/token?)" unless res.code == '200'
    JSON.parse(res.body)
  end

  # Seed list: cache file unless reseed (or no cache yet). Reseed rewrites
  # the cache. The cache is what makes repeat runs API-free.
  def self.seed(reseed: false)
    if !reseed && File.exist?(CACHE_PATH)
      return JSON.parse(File.read(CACHE_PATH))
    end
    list = fetch(*credentials)
    FileUtils.mkdir_p(File.dirname(CACHE_PATH))
    File.write(CACHE_PATH, JSON.generate(list))
    list
  end
end
