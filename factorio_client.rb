#!/usr/bin/env ruby
# frozen_string_literal: true

# Join a Factorio server as a client with no game behind it: no simulation,
# empty input actions, and everything the server sends written to a pcap you
# can hand straight to the sniffer.
#
#   ruby factorio_client.rb HOST[:PORT] --user someone
#   ruby factorio-packettools.rb -r captures/client-observer-<ts>.pcap
#
# Own server, no auth token. See lib/factorio_client.rb for what it does and
# how the tick closures keep the session alive with no simulation behind it.

require_relative 'lib/factorio_client'
require 'optparse'

options = { user: 'packettools', seconds: nil, record: nil, acts: [] }
parser = OptionParser.new do |o|
  o.banner = 'Usage: ruby factorio_client.rb HOST[:PORT] [options]'
  o.on('--user NAME', 'username to join with (default packettools)') { |v| options[:user] = v }
  o.on('--record PATH', 'pcap to write (default captures/observer-<ts>.pcap)') { |v| options[:record] = v }
  o.on('--seconds N', Integer, 'stop after N seconds (default: until Ctrl-C)') { |v| options[:seconds] = v }
  o.on('--act TYPE:DELTA:HEX', 'input action to send once: wire type, player delta, data as hex') do |v|
    type, delta, hex = v.split(':', 3)
    options[:acts] << [type.to_i, delta.to_i, [hex.to_s].pack('H*')]
  end
  o.on('--save PATH', 'server save zip/level.dat: fallback server tick when the UDP stream is too short to drain') { |v| options[:save] = v }
  o.on('-h', '--help', 'this text') { puts o; exit }
end
parser.parse!
target = ARGV.shift or abort parser.banner
host, port = target.include?(':') ? target.split(':', 2) : [target, '34197']

Dir.chdir(__dir__)
record = options[:record] ||
         File.join('captures', "observer-#{Time.now.strftime('%Y%m%d-%H%M%S')}.pcap")
client = FactorioClient.new(host: host, port: port.to_i, username: options[:user], record: record, save: options[:save])
client.connect
options[:acts].each { |type, delta, data| client.send_action(type, delta, data) }
puts "recording to #{record} — Ctrl-C to stop"
client.run(seconds: options[:seconds])
client.close # graceful leave (player_leave_game) so the server drops the
# peer at once instead of timing it out after the socket goes quiet
puts "#{client.received} packets in, #{client.sent_heartbeats} heartbeats out, " \
     "server tick #{client.server_tick}"
