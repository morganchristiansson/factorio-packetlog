#!/usr/bin/env ruby
# RCON CLI for the Factorio vanilla server.
#
# Usage:
#   ruby tools/rcon.rb status
#   ruby tools/rcon.rb players
#   ruby tools/rcon.rb exec "/shout hello everyone"
#   ruby tools/rcon.rb exec "/sc game.print('hi')"   (silent, not printed to players)
#   ruby tools/rcon.rb raw "/version"
#
# RCON host/port/password are auto-detected from the running factorio
# process (/proc/<pid>/cmdline + sockets; see lib/server_detect.rb).
# Override with RCON_HOST / RCON_PORT / RCON_PASSWORD env vars.
require "rcon"
require_relative "../lib/server_detect"

_detected = ServerDetect.detect
if _detected.empty?
  warn 'Warning: no running factorio process found; using default RCON settings'
elsif !_detected[:dedicated] && _detected[:hosting_flags]&.any?
  warn "Warning: factorio pid #{_detected[:pid]} looks like a client-hosted game, not a dedicated server — RCON may be unavailable"
elsif !_detected[:dedicated]
  warn "Warning: factorio pid #{_detected[:pid]} has no dedicated-server flags — RCON likely unavailable"
end
HOST = ENV["RCON_HOST"] || _detected[:rcon_host] || "localhost"
PORT = (ENV["RCON_PORT"] || _detected[:rcon_port] || 27015).to_i
PASSWORD = ENV["RCON_PASSWORD"] || _detected[:rcon_password] || "bzsmD3pE7WcPGk"

def client
  c = Rcon::Client.new(host: HOST, port: PORT, password: PASSWORD)
  # Factorio sends only ONE packet in response to auth (not two like SRCDS),
  # so the default ignore_first_packet: true would time out.
  c.authenticate!(ignore_first_packet: false)
  c
end

case ARGV[0]
when "status"
  c = client
  %w[/version /players /admins /time /evolution].each do |cmd|
    r = c.execute(cmd)
    puts "#{cmd.ljust(12)} => #{r.body.inspect}"
  end
  c.end_session!
when "players"
  c = client
  puts c.execute("/players").body
  c.end_session!
when "exec"
  c = client
  r = c.execute(ARGV[1])
  puts r.body
  c.end_session!
when "raw"
  c = client
  ARGV[1..].each do |cmd|
    r = c.execute(cmd)
    puts "#{cmd} => #{r.body.inspect}"
  end
  c.end_session!
else
  puts <<~USAGE
    Usage: ruby tools/rcon.rb <command> [args]
      status            server version/players/admins/time/evolution
      players           list online players
      exec "<cmd>"      run a console command (e.g. "/shout hello", "/sc ..." for silent)
      raw "<cmd>..."    run raw commands, print bodies
  USAGE
end
