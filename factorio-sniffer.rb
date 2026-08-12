#!/usr/bin/env ruby
# factorio-sniffer — live/offline Factorio player action logger
#
# Captures UDP traffic on the Factorio port, decodes the binary protocol,
# extracts player actions, and logs them with optional grief detection.
#
# Thin entry point: parses args, then runs the sniffer (lib/factorio_sniffer.rb)
# with a hot-reload loop — Ctrl-C reloads the code without losing the
# capture file, player names, or stats; Ctrl-C again quits.
#
# Usage:
#   Live capture: sudo ruby factorio-sniffer.rb -i eth0 -p 34197
#   Server mode:  sudo ruby factorio-sniffer.rb          (auto-detects IP/port/interface from the running factorio process)
#   Pcap analysis: ruby factorio-sniffer.rb -r capture.pcap
#   With grief detection: ... --detect-grief
#   Save player db: ... --player-db players.json
#   Save pcap: ... --save-capture output.pcap
#   Filter by local IP: ... --local-ip 192.168.1.100

require_relative 'lib/server_detect'
require_relative 'lib/factorio_protocol'
require_relative 'lib/item_db'
require_relative 'lib/player_db'
require_relative 'lib/pcap'
require_relative 'lib/live_capture'
require_relative 'lib/rcon_client'
require_relative 'lib/factorio_sniffer'

# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────
DEFAULT_PORT = 34_197
DEFAULT_PLAYER_DB = 'players.json'

# ─────────────────────────────────────────────────────────────────────
# CLI + hot-reload loop
# ─────────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  require 'optparse'

  options = { player_db: DEFAULT_PLAYER_DB }

  op = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
    opts.separator ''
    opts.separator 'Capture sources (specify one):'
    opts.on('-i', '--interface IFACE', 'Network interface for live capture') { |v| options[:interface] = v }
    opts.on('-r', '--read PCAP', 'Read from pcap file') { |v| options[:pcap] = v }
    opts.separator ''
    opts.on('-p', '--port PORT', Integer, "UDP port (default: #{DEFAULT_PORT})") { |v| options[:port] = v }
    opts.on('--player-db PATH', "Player database file (default: #{DEFAULT_PLAYER_DB})") { |v| options[:player_db] = v }
    opts.on('--local-ip IP', 'Client mode: only show outgoing packets from this IP (filters out all server broadcasts)') { |v| options[:local_ip] = v }
    opts.on('--server', 'Server mode: run on the game server host (auto-enabled when a factorio server is detected on this host). Analyzes only incoming (client→server) packets — no broadcast duplicates — and excludes map-download save packets (msg 13) from analysis and capture.') { |v| options[:server] = true }
    opts.on('--server-ip IP', 'Server IP for --server mode (default: auto-detected from local interfaces)') { |v| options[:server_ip] = v }
    opts.on('--no-rcon', 'Disable the RCON roster sync (server mode)') { |v| options[:no_rcon] = true }
    opts.on('--save-capture PATH', 'Save captured packets to a pcap file') { |v| options[:save_capture] = v }
    opts.on('--save-unknowns PATH', 'Save individual packets with unknown action types to pcap (for analysis)') { |v| options[:save_unknowns] = v }
    opts.on('--item-db PATH', 'Item prototype dump file (item_prototypes_runtime.txt) for item name lookup') { |v| options[:item_db] = v }
    opts.on('--dump-raw-types', 'Dump raw action type IDs with hex data (for reverse engineering)') { |v| options[:dump_raw_types] = v }
    opts.on('--validate', 'Show warnings about unknown action types and potential length mismatches') { |v| options[:validate] = v }
    opts.on('-q', '--quiet', 'Quiet mode: hide noise actions (wire_dragging, nothing)') { |v| options[:quiet] = v }

    opts.on('--list-interfaces', 'List available network interfaces') { |v| options[:list_interfaces] = v }
    opts.on('--map-player ID:NAME', 'Map player ID to name (e.g. 1:dlbattle)') do |v|
      (options[:player_maps] ||= []) << v
    end
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end

  op.parse!

  if options[:server_ip] && !options[:server]
    warn 'Warning: --server-ip has no effect without --server'
  end

  # Auto-enable server mode: when no explicit mode was chosen (no --server,
  # no --local-ip) and a factorio server is running on THIS host, run in
  # server mode with the detected config. Live capture only — for pcap
  # analysis the capture may come from a different machine, so an automatic
  # server-IP filter would silently drop everything. The capture interface
  # is auto-picked below (server's --bind IP → its interface, else the
  # default-route interface), so `-i` is optional.
  auto_server = false
  if !options[:server] && !options[:local_ip] && !options[:pcap]
    detected = ServerDetect.detect
    if detected[:serving]
      auto_server = true
      options[:server] = true
    end
  end

  # Server mode: auto-detect the running Factorio server's configuration
  # (game port, server IP, capture interface, RCON) instead of requiring
  # the operator to pass it all by hand. Explicit CLI values win.
  if options[:server]
    detected ||= ServerDetect.detect
    if detected.empty?
      warn 'Warning: no running factorio process found; using defaults/auto-detect'
    else
      options[:port] ||= detected[:game_port]
      options[:server_ips] = detected[:server_ips] if !options[:server_ip] && detected[:server_ips]&.any?
      # Capture interface: with one non-loopback interface there's nothing
      # to choose; otherwise prefer the server's --bind IP, then default route.
      options[:interface] ||= ServerDetect.capture_iface(detected[:cmdline]) if !options[:pcap]
      if auto_server
        puts "Auto-enabled SERVER mode: running factorio server detected (pid #{detected[:pid]})"
        puts '  (pass --local-ip to force client mode)'
      end
      puts "Auto-detected running factorio server (pid #{detected[:pid]}):"
      puts "  game port: #{detected[:game_port]}"
      puts "  server IP: #{options[:server_ips]&.join(', ') || options[:server_ip]}"
      puts "  interface: #{options[:interface]}" if options[:interface]
      puts "  rcon: #{detected[:rcon_host] || 'localhost'}:#{detected[:rcon_port]}" if detected[:rcon_port]
      if detected[:rcon_port] && !options[:no_rcon]
        options[:rcon] = {
          host: detected[:rcon_host] || 'localhost',
          port: detected[:rcon_port],
          password: detected[:rcon_password],
        }
      end
      if detected[:dedicated]
        puts "  dedicated server: yes (#{detected[:dedicated_flags].join(', ')})"
      elsif detected[:hosting_flags]&.any?
        puts "  dedicated server: no — client-hosted game (#{detected[:hosting_flags].join(', ')})"
        warn '  Warning: not a dedicated server; RCON will be unavailable'
      else
        puts '  WARNING: process has no dedicated-server or hosting flags — may be a plain client'
      end
    end
  end

  options[:port] ||= DEFAULT_PORT

  # Zero-args convenience: if the operator gave no interface and there is
  # exactly one non-loopback interface, just use it (client mode too).
  if !options[:interface] && !options[:pcap]
    iface = ServerDetect.capture_iface(detected ? detected[:cmdline] : nil)
    if iface
      options[:interface] = iface
      puts "Using interface: #{iface} (only non-loopback interface)" unless options[:server]
    end
  end

  if options[:list_interfaces]
    puts "Available interfaces: #{LiveCapture.list_interfaces.join(', ')}"
    exit 0
  end

  # Apply player mappings to the DB before starting
  db = PlayerDatabase.new(options[:player_db])
  (options[:player_maps] || []).each do |m|
    id, name = m.split(':', 2)
    db.add(id.to_i, name)
    puts "Mapped Player #{id} -> #{name}"
  end
  db.save

  unless options[:interface] || options[:pcap]
    puts op
    puts
    if options[:server]
      puts 'Error: server mode could not pick a capture interface (no default route found).'
      puts '  Pass -i IFACE explicitly (e.g. sudo ruby factorio-sniffer.rb -i ens18).'
    else
      puts 'Error: specify --interface or --read'
    end
    exit 1
  end

  unless Process.uid == 0 || options[:pcap]
    puts 'Warning: live capture requires root. Try: sudo ...'
  end

  # ── Hot-reload loop ────────────────────────────────────────────────
  # Ctrl-C once: snapshot state (capture file stays open, player names and
  # stats preserved), reload the lib files with `load` (fresh code), rebuild
  # the sniffer. Ctrl-C again WITHIN 5 SECONDS of the previous one:
  # finalize (summary, save player db, close capture) and quit. A Ctrl-C
  # pressed later (more than 5s after the last) is a fresh reload instead —
  # so you can reload repeatedly while editing code, and double-tap to quit.
  SNIFFER_LIBS = %w[
    factorio_protocol item_db player_db pcap live_capture rcon_client factorio_sniffer
  ].freeze

  # Seconds between two Ctrl-C presses that count as "quit". Uses monotonic
  # time so wall-clock changes (NTP, manual) don't affect the window.
  QUIT_WINDOW = 5

  state = SnifferState.new
  last_interrupt = nil

  loop do
    sniffer = FactorioSniffer.new(options, state)
    begin
      sniffer.run
      # Natural completion (pcap exhausted or capture loop ended) → finalize.
      sniffer.finish
      break
    rescue Interrupt
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      if last_interrupt && (now - last_interrupt) <= QUIT_WINDOW
        puts "\nInterrupt — shutting down."
        sniffer.finish
        break
      else
        puts "\nInterrupt — reloading code; capture file and player state preserved."
        puts "  Press Ctrl+C again within #{QUIT_WINDOW} seconds to quit."
        state = sniffer.snapshot
        state.player_db&.save
        # Reload the library files. `load` re-reads the file (redefining
        # classes); `require` would only load once. Constant-redefinition
        # warnings are expected and silenced.
        old_verbose = $VERBOSE
        $VERBOSE = nil
        SNIFFER_LIBS.each { |lib| load File.expand_path("lib/#{lib}.rb", __dir__) }
        $VERBOSE = old_verbose
        last_interrupt = now
        next
      end
    end
  end
end
