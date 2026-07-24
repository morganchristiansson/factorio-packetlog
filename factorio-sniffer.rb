#!/usr/bin/env ruby
# factorio-sniffer — live/offline Factorio player action logger
#
# Captures UDP traffic on the Factorio port, decodes the binary protocol,
# extracts player actions, and logs them with optional grief detection.
#
# Usage:
#   Live capture: sudo ruby factorio-sniffer.rb -i eth0 -p 34197
#   Pcap analysis: ruby factorio-sniffer.rb -r capture.pcap
#   With grief detection: ... --detect-grief
#   Save player db: ... --player-db players.json
#   Save pcap: ... --save-capture output.pcap
#   Filter by local IP: ... --local-ip 192.168.1.100

require 'json'
require 'time'
require_relative 'lib/factorio_protocol'
require_relative 'lib/item_db'


# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────
DEFAULT_PORT = 34_197
DEFAULT_PLAYER_DB = 'players.json'

# ─────────────────────────────────────────────────────────────────────
# Action Definitions (from Hornwitser's factorio_dissector Lua plugin)
# Maps action_type_id -> [name, data_len]
# data_len: nil = variable/dissect-only, 0 = no data, N = fixed length
# ─────────────────────────────────────────────────────────────────────
class PlayerDatabase
  attr_reader :players

  def initialize(path = nil)
    @path = path
    @players = {}  # id -> name
    @id_by_name = {}  # name -> id
    load if @path && File.exist?(@path)
  end

  def lookup(id)
    @players[id] || "Player_#{id}"
  end

  def add(id, name)
    return if name.nil? || name.empty?
    @players[id.to_i] = name
    @id_by_name[name] = id.to_i
  end

  def name_to_id(name)
    @id_by_name[name]
  end

  def save
    return unless @path
    File.write(@path, JSON.pretty_generate(@players))
  end

  private

  def load
    raw = JSON.parse(File.read(@path))
    @players = raw.each_with_object({}) { |(k, v), h|
      next unless k =~ /^\d+$/
      h[k.to_i] = v
    }
    @players.each { |id, name| @id_by_name[name] = id }
  rescue JSON::ParserError
    @players = {}
    @id_by_name = {}
  end
end

# ─────────────────────────────────────────────────────────────────────
# PCAP Writer (for saving live capture)
# ─────────────────────────────────────────────────────────────────────
class PcapWriter
  def initialize(path)
    @path = path
    @file = File.open(path, 'wb')
    # Write pcap global header
    @file.write([
      0xa1b2c3d4,  # magic (little endian)
      2, 4,        # version major, minor
      0, 0,        # timezone
      0, 0,        # sigfigs
      65535,       # snaplen
      1,           # link type (Ethernet)
    ].pack('VvvVVVV'))
    @start_time = Time.now
  end

  def write_packet(ip_payload)
    # We'll store the raw IP/UDP payload. To create a valid pcap we'd need
    # full ethernet+IP+UDP headers, but for simplicity just wrap the UDP data
    # with a fake Ethernet header.
    ts = Time.now
    ts_sec = ts.to_i
    ts_usec = ((ts - ts_sec) * 1_000_000).to_i

    # Create a minimal ethernet frame with the UDP payload
    # This won't be a valid pcap for all tools but preserves the data
    @file.write([
      ts_sec, ts_usec,
      ip_payload.bytesize,
      ip_payload.bytesize,
    ].pack('VVVV'))
    @file.write(ip_payload)
  end

  def close
    @file.close if @file
  end
end

# ─────────────────────────────────────────────────────────────────────
# PCAP Reader
# ─────────────────────────────────────────────────────────────────────
class PcapReader
  def initialize(path)
    @path = path
  end

  def each_packet(&block)
    data = File.binread(@path)
    magic = data.unpack1('V')
    endian = (magic == 0xa1b2c3d4) ? :little : :big
    raise "Not a pcap file" unless [:little, :big].include?(endian)

    gh = data.unpack(endian == :little ? 'VvvVVVV' : 'NnnNNNN')
    linktype = gh[6]
    pkt_num = 0

    offset = 24
    while offset + 16 <= data.bytesize
      ph = data.unpack(endian == :little ? 'VVVV' : 'NNNN', offset: offset)
      ts_sec, ts_usec, incl_len, _ = ph
      offset += 16
      break if offset + incl_len > data.bytesize
      pkt_data = data[offset, incl_len]
      offset += incl_len
      pkt_num += 1

      # Strip link layer
      raw = case linktype
      when 1 then pkt_data[14..]
      when 0 then pkt_data[4..]
      when 113 then pkt_data[16..]
      else pkt_data
      end
      next if raw.nil? || raw.bytesize < 28

      # Parse IP + UDP
      ihl = (raw.getbyte(0) & 0x0F) * 4
      next unless raw.getbyte(9) == 17  # UDP only
      next if raw.bytesize < ihl + 8

      sport = raw.unpack1('n', offset: ihl)
      dport = raw.unpack1('n', offset: ihl + 2)
      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.bytesize < 1

      src_ip = raw[12..15].bytes.join('.')
      dst_ip = raw[16..19].bytes.join('.')

      yield(pkt_num, ts_sec + ts_usec / 1_000_000.0,
            src_ip, dst_ip, sport, dport, udp_data)
    end
  end
end

# ─────────────────────────────────────────────────────────────────────
# Live Capture (pcaprub)
# ─────────────────────────────────────────────────────────────────────
class LiveCapture
  def initialize(interface:, port:, bpf: nil)
    @interface = interface
    @port = port
    @bpf = bpf || (port ? "udp port #{port}" : 'udp')
  end

  def self.list_interfaces
    require 'socket'
    Socket.getifaddrs.select { |a| a.addr&.ip? }.map { |a| a.name }.uniq
  rescue => e
    puts "Failed to list interfaces: #{e}"
    ['(none found)']
  end

  def each_packet(&block)
    require 'pcaprub'

    cap = PCAPRUB::Pcap.open_live(@interface, 65535, true, 1000)
    cap.setfilter(@bpf)

    pkt_num = 0
    loop do
      pkt = cap.next
      unless pkt
        sleep 0.01
        next
      end

      # Parse Ethernet header
      next if pkt.bytesize < 14
      eth_type = pkt.unpack1('n', offset: 12)
      next unless eth_type == 0x0800  # IPv4 only for now

      raw = pkt[14..]
      next if raw.nil? || raw.bytesize < 20

      ihl = (raw.getbyte(0) & 0x0F) * 4
      next if raw.bytesize < ihl + 8 || raw.getbyte(9) != 17

      sport = raw.unpack1('n', offset: ihl)
      dport = raw.unpack1('n', offset: ihl + 2)
      next if @port && sport != @port && dport != @port

      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.bytesize < 1

      ts = Time.now.to_f
      pkt_num += 1
      yield(pkt_num, ts,
            raw[12..15].bytes.join('.'),
            raw[16..19].bytes.join('.'),
            sport, dport, udp_data)
    end
  rescue PCAPRUB::PCAPRUBError => e
    puts "Capture error: #{e}"
    puts "Available interfaces: #{self.class.list_interfaces.join(', ')}"
  rescue Interrupt
    # Graceful exit
  end
end

# ─────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────
class FactorioSniffer
  def initialize(options)
    @options = options
    @player_db = PlayerDatabase.new(options[:player_db])
    @grief = nil
    @stats = { packets: 0, factorio_packets: 0, actions: 0 }
    @pcap_writer = options[:save_capture] ? PcapWriter.new(options[:save_capture]) : nil
    @item_db = nil
    if options[:item_db] && File.exist?(options[:item_db])
      @item_db = ItemDB.new(options[:item_db])
    end
  end

  def run
    if @options[:pcap]
      reader = PcapReader.new(@options[:pcap])
      reader.each_packet { |*args| process_packet(*args) }
    elsif @options[:interface]
      capturer = LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
      )
      puts "Listening on #{@options[:interface]} port #{@options[:port]}..."
      puts "Press Ctrl+C to stop."
      if @options[:local_ip]
        puts "Filtering: showing only packets involving #{@options[:local_ip]}"
      end
      capturer.each_packet { |*args| process_packet(*args) }
    end

    print_summary
    @player_db.save
    @pcap_writer&.close
  end

  private

  def process_packet(pkt_num, ts, src_ip, dst_ip, sport, dport, udp_data)
    @stats[:packets] += 1

    # Save to pcap if requested
    if @pcap_writer
      # Reconstruct a minimal IP+UDP packet for storage
      # This won't be fully standards-compliant but preserves the data
      pkt = build_fake_ip_udp(src_ip, dst_ip, sport, dport, udp_data)
      @pcap_writer.write_packet(pkt)
    end

    # Apply local IP filter if specified
    if @options[:local_ip]
      return unless src_ip == @options[:local_ip]
    end

    parsed = FactorioProtocol.parse_udp_payload(udp_data)
    return unless parsed

    @stats[:factorio_packets] += 1
    hdr = parsed[:header]

    if parsed[:connection_confirm]
      username = parsed[:connection_confirm][:username]
    end

    return unless (hb = parsed[:heartbeat])

    # synchronizer actions (NewPeerInfo can give usernames)
    hb[:sync_actions]&.each do |sa|
      if sa[:username]
        @player_db.add(0, sa[:username])
      end
    end

    # tick closures → player actions
    # Ghost flag is in bit 0 of next_receive timeshift
    @ghost_mode = hb[:next_receive] ? (hb[:next_receive] & 1) == 1 : false
    
    # Warn when hit_unknown stops parsing — indicates wrong data length
    if hb[:hit_unknown]
      tc = hb[:tick_closures]&.last
      if tc&.dig(:actions, -1)
        last_act = tc[:actions][-1]
        warn "[WARN] type #{last_act[:type]}(#{last_act[:name]}) triggered hit_unknown — previous action may have wrong data length"
      end
    end
    
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each do |act|
        @stats[:actions] += 1
        log_action(ts, act, hdr[:msg_type] == 7, ghost: @ghost_mode)
      end
    end
  end

  # Build a fake pcap packet with IP+UDP headers
  def build_fake_ip_udp(src_ip, dst_ip, sport, dport, payload)
    src_bytes = src_ip.split('.').map(&:to_i).pack('C4')
    dst_bytes = dst_ip.split('.').map(&:to_i).pack('C4')

    udp_len = 8 + payload.bytesize
    udp_hdr = [sport, dport, udp_len, 0].pack('nnnn')

    ip_total_len = 20 + udp_len
    ip_hdr = [0x45, 0, ip_total_len, 0, 0, 0, 64, 17, 0].pack('CCnCCnCCn')
    # Calculate IP checksum
    ip_hdr += [0, 0].pack('n')
    ip_hdr[10, 2] = [checksum(ip_hdr)].pack('n')
    ip_hdr += src_bytes + dst_bytes

    eth_hdr = ["\x00" * 6, "\x00" * 6, [0x0800].pack('n')].join
    eth_hdr + ip_hdr + udp_hdr + payload
  end

  def checksum(data)
    sum = 0
    data.bytes.each_slice(2) do |b1, b2|
      sum += (b1 << 8) | (b2 || 0)
    end
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum = (sum >> 16) + sum
    (~sum) & 0xFFFF
  end

  DIR_NAMES = %w[north northnortheast northeast eastnortheast east eastsoutheast southeast southsoutheast south southsouthwest southwest westsouthwest west westnorthwest northwest northnorthwest].freeze

  # Named constants for commonly-referenced action types
  module ActionType
    NOTHING = 0
    STOP_WALKING = 1
    BEGIN_MINING = 2
    STOP_MINING = 3
    TOGGLE_DRIVING = 4
    OPEN_GUI = 5
    SETUP_ASSEMBLING_MACHINE = 88
    START_WALKING = 69
    BEGIN_MINING_TERRAIN = 70
    CHANGE_RIDING_STATE = 71
    OPEN_ITEM = 73
    REMOTE_VIEW_SURFACE = 259
    QUICK_BAR_SET = 244
    QUICK_BAR_PICK = 245
    PIPETTE = 90
    CURSOR_TRANSFER = 78
    STACK_TRANSFER = 80
    INVENTORY_TRANSFER = 83
    CRAFT = 85
    WIRE_DRAGGING = 86
    SELECTED_ENTITY_CHANGED = 87
    DROP_ITEM = 67
    BUILD = 68
    USE_ITEM = 119
    START_REPAIR = 130
    DECONSTRUCT = 131
    COPY = 133
    CHEAT = 58
    STOP_DRAG_BUILD = 48
    ROTATE_ENTITY = 279
    FAST_ENTITY_SPLIT = 281
    WRITE_TO_CONSOLE = 106
    FAST_ENTITY_TRANSFER = 278
    PLAYER_LEAVE_GAME = 247
    SERVER_COMMAND = 209
    OPEN_TRAIN_GUI = 289
    SET_ENTITY_COLOR = 291
    SET_TRAINS_LIMIT = 313
  end

  def decode_action_string(act)
    return nil unless act[:data] && act[:data].bytesize > 0
    d = act[:data]
    # Segment format (outgoing): [0x05][text_len][text]
    if d.getbyte(0) == 0x05 && d.bytesize >= 3
      text_len = d.getbyte(1)
      if text_len + 2 <= d.bytesize
        return d[2, text_len].force_encoding('UTF-8')
      end
    end
    # Non-segment format: [0x04][text]
    if d.getbyte(0) == 0x04 && d.bytesize > 1
      return d[1..-1].force_encoding('UTF-8')
    end
    # Standard uint32v-prefixed string
    off, slen = FactorioProtocol.decode_uint32v(d, 0)
    return nil unless slen && off + slen <= d.bytesize
    d[off, slen].force_encoding('UTF-8')
  end

  def format_action_data(act)
    return '' unless act[:data] && act[:data].bytesize > 0
    d = act[:data]

    case act[:type]
    when ActionType::START_WALKING
      if d.bytesize >= 16
        x = d.unpack1('E', offset: 0)
        y = d.unpack1('E', offset: 8)
        dirs = [
          [[1.0, 0.0], 'east'], [[-1.0, 0.0], 'west'],
          [[0.0, 1.0], 'south'], [[0.0, -1.0], 'north'],
          [[0.707, 0.707], 'southeast'], [[0.707, -0.707], 'northeast'],
          [[-0.707, 0.707], 'southwest'], [[-0.707, -0.707], 'northwest'],
        ]
        name = dirs.find { |(dx, dy), _| (x - dx).abs < 0.05 && (y - dy).abs < 0.05 }&.last
        if name
          return " dir=#{name}"
        else
          return " dir=(#{'%.1f' % x}, #{'%.1f' % y})"
        end
      end
    when ActionType::BEGIN_MINING_TERRAIN, ActionType::DROP_ITEM
      if d.bytesize >= 8
        raw_x = d.unpack1('i', offset: 0)
        raw_y = d.unpack1('i', offset: 4)
        x = raw_x / 256.0
        y = raw_y / 256.0
        return " pos=(#{'%.3f' % x}, #{'%.3f' % y})"
      end
    when ActionType::OPEN_ITEM, ActionType::SELECTED_ENTITY_CHANGED,
         ActionType::USE_ITEM, ActionType::START_REPAIR, ActionType::DECONSTRUCT
      if d.bytesize >= 4
        eid = d.unpack1('V')
        return " entity=##{eid}"
      end
    when ActionType::BUILD
      if d.bytesize >= 9
        x = d.unpack1('i', offset: 0)
        y = d.unpack1('i', offset: 4)
        dir = d.getbyte(8)
        dname = DIR_NAMES[dir] || dir
        return " pos=(#{'%.3f' % (x/256.0)}, #{'%.3f' % (y/256.0)}) dir=#{dname}"
      end
    when ActionType::ROTATE_ENTITY
      return " dir=#{d.getbyte(0)}"
    when ActionType::FAST_ENTITY_SPLIT
      return " slot=#{d.getbyte(0)}"
    when ActionType::FAST_ENTITY_TRANSFER
      dir = d.getbyte(0) == 1 ? 'put' : 'take'
      return " #{dir}"
    when ActionType::CHANGE_RIDING_STATE
      return " vehicle=#{d.unpack1('v')}" if d.bytesize >= 2
    when ActionType::CRAFT
      return " recipe_id=#{d.unpack1('V')}" if d.bytesize >= 4
    when ActionType::CURSOR_TRANSFER
      if d.bytesize >= 9
        item_id = d.unpack1('v')
        item_name = @item_db ? @item_db.name(item_id) : "item_#{item_id}"
        action = d.unpack1('V', offset: 2)
        act = action == 1 ? 'put' : 'clear'
        return " #{item_name} #{act}"
      end
    when ActionType::OPEN_GUI
      return "" if d.bytesize >= 2
    when ActionType::REMOTE_VIEW_SURFACE
      if d.bytesize >= 4
        surf_id = d[0, 4].unpack1('N')
        return " surface=#{surf_id}"
      end
    when ActionType::SETUP_ASSEMBLING_MACHINE
      return " recipe=#{d.unpack1('v')}" if d.bytesize >= 2
    when ActionType::PIPETTE
      if d.bytesize >= 9
        src = d.getbyte(0)
        ref = d.unpack1('V', offset: 1)
        qual = d.getbyte(8)
        if src == 0 && @item_db
          return " #{@item_db.name(ref)} qual=#{qual}"
        elsif src == 4
          return " entity=#{ref} qual=#{qual}"
        end
        return " src=#{src} ref=#{ref} qual=#{qual}"
      end
    when ActionType::STACK_TRANSFER, ActionType::INVENTORY_TRANSFER
      if d.bytesize >= 5
        item_id = d.unpack1('v')
        item_name = @item_db ? @item_db.name(item_id) : "item_#{item_id}"
        count = d.unpack1('v', offset: 2)
        return " #{item_name} count=#{count}"
      end
    when ActionType::QUICK_BAR_PICK
      if d.bytesize >= 2
        row = d.getbyte(0)
        slot = d.getbyte(1)
        return " row=#{row} slot=#{slot}"
      end
    when ActionType::QUICK_BAR_SET
      if d.bytesize >= 9
        row = d.getbyte(0)
        slot = d.getbyte(1)
        action = d.getbyte(2)  # 0=set, 1=clear
        src_row = d.getbyte(3)
        src_slot = d.getbyte(4)
        act = action == 0 ? 'set' : 'clear'
        if src_row == 0xFF && src_slot == 0xFF
          return " row=#{row} slot=#{slot} #{act}"
        else
          return " move row=#{src_row} slot=#{src_slot} -> row=#{row} slot=#{slot}"
        end
      end
    when ActionType::COPY
      return " flags=#{d.unpack1('v')}" if d.bytesize >= 2
    when ActionType::CHEAT
      return ''
    end

    return '' unless @options[:dump_raw_types]
    hex = d.bytes.first(8).map { |b| '%02x' % b }.join
    " [#{hex}#{d.bytesize > 8 ? '..' : ''}]"
  end

  def log_action(ts, act, is_server, ghost: false)
    pid = act[:game_player] || act[:player]
    ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
    arrow = is_server ? '<-' : '->'

    # Dump raw type info for reverse engineering
    pname = @player_db.lookup(pid)


    # Chat messages
    if act[:name] == 'write_to_console'
      msg = decode_action_string(act)
      if msg
        puts "#{ts_str}  #{arrow} #{pname}: #{msg}"
        return
      end
    end

    # Skip noise only in quiet mode
    return if @options[:quiet] && FactorioProtocol::NOISE_ACTIONS.include?(act[:name])
    return if act[:name].start_with?('Unknown')

    # Skip invalid player IDs if max_players is set
    if @options[:max_players] && pid > @options[:max_players]
      if @options[:verbose]
        puts "#{ts_str}  #{arrow} #{pname.ljust(16)} #{act[:name].ljust(28)} [skipped: invalid player #{pid}]"
      end
      return
    end

    # Format action data (position, entity refs, etc.)
    data_str = format_action_data(act)
    suffix = ghost && act[:type] == 68 ? ' [ghost]' : ''
    if @options[:dump_raw_types]
      hex = act[:data] ? act[:data].unpack1('H*') : ''
      data_str += " [#{hex}]"
    end
    puts "#{ts_str}  #{arrow} #{pname.ljust(16)} #{act[:name].ljust(28)}#{data_str}#{suffix}"
  end

  def print_summary
    puts
    puts "── Summary ──"
    puts "Packets seen: #{@stats[:packets]}"
    puts "Factorio packets: #{@stats[:factorio_packets]}"
    puts "Player actions: #{@stats[:actions]}"
    puts "Known players: #{@player_db.players.size}"
    @player_db.players.each { |id, name| puts "  Player #{id}: #{name}" }


  end
end

# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  require 'optparse'

  options = { port: DEFAULT_PORT, player_db: DEFAULT_PLAYER_DB }

  op = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
    opts.separator ''
    opts.separator 'Capture sources (specify one):'
    opts.on('-i', '--interface IFACE', 'Network interface for live capture') { |v| options[:interface] = v }
    opts.on('-r', '--read PCAP', 'Read from pcap file') { |v| options[:pcap] = v }
    opts.separator ''
    opts.on('-p', '--port PORT', Integer, "UDP port (default: #{DEFAULT_PORT})") { |v| options[:port] = v }
    opts.on('--player-db PATH', "Player database file (default: #{DEFAULT_PLAYER_DB})") { |v| options[:player_db] = v }
    opts.on('--local-ip IP', 'Only show outgoing packets from this IP (filters out all server broadcasts)') { |v| options[:local_ip] = v }
    opts.on('--max-players N', Integer, 'Max valid player ID (skip actions with higher IDs)') { |v| options[:max_players] = v }
    opts.on('--save-capture PATH', 'Save captured packets to a pcap file') { |v| options[:save_capture] = v }
    opts.on('--item-db PATH', 'Item prototype dump file (item_prototypes_runtime.txt) for item name lookup') { |v| options[:item_db] = v }
    opts.on('--dump-raw-types', 'Dump raw action type IDs with hex data (for reverse engineering)') { |v| options[:dump_raw_types] = v }
    opts.on('-q', '--quiet', 'Quiet mode: hide noise actions (wire_dragging, nothing)') { |v| options[:quiet] = v }

    opts.on('--list-interfaces', 'List available network interfaces') { |v| options[:list_interfaces] = v }
    opts.on('--map-player ID:NAME', 'Map player ID to name (e.g. 1:dlbattle)') do |v|
      (options[:player_maps] ||= []) << v
    end
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end

  op.parse!

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
    puts 'Error: specify --interface or --read'
    exit 1
  end

  unless Process.uid == 0 || options[:pcap]
    puts 'Warning: live capture requires root. Try: sudo ...'
  end

  FactorioSniffer.new(options).run
end
