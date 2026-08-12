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

  # Remove all entries for a name except the given id (used when the
  # true game index is learned and may override peer-id-based guesses).
  def remove_other_entries_for(name, keep_id)
    @players.each do |id, n|
      if n == name && id != keep_id.to_i
        @players.delete(id)
      end
    end
    rebuild_index
  end

  def save
    return unless @path
    File.write(@path, JSON.pretty_generate(@players))
  end

  private

  def rebuild_index
    @id_by_name = {}
    @players.each { |id, name| @id_by_name[name] = id }
  end

  def load
    raw = JSON.parse(File.read(@path))
    @players = raw.each_with_object({}) { |(k, v), h|
      next unless k =~ /^\d+$/
      h[k.to_i] = v
    }
    rebuild_index
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
    # Write pcap global header directly (avoids pack issues)
    @file.write([0xd4, 0xc3, 0xb2, 0xa1].pack('C4'))  # magic LE
    @file.write([2, 4].pack('v2'))  # version
    @file.write([0, 0].pack('V2'))  # timezone, sigfigs
    @file.write([65535].pack('V'))   # snaplen
    @file.write([1].pack('V'))       # linktype = Ethernet
    @start_time = Time.now
    # Buffered writes flushed by a BACKGROUND thread: the capture loop only
    # appends to the buffer (fast, non-blocking). Flushing on the capture
    # thread stalls it on disk I/O (the workspace is a Docker bind mount),
    # which overflowed the kernel capture buffer during map downloads.
    @mutex = Mutex.new
    @buf = +''.b
    @closed = false
    @flush_thread = Thread.new { flush_loop }
  end

  def write_packet(ip_payload)
    write_record(Time.now, ip_payload)
  end

  # Write a real captured Ethernet frame as-is (fast path for live capture;
  # avoids rebuilding fake IP/UDP headers per packet).
  def write_frame(frame, ts = Time.now)
    write_record(ts, frame)
  end

  def close
    @closed = true
    @flush_thread.join(2)
    @mutex.synchronize do
      @file.write(@buf) unless @buf.empty?
      @buf = +''.b
    end
    @file.close if @file
  end

  private

  def write_record(ts, data)
    ts_sec = ts.to_i
    ts_usec = ((ts.to_f - ts_sec) * 1_000_000).to_i
    hdr = [ts_sec, ts_usec, data.bytesize, data.bytesize].pack('VVVV')
    @mutex.synchronize { @buf << hdr << data.b }
  end

  def flush_loop
    until @closed
      sleep 0.2
      chunk = @mutex.synchronize do
        c = @buf
        @buf = +''.b
        c
      end
      @file.write(chunk) unless chunk.empty?
    end
  rescue IOError
    # file closed
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
  def initialize(interface:, port:, bpf: nil, transfer_block_sink: nil)
    @interface = interface
    @port = port
    @bpf = bpf || (port ? "udp port #{port}" : 'udp')
    @last_drop_report = 0
    # Optional sink for map-download TransferBlocks: when set, transfer
    # frames are written straight here (e.g. the pcap writer) and skipped
    # from the parse pipeline entirely.
    @transfer_block_sink = transfer_block_sink
  end

  def self.list_interfaces
    require 'socket'
    Socket.getifaddrs.select { |a| a.addr&.ip? }.map { |a| a.name }.uniq
  rescue => e
    puts "Failed to list interfaces: #{e}"
    ['(none found)']
  end

  # Report libpcap kernel-buffer drops so capture loss is visible instead
  # of silently corrupting the session. stats => { 'recv' =>, 'drop' =>,
  # 'idrop' => }. 'drop' = packets the kernel buffer overflowed (the
  # capture loop was too slow); 'idrop' = dropped by the interface.
  def report_drops(cap, force: false)
    st = cap.stats
    return unless st.is_a?(Hash)
    drop = st['drop'].to_i
    idrop = st['idrop'].to_i
    return if drop.zero? && idrop.zero?
    return if !force && drop - @last_drop_report < 1000
    @last_drop_report = drop
    msg = +"[capture] kernel buffer drops: #{drop}"
    msg << " (interface: #{idrop})" if idrop > 0
    msg << " — capture can't keep up; use tcpdump for lossless capture" if drop > 0
    puts msg
  end

  def each_packet(&block)
    require 'pcaprub'

    # pcaprub 0.13.3 emits a one-time cosmetic "undefining the allocator of
    # T_DATA class" warning on the first open_live (Ruby 3.2 data-object
    # machinery + pcaprub's old-style Data_Make_Struct). Capture works fine;
    # silence it.
    old_verbose = $VERBOSE
    $VERBOSE = nil
    begin
      cap = PCAPRUB::Pcap.open_live(@interface, 65535, true, 1000)
    ensure
      $VERBOSE = old_verbose
    end
    cap.setfilter(@bpf)

    pkt_num = 0

    # Blocking batch read: pcaprub's each_data loops on pcap_dispatch and
    # waits on the capture fd when the buffer is empty (rb_thread_wait_fd).
    # This drains the kernel buffer continuously — the old next()+sleep(0.01)
    # poll let the kernel buffer overflow during map-download bursts
    # (~20k pps), silently dropping blocks.
    cap.each_data do |pkt|
      # Parse Ethernet header
      next if pkt.bytesize < 14
      eth_type = pkt.unpack1('n', offset: 12)
      next unless eth_type == 0x0800  # IPv4 only for now

      ihl = (pkt.getbyte(14) & 0x0F) * 4
      next if pkt.bytesize < 14 + ihl + 8

      # Fast path: map-download TransferBlocks (msg 13) need no parsing at
      # all — persist the frame if saving and skip the full yield/parse
      # pipeline (the bottleneck that overflowed the buffer before).
      if (pkt.getbyte(14 + ihl + 8) & 0x1F) == 13
        if @transfer_block_sink
          @transfer_block_sink.write_frame(pkt)
        end
        next
      end

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
            sport, dport, udp_data, pkt)

      # Surface capture loss early (report when it jumps by >= 1000)
      report_drops(cap) if pkt_num % 50_000 == 0
    end
  rescue PCAPRUB::PCAPRUBError => e
    puts "Capture error: #{e}"
    puts "Available interfaces: #{self.class.list_interfaces.join(', ')}"
  rescue Interrupt
    # Graceful exit
  ensure
    report_drops(cap, force: true) if cap
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
    @unknown_writer = options[:save_unknowns] ? PcapWriter.new(options[:save_unknowns]) : nil
    @item_db = nil
    if options[:item_db] && File.exist?(options[:item_db])
      @item_db = ItemDB.new(options[:item_db])
    end
    # Self (this client) tracking: we learn our own username from the
    # ConnectionRequestReplyConfirm and our own game player index from our
    # outgoing (C→S) heartbeat actions. This lets us correct the peer-id
    # based guesses from ConnectionAcceptOrDeny / NewPeerInfo, which use
    # NETWORK peer ids — those only equal game indexes for new joiners.
    @self_ip = nil
    @self_name = nil
    @self_index = nil  # 0-indexed game player index of this client
    # peer_id (network) -> name, for join/leave events (peer ids are NOT
    # game indexes; game indexes come from heartbeat actions instead).
    @peer_names = {}
  end

  def run
    if @options[:pcap]
      reader = PcapReader.new(@options[:pcap])
      reader.each_packet { |*args| process_packet(*args) }
    elsif @options[:interface]
      capturer = LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
        transfer_block_sink: @pcap_writer,
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
    @unknown_writer&.close
  end

  private

  def process_packet(pkt_num, ts, src_ip, dst_ip, sport, dport, udp_data, raw_frame = nil)
    @stats[:packets] += 1

    # Fast path for map download bursts: TransferBlock (msg 13) packets carry
    # raw save data — nothing to parse, and at ~20k pps the per-packet parse
    # cost is what overflowed the capture buffer before. Just persist the
    # frame (if saving) and move on.
    if raw_frame && (udp_data.getbyte(0) & 0x1F) == 13
      @pcap_writer.write_frame(raw_frame, Time.at(ts)) if @pcap_writer
      return
    end

    # Save to pcap if requested. When a raw frame is available (live capture)
    # write it as-is — much cheaper than rebuilding a fake IP/UDP packet per
    # packet, which matters during map-download bursts (~20k pps).
    if @pcap_writer
      if raw_frame
        @pcap_writer.write_frame(raw_frame, Time.at(ts))
      else
        pkt = build_fake_ip_udp(src_ip, dst_ip, sport, dport, udp_data)
        @pcap_writer.write_packet(pkt)
      end
    end

    # Apply local IP filter if specified
    if @options[:local_ip]
      return unless src_ip == @options[:local_ip]
    end

    parsed = FactorioProtocol.parse_udp_payload(udp_data)
    return unless parsed

    @stats[:factorio_packets] += 1
    hdr = parsed[:header]

    # Connection confirm carries this client's username. The packet is sent
    # by the client, so src_ip identifies us for self-index learning. A new
    # connection (e.g. joining a second server) may assign a new game index,
    # so reset the learned index to re-learn it from the next C→S heartbeat.
    if parsed[:connection_confirm]
      cc = parsed[:connection_confirm]
      if cc[:username]
        @self_ip = src_ip
        @self_name = cc[:username]
        @self_index = nil
      end
    end

    # ConnectionAcceptOrDeny carries the server's player list: serverUsername
    # (host) + clientPeerInfo (peer_id + name for every online player). These
    # ids are NETWORK peer ids, which equal the game player index for new
    # joiners but NOT for returning players. We register them as candidate
    # mappings; the true index is confirmed/learned from heartbeat actions.
    if parsed[:connection_accept]
      ca = parsed[:connection_accept]
      ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
      puts "#{ts_str}  [server]  game=\"#{ca[:game_name]}\" host=#{ca[:server_username]}"
      ca[:peers].each do |p|
        @peer_names[p[:peer_id]] = p[:name]
        pid = p[:peer_id] + 1
        @player_db.add(pid, p[:name])
        puts "#{ts_str}  [server]  online peer #{p[:peer_id]} -> #{p[:name]} (candidate index #{pid})"
      end
    end

    return unless (hb = parsed[:heartbeat])

    # synchronizer actions
    hb[:sync_actions]&.each do |sa|
      if sa[:username]  # NewPeerInfo — a player joined (or is this client)
        @peer_names[sa[:peer_id]] = sa[:username]
        pid = sa[:peer_id] ? sa[:peer_id] + 1 : 0
        @player_db.add(pid, sa[:username])
        ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
        # Don't print our own join as "joined the game" (we know we connected)
        unless @self_name == sa[:username]
          puts "#{ts_str}  #{sa[:username]} joined the game (peer #{sa[:peer_id]}, index #{pid})"
        end
      end
      if sa[:name] == 'PeerDisconnect' && sa[:peer_id]
        pname = @peer_names[sa[:peer_id]] || @player_db.lookup(sa[:peer_id] + 1)
        ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
        puts "#{ts_str}  #{pname} left the game"
      end
    end

    # Learn this client's own game player index from its outgoing heartbeats.
    # The first real action in a C→S tick closure carries the sender's index
    # (delta chain starts from 0xFFFF, so the first delta IS the index+1).
    if hdr[:msg_type] == 6 && @self_name && src_ip == @self_ip && @self_index.nil? && hb[:tick_closures]&.any?
      idx = nil
      hb[:tick_closures].each do |tc|
        real = tc[:actions]&.find { |a| a[:type] != 0 && a[:type] != 84 }
        if real
          idx = real[:player]
          break
        end
      end
      if idx
        @self_index = idx
        @player_db.add(idx + 1, @self_name)
        # Peer-id-based guess (peer_id+1) may differ for returning players;
        # remove any other slot claiming our name.
        @player_db.remove_other_entries_for(@self_name, idx + 1)
        ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
        puts "#{ts_str}  [self]  #{@self_name} confirmed as game player ##{idx + 1}"
      end
    end

    # tick closures → player actions
    # Ghost flag is in bit 0 of next_receive timeshift
    @ghost_mode = hb[:next_receive] ? (hb[:next_receive] & 1) == 1 : false
    
    # Validation warning when hit_unknown occurs
    if hb[:hit_unknown]
      tc = hb[:tick_closures]&.last
      if tc&.dig(:actions, -1)
        last_act = tc[:actions][-1]
        if @options[:validate]
          warn "[WARN] type #{last_act[:type]}(#{last_act[:name]}) triggered hit_unknown — previous action may have wrong data length"
        end
        # Save unknown packet for analysis
        if @unknown_writer
          pkt = build_fake_ip_udp(src_ip, dst_ip, sport, dport, udp_data)
          @unknown_writer.write_packet(pkt)
        end
      end
    end
    
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each do |act|
        @stats[:actions] += 1
        log_action(ts, act, hdr[:msg_type] == 7, ghost: @ghost_mode)
      end
    end
  end

  # Build a minimal Ethernet+IP+UDP packet for pcap storage.
  # Optimized: per-flow template with a fast checksum (the old version
  # recomputed the IP checksum with a byte loop for every packet, which was
  # a bottleneck during map-download bursts).
  def build_fake_ip_udp(src_ip, dst_ip, sport, dport, payload)
    # Template per flow: eth(14) + IP header(20, len+cksum placeholder) +
    # UDP header(8). Only the length words and checksum vary per packet.
    @pkt_templates ||= {}
    key = [src_ip, dst_ip, sport, dport]
    tmpl = @pkt_templates[key] ||= begin
      src_bytes = src_ip.split('.').map(&:to_i).pack('C4')
      dst_bytes = dst_ip.split('.').map(&:to_i).pack('C4')
      eth = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff].pack('C6') +  # dest MAC
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00].pack('C6') +  # src MAC
            [0x0800].pack('n')                                  # EtherType IPv4
      # IP header prefix: ver/ihl, tos, LEN(2B @16), id, flags/frag,
      # ttl, proto(17), CKSUM(2B @24), src(4), dst(4)
      ip = "\x45\x00" + "\x00\x00" + "\x00\x00\x00\x00" +
           "\x40\x11" + "\x00\x00" + src_bytes + dst_bytes
      udp = [sport, dport].pack('nn')
      # precomputed base of the IP checksum (16-bit words, minus the
      # length word and checksum word, one's-complement folding deferred)
      words = ip.unpack('n10')
      # words: [ver/ihl+tos, len, id, frag, ttl/proto, cksum, src_hi,
      #         src_lo, dst_hi, dst_lo] — include all constant words
      base = words[0] + words[2] + words[3] + words[4] +
             words[6] + words[7] + words[8] + words[9]
      [eth + ip, udp, base]
    end
    eth_ip, udp_hdr, csum_base = tmpl

    udp_len = 8 + payload.bytesize
    total_len = 20 + udp_len

    # IP checksum = ~ones_complement_sum(words); only the length word varies.
    sum = csum_base + total_len
    sum = (sum >> 16) + (sum & 0xFFFF)
    sum += sum >> 16
    cksum = (~sum) & 0xFFFF

    pkt = eth_ip.dup
    pkt[16, 2] = [total_len].pack('n')
    pkt[24, 2] = [cksum].pack('n')
    pkt << udp_hdr << [udp_len, 0].pack('nn') << payload
    pkt
  end

  DIR_NAMES = %w[north northnortheast northeast eastnortheast east eastsoutheast southeast southsoutheast south southsouthwest southwest westsouthwest west westnorthwest northwest northnorthwest].freeze

  # Named constants for commonly-referenced action types
  module ActionType
    NOTHING = 0
    STOP_WALKING = 1
    BEGIN_MINING = 2
    STOP_MINING = 3
    CONNECT_ROLLING_STOCK = 7
    DISCONNECT_ROLLING_STOCK = 8
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
    CURSOR_HOVER = 265
    CURSOR_CLICK_SELECT = 9
    PLAYER_LEAVE_GAME = 247
    SERVER_COMMAND = 209
    OPEN_TRAIN_GUI = 289
    SET_ENTITY_COLOR = 291
    SET_TRAINS_LIMIT = 313
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
    when ActionType::DECONSTRUCT
      if d.bytesize >= 16
        x1 = d.unpack1('i', offset: 0)
        y1 = d.unpack1('i', offset: 4)
        x2 = d.unpack1('i', offset: 8)
        y2 = d.unpack1('i', offset: 12)
        return " area=(#{'%.3f' % (x1/256.0)}, #{'%.3f' % (y1/256.0)})-(#{'%.3f' % (x2/256.0)}, #{'%.3f' % (y2/256.0)})"
      end
    when ActionType::OPEN_ITEM, ActionType::SELECTED_ENTITY_CHANGED,
         ActionType::USE_ITEM, ActionType::START_REPAIR
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
      if d.bytesize >= 14
        gt = d.getbyte(0)
        flag = d.getbyte(1)
        # Bytes 2-5: stable entity reference (tag + instance ID)
        ref_tag = d.getbyte(2)
        ref_hi = d.getbyte(3)
        ref_lo = d.unpack1('v', offset: 4)
        ref_id = (ref_hi << 16) | ref_lo
        # Bytes 6-9: per-call token (changes each invocation, not entity ID)
        token = d.unpack1('V', offset: 6)
        tick = d.unpack1('V', offset: 10) + 1
        gui_names = { 0x30 => 'entity', 0x31 => 'entity_close' }
        gname = gui_names[gt] || "type_#{gt}"
        state = flag == 0 ? 'open' : 'close'
        return " #{state} #{gname} ref=#{ref_tag}:#{ref_id} tok=#{token} tick=#{tick}"
      end
    when ActionType::CURSOR_HOVER
      if d.bytesize >= 8
        flags = d.getbyte(0)
        tick = d.unpack1('V', offset: 1)
        return " flags=#{flags} tick=#{tick}"
      end
    when ActionType::CURSOR_CLICK_SELECT
      if d.bytesize >= 8
        tick = d.unpack1('V', offset: 0)
        return " tick=#{tick}"
      end
    when ActionType::REMOTE_VIEW_SURFACE
      if d.bytesize >= 4
        surf_id = d[0, 4].unpack1('N')
        return " surface=#{surf_id}"
      end
    when ActionType::SETUP_ASSEMBLING_MACHINE
      return " recipe=#{d.unpack1('v')}" if d.bytesize >= 2
    when ActionType::CONNECT_ROLLING_STOCK, ActionType::DISCONNECT_ROLLING_STOCK
      return " ref=#{d.unpack1('V')}" if d.bytesize >= 4
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
      msg = FactorioProtocol.decode_chat(act[:data])
      if msg
        puts "#{ts_str}  #{arrow} #{pname}: #{msg}"
        return
      end
    end

    # Skip noise only in quiet mode
    return if @options[:quiet] && FactorioProtocol::NOISE_ACTIONS.include?(act[:name])
    return if act[:name].start_with?('Unknown')
    # Skip server-internal actions (no real player)
    return if act[:player] == 0xFFFF
    # Skip 'nothing' (type 0) - these are server padding/metadata after echoed actions
    return if act[:type] == 0
    # Skip server_tick_info (type 84) - server wrapper action (hash+tick) in every server heartbeat
    return if act[:name] == 'server_tick_info'

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
