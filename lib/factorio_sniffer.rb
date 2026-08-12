# frozen_string_literal: true

require 'time'
require_relative 'factorio_protocol'
require_relative 'item_db'
require_relative 'player_db'
require_relative 'pcap'
require_relative 'live_capture'
require_relative 'rcon_client'

# Mutable session state carried across hot reloads. The entry point keeps
# one of these; on Ctrl-C it snapshots the running sniffer into it, reloads
# the code, and rebuilds a sniffer with the same state — so the capture
# file keeps its position, player names survive, and stats are continuous.
class SnifferState
  attr_accessor :player_db, :pcap_writer, :unknown_writer, :stats,
                :self_ip, :self_name, :self_index, :peer_names, :conn_names,
                :roster_loaded
end

# ─────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────
class FactorioSniffer
  def initialize(options, state = nil)
    @options = options
    @state = state || SnifferState.new
    @player_db = @state.player_db || PlayerDatabase.new(options[:player_db])
    @grief = nil
    @stats = @state.stats || { packets: 0, factorio_packets: 0, actions: 0, outgoing_skipped: 0 }
    @pcap_writer = @state.pcap_writer || (options[:save_capture] ? PcapWriter.new(options[:save_capture]) : nil)
    @unknown_writer = @state.unknown_writer || (options[:save_unknowns] ? PcapWriter.new(options[:save_unknowns]) : nil)
    @item_db = nil
    if options[:item_db] && File.exist?(options[:item_db])
      @item_db = ItemDB.new(options[:item_db])
    end
    # Self (this client) tracking: we learn our own username from the
    # ConnectionRequestReplyConfirm and our own game player index from our
    # outgoing (C→S) heartbeat actions. This lets us correct the peer-id
    # based guesses from ConnectionAcceptOrDeny / NewPeerInfo, which use
    # NETWORK peer ids — those only equal game indexes for new joiners.
    @self_ip = @state.self_ip
    @self_name = @state.self_name
    @self_index = @state.self_index  # 0-indexed game player index of this client
    # peer_id (network) -> name, for join/leave events (peer ids are NOT
    # game indexes; game indexes come from heartbeat actions instead).
    @peer_names = @state.peer_names || {}
    # Server mode: this host IS the game server. Classify packet direction
    # by comparing src/dst against our own IPs and analyze ONLY incoming
    # (client→server) traffic — the outgoing direction is a broadcast of
    # every action to all N clients (N duplicates per action).
    if options[:server]
      # Explicit --server-ip wins; else the auto-detected list (default-route
      # interface first); else all local IPv4s as a last resort.
      @server_ips = options[:server_ips] ||
                    (options[:server_ip] ? [options[:server_ip]] : detect_local_ipv4)
      # src_ip -> username, learned from ConnectionRequestReplyConfirm (msg 4,
      # incoming). Bound to the real game index by the client's first C→S
      # heartbeat action below.
      @conn_names = @state.conn_names || {}
      # RCON roster: authoritative {name -> index} for players connected at
      # startup. Loaded once before capture; players who join later are
      # learned from the packet stream (msg 4 + first C→S heartbeat).
      @rcon = nil
      if options[:rcon] && !options[:no_rcon]
        begin
          @rcon = RconClient.new(**options[:rcon])
        rescue => e
          warn "RCON roster disabled: #{e.class}: #{e.message}"
          @rcon = nil
        end
      end
    end
  end

  # Run the capture/analysis loop. Blocks until the source is exhausted
  # (pcap) or Interrupt is raised (live capture). Does NOT finalize — the
  # entry point calls #finish when actually shutting down, so a hot reload
  # can keep the capture file and state alive.
  def run
    if @options[:server] && @server_ips.empty?
      puts 'Error: --server mode could not determine the server IP.'
      puts '  Pass --server-ip <ip> to set it explicitly.'
      exit 1
    end

    if @options[:server]
      puts 'SERVER MODE: analyzing only incoming (client→server) packets — no broadcast duplicates'
      puts "  server IP(s): #{@server_ips.join(', ')}"
      puts '  map-download TransferBlocks (save file) excluded from analysis and capture'
    end

    if @options[:pcap]
      reader = PcapReader.new(@options[:pcap])
      reader.each_packet { |*args| process_packet(*args) }
    elsif @options[:interface]
      # Seed the roster before capturing so existing players' names are
      # known from the start (RCON is authoritative; later joiners are
      # learned from the packet stream). One-shot — see load_roster.
      load_roster if @rcon
      capturer = LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
        transfer_block_sink: @pcap_writer,
      )
      puts "Listening on #{@options[:interface]} port #{@options[:port]}..."
      puts 'Press Ctrl+C to reload code; Ctrl+C again to quit.'
      if @options[:local_ip]
        puts "Filtering: showing only packets involving #{@options[:local_ip]}"
      end
      capturer.each_packet { |*args| process_packet(*args) }
    end
  end

  # Finalize the session: summary, persist player names, close writers.
  def finish
    print_summary
    @player_db.save
    @pcap_writer&.close
    @unknown_writer&.close
  end

  # Capture the stateful objects so a hot-reloaded instance can pick up
  # where this one left off (same capture file, same player DB, stats,
  # learned identities).
  def snapshot
    SnifferState.new.tap do |st|
      st.player_db = @player_db
      st.pcap_writer = @pcap_writer
      st.unknown_writer = @unknown_writer
      st.stats = @stats
      st.self_ip = @self_ip
      st.self_name = @self_name
      st.self_index = @self_index
      st.peer_names = @peer_names
      st.conn_names = @conn_names
      st.roster_loaded = @state.roster_loaded
    end
  end

  private

  # Local IPv4 addresses, used in server mode to classify packet direction
  # (dst = incoming/client→server, src = outgoing/server→client).
  def detect_local_ipv4
    require 'socket'
    Socket.getifaddrs
          .select { |a| a.addr&.ipv4? }
          .map { |a| a.addr.ip_address }
          .reject { |ip| ip.start_with?('127.') }
          .uniq
  rescue => e
    warn "Warning: could not detect local IPs (#{e}); pass --server-ip"
    []
  end

  def process_packet(pkt_num, ts, src_ip, dst_ip, sport, dport, udp_data, raw_frame = nil)
    @stats[:packets] += 1

    # Server mode: the server already has the save on disk, so the map
    # download (msg 13 TransferBlocks, ~40 MB per joining player) is dropped
    # entirely — no analysis, no capture. Avoids capture-buffer pressure and
    # pointless disk usage from N copies of the same save.
    if @options[:server] && (udp_data.getbyte(0) & 0x1F) == 13
      return
    end

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

    # Server mode: analyze ONLY incoming (client→server) packets. Every
    # player action arrives at the server exactly once; the server then
    # broadcasts it to all N clients, so the outgoing direction is N
    # duplicates. Tradeoff (documented): incoming packets have not yet been
    # validated/echoed by the server — cross-check with RCON if needed.
    if @options[:server]
      unless @server_ips.include?(dst_ip)
        @stats[:outgoing_skipped] += 1
        return
      end
    end

    # Apply local IP filter if specified (client mode)
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
        if @options[:server]
          # Server mode: every connecting client's username (not just a
          # "self" client). Bound to a game index by their first C→S
          # heartbeat action below.
          @conn_names[src_ip] = cc[:username]
          ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
          puts "#{ts_str}  #{cc[:username]} connected (from #{src_ip})"
        else
          @self_ip = src_ip
          @self_name = cc[:username]
          @self_index = nil
        end
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

    # Bind usernames to game indexes from C→S heartbeat actions. In a C→S
    # tick closure the first real action carries the SENDER's game index
    # (delta chain starts from 0xFFFF, so the first delta IS the index+1).
    if hdr[:msg_type] == 6 && hb[:tick_closures]&.any?
      idx = nil
      hb[:tick_closures].each do |tc|
        real = tc[:actions]&.find { |a| a[:type] != 0 && a[:type] != 84 }
        if real
          idx = real[:player]
          break
        end
      end
      if idx
        if @options[:server]
          # Server mode: learn EVERY client's name→index. msg 4 gave us
          # src_ip→name; the first real action in their C→S heartbeat gives
          # the game index. RCON /players is the authoritative cross-check.
          name = @conn_names.delete(src_ip)
          if name
            @player_db.add(idx + 1, name)
            @player_db.remove_other_entries_for(name, idx + 1)
            ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
            puts "#{ts_str}  #{name} confirmed as game player ##{idx + 1}"
          end
        elsif @self_name && src_ip == @self_ip && @self_index.nil?
          @self_index = idx
          @player_db.add(idx + 1, @self_name)
          # Peer-id-based guess (peer_id+1) may differ for returning players;
          # remove any other slot claiming our name.
          @player_db.remove_other_entries_for(@self_name, idx + 1)
          ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
          puts "#{ts_str}  [self]  #{@self_name} confirmed as game player ##{idx + 1}"
        end
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
    CHANGE_SHOOTING_STATE = 87
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
    SELECTED_ENTITY_CHANGED_VERY_CLOSE = 265
    SELECTED_ENTITY_CHANGED_BASED_ON_UNIT_NUMBER = 266
    SELECTED_ENTITY_CHANGED_VERY_CLOSE_PRECISE = 267
    SELECTED_ENTITY_CHANGED_RELATIVE = 268
    SELECTED_ENTITY_CLEARED = 9
    ZOOM_AROUND_POINT = 128
    MOVE_ON_PAN = 129
    RENDER_MODE_CHANGED = 310
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
    when ActionType::OPEN_ITEM, ActionType::USE_ITEM, ActionType::START_REPAIR
      if d.bytesize >= 4
        eid = d.unpack1('V')
        return " entity=##{eid}"
      end
    when ActionType::CHANGE_SHOOTING_STATE
      if d.bytesize >= 9
        flag = d.getbyte(0)
        x = d.unpack1('V', offset: 1) / 256.0
        y = d.unpack1('V', offset: 5) / 256.0
        return " shooting=#{flag} pos=(#{'%.3f' % x}, #{'%.3f' % y})"
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
      elsif d.bytesize >= 6
        # Client form (8 bytes): [gui_type][flags][tick(4)][pad(2)]
        gt = d.getbyte(0)
        flag = d.getbyte(1)
        tick = d.unpack1('V', offset: 2)
        gui_names = { 0x30 => 'entity', 0x31 => 'entity_close' }
        gname = gui_names[gt] || "type_#{gt}"
        state = flag == 0 ? 'open' : 'close'
        return " #{state} #{gname} tick=#{tick}"
      end
    when ActionType::SELECTED_ENTITY_CHANGED_VERY_CLOSE,
         ActionType::SELECTED_ENTITY_CHANGED_BASED_ON_UNIT_NUMBER,
         ActionType::SELECTED_ENTITY_CHANGED_VERY_CLOSE_PRECISE,
         ActionType::SELECTED_ENTITY_CHANGED_RELATIVE
      # Client form: [payload][tick(4)][pad(4)] — payload len 1/1/2/4
      # Server echo: [payload][ref(4)][token(4)][tick-1(4)][pad(4)]
      plen = { 265 => 1, 266 => 1, 267 => 2, 268 => 4 }[act[:type]] || 0
      if d.bytesize >= plen + 12 && d.getbyte(plen) == 0x54
        payload = d[0, plen].unpack1('H*')
        tok = d.unpack1('V', offset: plen + 4)
        tick = d.unpack1('V', offset: plen + 8) + 1
        return " payload=#{payload} tok=#{tok} tick=#{tick}"
      elsif d.bytesize >= plen + 4
        payload = d[0, plen].unpack1('H*')
        tick = d.unpack1('V', offset: plen)
        return " payload=#{payload} tick=#{tick}"
      end
    when ActionType::SELECTED_ENTITY_CLEARED
      # Client: [tick(4)][pad(4)]; server echo: [ref(4)][token(4)]
      if d.bytesize >= 8 && d.getbyte(0) == 0x54
        tok = d.unpack1('V', offset: 4)
        return " tok=#{tok}"
      elsif d.bytesize >= 8
        tick = d.unpack1('V', offset: 0)
        return " tick=#{tick}"
      end
    when ActionType::ZOOM_AROUND_POINT
      if d.bytesize >= 24
        a, b, c = d.unpack('E3')
        return " (#{'%.2f' % a}, #{'%.2f' % b}, #{'%.2f' % c})"
      end
    when ActionType::MOVE_ON_PAN
      if d.bytesize >= 17
        x = d.unpack1('l', offset: 0) / 256.0
        y = d.unpack1('l', offset: 4) / 256.0
        v = d.unpack1('l', offset: 8)
        f = d.unpack1('e', offset: 12)
        return " pos=(#{'%.2f' % x}, #{'%.2f' % y}) int=#{v} f=#{'%.2f' % f}"
      end
    when ActionType::RENDER_MODE_CHANGED
      return " mode=#{d.getbyte(0)}" if d.bytesize >= 1
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

  # Query the RCON roster once and merge {name -> index} into the player
  # DB, so players connected at startup are named immediately. Players who
  # join later are captured from the packet stream (msg 4 username + first
  # C→S heartbeat game index). A failed query is skipped silently.
  #
  # One-shot (state.roster_loaded survives hot reloads): the roster is only
  # authoritative for the moment we started — joiners/leavers are tracked via
  # the packet stream from then on, and re-querying on every Ctrl-C just
  # reprints the same list.
  def load_roster
    return if @state.roster_loaded
    @state.roster_loaded = true
    return unless @rcon
    players = @rcon.connected_players
    return if players.nil? || players.empty?
    players.each do |p|
      @player_db.add(p[:index], p[:name])
      @player_db.remove_other_entries_for(p[:name], p[:index])
    end
    ts = Time.now.strftime('%H:%M:%S.%L')
    puts "#{ts}  [rcon]  connected players (#{players.size}): " +
         players.map { |p| "#{p[:name]} (##{p[:index]})" }.join(', ')
  end

  def print_summary
    puts "[summary] packets=#{@stats[:packets]} factorio=#{@stats[:factorio_packets]} actions=#{@stats[:actions]}"
    puts "[summary] outgoing broadcasts skipped (server mode)=#{@stats[:outgoing_skipped]}" if @options[:server]
  end
end
