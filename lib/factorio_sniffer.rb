# frozen_string_literal: true

require 'time'
require_relative 'factorio_protocol'
require_relative 'item_db'
require_relative 'player_db'
require_relative 'pcap'
require_relative 'live_capture'
require_relative 'rcon_client'
require_relative 'ai_agent'
require_relative 'player_attrs'

# Mutable session state carried across hot reloads. The entry point keeps
# one of these; on Ctrl-C it snapshots the running sniffer into it, reloads
# the code, and rebuilds a sniffer with the same state — so the capture
# file keeps its position, player names survive, and stats are continuous.
class SnifferState
  attr_accessor :player_db, :pcap_writer, :unknown_writer, :stats,
                :self_ip, :self_name, :self_index, :peer_names, :conn_names,
                :conn_ip_name, :roster_loaded, :ai_agent, :online, :attrs,
                :game_tick, :attrs_loaded, :protocol_version, :chat_segments,
                :show_players, :hide_players, :show_actions, :hide_actions,
                :chat_only, :quiet
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
    @stats = @state.stats || { packets: 0, factorio_packets: 0, actions: 0, outgoing_skipped: 0, capture_skipped: 0 }
    # --save-capture [PATH]: bare flag = ALWAYS auto-name the capture
    # (default captures/ dir; server-<port> in server mode, client-<ip>
    # in client mode — deferred until the first packet reveals the
    # server). An explicit PATH still works for tests/tools. The state's
    # writer (hot reload) is always reused.
    @pcap_writer = @state.pcap_writer
    @pending_capture = nil
    if options[:save_capture] && !@pcap_writer
      cap = options[:save_capture]
      if cap == true
        dir = default_capture_dir
        if options[:server]
          @pcap_writer = new_pcap_writer(auto_capture_path(dir, "server-#{options[:port]}"))
          puts "capturing to #{@pcap_writer.path}"
        else
          @pending_capture = dir  # resolved on the first packet (client mode)
        end
      else
        @pcap_writer = new_pcap_writer(cap)
      end
    end
    @unknown_writer = @state.unknown_writer || (options[:save_unknowns] ? PcapWriter.new(options[:save_unknowns]) : nil)
    @item_db = nil
    if options[:item_db] && File.exist?(options[:item_db])
      @item_db = ItemDB.new(options[:item_db])
    end
    @entity_db = nil
    if options[:entity_db] && File.exist?(options[:entity_db])
      @entity_db = ItemDB.new(options[:entity_db])
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
    # name -> game index for players currently in-game. Unlike player_db
    # (permanent mapping) this tracks ONLINE status: seeded from the RCON
    # roster, added on NewPeerInfo (join), index bound from the first C→S
    # heartbeat, removed on PeerDisconnect. Survives hot reloads via state.
    @online = @state.online || {}
    # src_ip → name for CONFIRMED (in-game) players — lets a clean-quit
    # signal (C→S PeerDisconnect sync action / msg 14) resolve the leaver
    # without S→C analysis.
    @conn_ip_name = @state.conn_ip_name || {}
    # Cross-packet chat segment reassembly buffer: [player, total_segs] =>
    # {seg_no => payload}. Split chat messages arrive as separate
    # input-action segments across packets; merged when complete. Survives
    # hot reloads via state.
    @chat_segments = @state.chat_segments || {}
    # Mirrored LuaPlayer attributes (connected/admin/online_time): seeded
    # once from RCON, maintained by packet decoding. See PlayerAttrs.
    @attrs = @state.attrs || PlayerAttrs.new
    # Latest game tick observed in heartbeat tick closures — the clock for
    # lazy online_time computation (60 ticks/s, tick is in every closure).
    @game_tick = @state.game_tick || 0
    # Interactive output filters (stdin console, /show /hide /chat /quiet).
    # Survive hot reloads via state. Empty list = no restriction.
    @show_players = @state.show_players || []
    @hide_players = @state.hide_players || []
    @show_actions = @state.show_actions || []
    @hide_actions = @state.hide_actions || []
    @chat_only = @state.chat_only || false
    # Runtime toggle overrides the --quiet startup flag (state wins).
    @quiet = @state.quiet.nil? ? !!@options[:quiet] : @state.quiet
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
      # Item/entity name lookup: explicit --item-db / --entity-db files win;
      # otherwise dump both from RCON via helpers.write_file and read them
      # back from script-output (`prototypes.<kind>` iteration order = wire
      # ids; `game.*_prototypes` does not exist at runtime). See
      # docs/rcon-knowledge.md.
      if @rcon && @rcon.script_output_dir
        begin
          @rcon.dump_prototype_files
          unless @item_db
            f = File.join(@rcon.script_output_dir, 'factorio-sniffer-items.txt')
            if File.exist?(f) && File.size(f) > 0
              @item_db = ItemDB.new(f)
              puts "Item DB populated from RCON: #{@item_db.size} items"
            end
          end
          unless @entity_db
            f = File.join(@rcon.script_output_dir, 'factorio-sniffer-entities.txt')
            if File.exist?(f) && File.size(f) > 0
              @entity_db = ItemDB.new(f)
              puts "Entity DB populated from RCON: #{@entity_db.size} entities"
            end
          end
        rescue => e
          warn "Prototype DB from RCON failed: #{e.class}: #{e.message}"
        end
      end
      # Protocol version → input-action SEGMENT-type mapping. Explicit
      # --protocol-version wins; otherwise ask RCON for
      # helpers.game_version (cached in state so hot reloads keep it). Main
      # action types are version-stable and need no switch — only segments
      # follow defines.input_action.
      # HiveMind AI agent: reads packet-decoded chat and answers players who
      # say "hivemind". Survives hot reloads (kept in SnifferState so the
      # LLM context and rate limiter carry over).
      @agent = @state.ai_agent
      # Re-point the agent's online-player source at THIS sniffer instance —
      # needed on every construction (fresh or hot-reloaded) since the agent
      # persists while the sniffer object is rebuilt.
      @agent.online_provider = -> { online_players } if @agent
      @agent.player_stats_provider = -> { player_stats } if @agent
      if options[:ai_agent] && !@agent
        if @rcon
          @agent = HiveMindAgent.new(
            rcon: @rcon,
            model: options[:ai_model],
            provider: options[:ai_provider],
            api_key: options[:ai_api_key],
            api_base: options[:ai_api_base],
          )
          @agent.online_provider = -> { online_players }
          @agent.player_stats_provider = -> { player_stats }
          unless @agent.disabled?
            puts "[hivemind] AI agent online — answering chat for \"#{@agent.trigger_label}\" (model #{@agent.model})"
          end
        else
          warn '[hivemind] --ai-agent requires RCON (server mode); agent disabled'
        end
      end
    end

    # Version → segment-type mapping (server mode may also query RCON here;
    # the RCON client is only created in server mode). Runs on every
    # construction, including hot reloads.
    select_protocol_version
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
      if @pcap_writer && !@options[:full_capture]
        puts '  capture: incoming-only + no keepalive-only heartbeats (~20MB per 5h vs ~460MB; --full-capture to record everything)'
      end
    elsif @pcap_writer && !@options[:save_transfer_blocks] && !@options[:full_capture]
      puts '  capture: TransferBlocks (msg 13) and keepalive-only heartbeats excluded (--full-capture to record everything)'
    end

    if @options[:pcap]
      reader = PcapReader.new(@options[:pcap])
      reader.each_packet { |*args| process_packet(*args) }
    elsif @options[:interface]
      # Seed the roster before capturing so existing players' names are
      # known from the start (RCON is authoritative; later joiners are
      # learned from the packet stream). One-shot — see load_roster.
      load_roster if @rcon
      load_player_attrs if @rcon
      capturer = LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
        transfer_block_sink: (@options[:save_transfer_blocks] || @options[:full_capture] ? @pcap_writer : nil),
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
  # Long-term memory: distill the session into the keyed memory blobs
  # (soul/knowledge/<player>) so a NEW session can resume what Hivemind
  # learned. Runs synchronously — the process is exiting, so wait for the
  # memories to land. No-op when the agent is disabled or memory is off
  # (also: pcap analysis without RCON, where the agent never enabled).
  def finish
    print_summary
    @player_db.save
    @pcap_writer&.close
    @unknown_writer&.close
    @agent&.compact_memory!('quit')
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
      st.conn_ip_name = @conn_ip_name
      st.chat_segments = @chat_segments
      st.roster_loaded = @state.roster_loaded
      st.ai_agent = @agent
      st.online = @online
      st.attrs = @attrs
      st.game_tick = @game_tick
      st.attrs_loaded = @state.attrs_loaded
      st.protocol_version = @state.protocol_version
      st.show_players = @show_players
      st.hide_players = @hide_players
      st.show_actions = @show_actions
      st.hide_actions = @hide_actions
      st.chat_only = @chat_only
      st.quiet = @quiet
    end
  end

  private

  # Whether to persist this packet to the capture file. --full-capture keeps
  # everything; otherwise drop (a) keepalive-only heartbeats (no input
  # actions / sync actions / heartbeat requests — ~40% of packets in a
  # typical session) and (b) in server mode, outgoing (server→client)
  # broadcasts: analysis only reads incoming packets, so the outgoing
  # direction is N duplicates of the same data (~47% of a server capture).
  def capture_recordable?(src_ip, dst_ip, udp_data)
    return true if @options[:full_capture]
    if @options[:server]
      return false unless @server_ips.include?(dst_ip)
    end
    recordable_heartbeat?(udp_data)
  end

  # Cheap flag-byte check: keep heartbeats that carry heartbeat requests
  # (0x01), a synchronizer action (0x10), or tick closures that are not
  # all-empty (0x02 set, 0x08 clear). Drop pure keepalives. Fragmented
  # heartbeats are always kept (byte 1 is message_id there, not flags).
  def recordable_heartbeat?(udp_data)
    return true if udp_data.bytesize < 2
    mt = udp_data.getbyte(0) & 0x1F
    return true unless mt == 6 || mt == 7
    return true if (udp_data.getbyte(0) & 0x40) != 0
    f = udp_data.getbyte(1)
    (f & 0x01) != 0 || (f & 0x10) != 0 || ((f & 0x02) != 0 && (f & 0x08) == 0)
  end

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

    # Client mode auto-named capture: resolve the server IP from the first
    # identifiable packet and create the writer (server mode creates it at
    # init — server-<port>).
    ensure_pcap_writer(src_ip, dst_ip) if @pending_capture

    # RequestForHeartbeatWhenDisconnecting (msg 14) — documented as a C→S
    # clean-quit request (header only). Never observed in captures so far
    # (all real quits use the C→S PeerDisconnect sync action in the final
    # heartbeat, handled below); kept as a belt-and-braces fallback:
    # resolve the src_ip to a player and mark them offline.
    if (udp_data.getbyte(0) & 0x1F) == 14
      handle_client_disconnect(src_ip, ts)
      return
    end

    # Server mode: the server already has the save on disk, so the map
    # download (msg 13 TransferBlocks, ~40 MB per joining player) is dropped
    # entirely — no analysis, no capture. Avoids capture-buffer pressure and
    # pointless disk usage from N copies of the same save. --full-capture
    # overrides (falls through to the msg-13 gate below, which writes).
    if @options[:server] && (udp_data.getbyte(0) & 0x1F) == 13 && !@options[:full_capture]
      @stats[:capture_skipped] += 1 if @pcap_writer
      return
    end

    # TransferBlock (msg 13) packets carry raw save data — never analyzed,
    # and at ~20k pps the per-packet parse cost is what overflowed the
    # capture buffer before. Record them only when explicitly requested
    # (--save-transfer-blocks / --full-capture); the default is to drop them:
    # they contain no player actions and added ~12% to a 4.9M-packet capture.
    if (udp_data.getbyte(0) & 0x1F) == 13
      if @pcap_writer && (@options[:save_transfer_blocks] || @options[:full_capture])
        if raw_frame
          @pcap_writer.write_frame(raw_frame, Time.at(ts))
        else
          pkt = build_fake_ip_udp(src_ip, dst_ip, sport, dport, udp_data)
          @pcap_writer.write_packet(pkt)
        end
      else
        @stats[:capture_skipped] += 1 if @pcap_writer
      end
      return
    end

    # Save to pcap if requested. When a raw frame is available (live capture)
    # write it as-is — much cheaper than rebuilding a fake IP/UDP packet per
    # packet, which matters during map-download bursts (~20k pps).
    # capture_recordable? drops keepalive-only heartbeats and (server mode)
    # outgoing broadcasts from the file — analysis-uninteresting packets.
    if @pcap_writer
      if capture_recordable?(src_ip, dst_ip, udp_data)
        if raw_frame
          @pcap_writer.write_frame(raw_frame, Time.at(ts))
        else
          pkt = build_fake_ip_udp(src_ip, dst_ip, sport, dport, udp_data)
          @pcap_writer.write_packet(pkt)
        end
      else
        @stats[:capture_skipped] += 1
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

    # Track the game tick (clock for lazy online_time): the last tick closure
    # carries the current tick. Anchor any connected players seeded from RCON
    # whose live-session start we haven't observed yet.
    if (last_tc = hb[:tick_closures]&.last) && last_tc[:tick]
      @game_tick = last_tc[:tick] if last_tc[:tick] > @game_tick
      @attrs.anchor_sessions(@game_tick)
    end

    # synchronizer actions
    hb[:sync_actions]&.each do |sa|
      if sa[:username]  # NewPeerInfo — a player joined (or is this client)
        @peer_names[sa[:peer_id]] = sa[:username]
        pid = sa[:peer_id] ? sa[:peer_id] + 1 : 0
        @player_db.add(pid, sa[:username])
        @online[sa[:username]] ||= nil  # index bound once a C→S heartbeat confirms it
        @attrs.connect(sa[:username], @game_tick)
        ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
        # Don't print our own join as "joined the game" (we know we connected)
        unless @self_name == sa[:username]
          @agent&.on_player_event(:joined, sa[:username])
          puts "#{ts_str}  #{sa[:username]} joined the game (peer #{sa[:peer_id]}, index #{pid})" if player_visible?(sa[:username])
        end
      end
      if sa[:name] == 'PeerDisconnect'
        if sa[:peer_id]
          # S→C broadcast form (client mode): names the departed peer.
          pname = @peer_names[sa[:peer_id]] || @player_db.lookup(sa[:peer_id] + 1)
          @online.delete(pname) if pname
          @attrs.disconnect(pname, @game_tick) if pname
          @agent&.on_player_event(:left, pname) if pname
          ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
          puts "#{ts_str}  #{pname} left the game" if player_visible?(pname)
        else
          # C→S form (server mode): the SENDER announces its own disconnect
          # in its FINAL heartbeat — capture-verified (reason=0, no peer_id;
          # the peer_id form is the S→C broadcast). This is the server
          # mode's clean-quit signal (S→C broadcasts aren't analyzed).
          handle_client_disconnect(src_ip, ts)
        end
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
            @online[name] = idx + 1
            @attrs.set_index(name, idx + 1)
            # src_ip → name for connected players: lets the clean-quit
            # signals (C→S PeerDisconnect sync action, msg 14 fallback)
            # resolve the leaver on C→S alone. Server mode has no S→C
            # analysis (NewPeerInfo/PeerDisconnect broadcasts are dropped),
            # so joins are detected here and leaves via the final
            # heartbeat's PeerDisconnect sync action.
            @conn_ip_name[src_ip] = name
            @agent&.on_player_event(:joined, name)
            ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
            puts "#{ts_str}  #{name} confirmed as game player ##{idx + 1}"
          end
        elsif @self_name && src_ip == @self_ip && @self_index.nil?
          @self_index = idx
          @player_db.add(idx + 1, @self_name)
          # Peer-id-based guess (peer_id+1) may differ for returning players;
          # remove any other slot claiming our name.
          @player_db.remove_other_entries_for(@self_name, idx + 1)
          @online[@self_name] = idx + 1
          @attrs.set_index(@self_name, idx + 1)
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
    REMOTE_VIEW_SURFACE = 260
    QUICK_BAR_SET = 245
    QUICK_BAR_PICK = 246
    PIPETTE = 90
    CURSOR_TRANSFER = 78
    STACK_TRANSFER = 80
    INVENTORY_TRANSFER = 83
    CRAFT = 85
    WIRE_DRAGGING = 86
    CHANGE_SHOOTING_STATE = 87
    DROP_ITEM = 67
    BUILD = 68
    USE_ITEM = 124
    START_REPAIR = 130
    DECONSTRUCT = 131
    COPY = 133
    CHEAT = 58
    STOP_DRAG_BUILD = 48
    ROTATE_ENTITY = 280
    FLIP_ENTITY = 281
    FAST_ENTITY_SPLIT = 282
    WRITE_TO_CONSOLE = 106
    FAST_ENTITY_TRANSFER = 279
    CHANGE_PICKING_STATE = 265
    SELECTED_ENTITY_CHANGED_VERY_CLOSE = 266
    SELECTED_ENTITY_CHANGED_VERY_CLOSE_PRECISE = 267
    SELECTED_ENTITY_CHANGED_RELATIVE = 268
    SELECTED_ENTITY_CLEARED = 9
    ZOOM_AROUND_POINT = 128
    MOVE_ON_PAN = 129
    RENDER_MODE_CHANGED = 310
    OPEN_TRAIN_GUI = 290
    SET_ENTITY_COLOR = 292
    SET_TRAINS_LIMIT = 314
  end

  def format_action_data(act)
    return '' unless act[:data] && act[:data].bytesize > 0
    d = act[:data]

    case act[:name]
    when "start_walking"
      dir = FactorioProtocol::Position.direction(act)
      if dir && dir.size >= 2
        x, y = dir
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
    when "begin_mining_terrain"
      pos = FactorioProtocol::Position.decode(act)
      return " pos=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]})" if pos
    when "drop_item"
      # 8-byte payload is a DIRECTION double, not a position (verified
      # 2026-08-16). Print it as a direction to avoid emitting a bogus
      # position from the raw i32s.
      dir = FactorioProtocol::Position.direction(act)
      return " dir=(#{'%.2f' % dir[0]})" if dir
    when "deconstruct"
      area = FactorioProtocol::Position.decode(act)
      if area
        x1, y1, x2, y2 = area
        return " area=(#{'%.3f' % x1}, #{'%.3f' % y1})-(#{'%.3f' % x2}, #{'%.3f' % y2})"
      end
    when "open_item", "use_item", "start_repair"
      if d.bytesize >= 4
        eid = d.unpack1('V')
        return " entity=##{eid}"
      end
    when "change_shooting_state"
      pos = FactorioProtocol::Position.decode(act)
      if pos && d.bytesize >= 9
        return " shooting=#{d.getbyte(0)} pos=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]})"
      end
    when "build"
      pos = FactorioProtocol::Position.decode(act)
      if pos && d.bytesize >= 9
        dir = d.getbyte(8)
        dname = DIR_NAMES[dir] || dir
        return " pos=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]}) dir=#{dname}"
      end
    when "move_on_pan"
      pos = FactorioProtocol::Position.decode(act)
      return " pan=(#{'%.3f' % pos[0]}, #{'%.3f' % pos[1]})" if pos
    when "rotate_entity"
      return " dir=#{d.getbyte(0)}"
    when "flush_opened_entity_specific_fluid"
      # 1-byte selector (0x00/0x01 observed). Whether it is a fluid
      # prototype ID (prototypes.fluid order: 1=water, 4=petroleum-gas,
      # 5=light-oil …) is unverified — the fluid may be resolved by the
      # simulation (on_player_flushed_fluid event, Lua-only). Test: flush
      # a KNOWN fluid and compare the byte.
      return " selector=0x#{d.getbyte(0).to_s(16)}" if d.bytesize >= 1
    when "flush_opened_entity_fluid"
      return " flush" if d.bytesize >= 1
    when "fast_entity_split"
      return " slot=#{d.getbyte(0)}"
    when "fast_entity_transfer"
      dir = d.getbyte(0) == 1 ? 'put' : 'take'
      return " #{dir}"
    when "change_riding_state"
      return " vehicle=#{d.unpack1('v')}" if d.bytesize >= 2
    when "craft"
      return " recipe_id=#{d.unpack1('V')}" if d.bytesize >= 4
    when "cursor_transfer"
      if d.bytesize >= 9
        item_id = d.unpack1('v')
        item_name = @item_db ? @item_db.name(item_id) : "item_#{item_id}"
        action = d.unpack1('V', offset: 2)
        act = action == 1 ? 'put' : 'clear'
        return " #{item_name} #{act}"
      end
    when "open_gui"
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
    when "selected_entity_changed_very_close",
         "selected_entity_changed_very_close_precise",
         "selected_entity_changed_relative"
      # Client form: [payload][tick(4)][pad(4)] — payload len 1/2/4
      # Server echo: [payload][ref(4)][token(4)][tick-1(4)][pad(4)]
      plen = { 'selected_entity_changed_very_close' => 1,
               'selected_entity_changed_very_close_precise' => 2,
               'selected_entity_changed_relative' => 4 }[act[:name]] || 0
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
    when "selected_entity_cleared"
      # Client: [tick(4)][pad(4)]; server echo: [ref(4)][token(4)]
      if d.bytesize >= 8 && d.getbyte(0) == 0x54
        tok = d.unpack1('V', offset: 4)
        return " tok=#{tok}"
      elsif d.bytesize >= 8
        tick = d.unpack1('V', offset: 0)
        return " tick=#{tick}"
      end
    when "zoom_around_point"
      if d.bytesize >= 24
        a, b, c = d.unpack('E3')
        return " (#{'%.2f' % a}, #{'%.2f' % b}, #{'%.2f' % c})"
      end
    when "move_on_pan"
      if d.bytesize >= 17
        x = d.unpack1('l', offset: 0) / 256.0
        y = d.unpack1('l', offset: 4) / 256.0
        v = d.unpack1('l', offset: 8)
        f = d.unpack1('e', offset: 12)
        return " pos=(#{'%.2f' % x}, #{'%.2f' % y}) int=#{v} f=#{'%.2f' % f}"
      end
    when "render_mode_changed"
      return " mode=#{d.getbyte(0)}" if d.bytesize >= 1
    when "remote_view_surface"
      if d.bytesize >= 4
        surf_id = d[0, 4].unpack1('N')
        return " surface=#{surf_id}"
      end
    when "setup_assembling_machine"
      return " recipe=#{d.unpack1('v')}" if d.bytesize >= 2
    when "connect_rolling_stock", "disconnect_rolling_stock"
      return " ref=#{d.unpack1('V')}" if d.bytesize >= 4
    when "pipette"
      if d.bytesize >= 9
        src = d.getbyte(0)
        ref = d.unpack1('V', offset: 1)
        qual = d.getbyte(8)
        # src=0 (inventory/quickbar): ref is the ITEM prototype id
        # (`prototypes.item` order). src=4 (world entity): ref is the ENTITY
        # prototype id (`prototypes.entity` order) — capture-verified against
        # the live server: refs like 87=stone-furnace, 149=iron-ore,
        # 148=copper-ore. NOT an item id (item 87=nuclear-reactor,
        # 149=carbon — those never appear pipetted from the world) and NOT an
        # entity unit_number.
        if src == 0 && @item_db
          return " #{@item_db.name(ref)} qual=#{qual}"
        elsif src == 4 && @entity_db
          return " entity=#{@entity_db.name(ref)} qual=#{qual}"
        end
        return " src=#{src} ref=#{ref} qual=#{qual}"
      end
    when "stack_transfer", "inventory_transfer"
      if d.bytesize >= 5
        item_id = d.unpack1('v')
        item_name = @item_db ? @item_db.name(item_id) : "item_#{item_id}"
        count = d.unpack1('v', offset: 2)
        return " #{item_name} count=#{count}"
      end
    when "quick_bar_pick_slot"
      if d.bytesize >= 2
        row = d.getbyte(0)
        slot = d.getbyte(1)
        return " row=#{row} slot=#{slot}"
      end
    when "quick_bar_set_slot"
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
    when "copy"
      return " flags=#{d.unpack1('v')}" if d.bytesize >= 2
    when "cheat"
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

    # Any real input action (not server-internal padding) resets the
    # player's afk_time — mirrors LuaPlayer.afk_time, fed by C→S actions.
    @attrs.register_action(pname, @game_tick) if pname && act[:type] != 0 && act[:name] != 'server_tick_info'

    # Chat messages: ALWAYS printed (exempt from all filters) and fed to
    # the agent — chat is the important signal, filters are for action
    # spam. /chat chat-only mode still hides non-chat actions. Split
    # messages are reassembled across packets (chat_action_data) before
    # decoding.
    if act[:name] == 'write_to_console'
      data = chat_action_data(act, pname, ts)
      if data
        msg = FactorioProtocol.decode_chat(data)
        if msg
          @agent&.on_chat(pname, msg)
          puts "#{ts_str}  #{arrow} #{pname}: #{msg}"
        end
      end
      return
    end

    return unless visible?(pname, act)

    # Skip noise only in quiet mode
    return if @quiet && FactorioProtocol::NOISE_ACTIONS.include?(act[:name])
    return if act[:name].start_with?('Unknown')
    # Skip server-internal actions (no real player)
    return if act[:player] == 0xFFFF
    # Skip 'nothing' (type 0) - these are server padding/metadata after echoed actions
    return if act[:type] == 0
    # Skip server_tick_info (type 84) - server wrapper action (hash+tick) in every server heartbeat
    return if act[:name] == 'server_tick_info'

    # Format action data (position, entity refs, etc.)
    data_str = format_action_data(act)
    suffix = ghost && act[:name] == 'build' ? ' [ghost]' : ''
    if @options[:dump_raw_types]
      hex = act[:data] ? act[:data].unpack1('H*') : ''
      data_str += " [#{hex}]"
    end
    puts "#{ts_str}  #{arrow} #{pname.ljust(16)} #{act[:name].ljust(28)}#{data_str}#{suffix}"
  end

  # ── Interactive filter console (stdin) ──────────────────────────

  # Visibility of an action line: player filters (AND) + chat-only + action
  # filters. Filters are stored downcased; names are matched case-
  # insensitively.
  def visible?(pname, act)
    name = pname.to_s.downcase
    return false if @hide_players.include?(name)
    return false if @show_players.any? && !@show_players.include?(name)
    return false if @chat_only && act[:name] != 'write_to_console'
    return false if @hide_actions.include?(act[:name])
    return false if @show_actions.any? && !@show_actions.include?(act[:name])
    true
  end

  # Same player filtering for join/leave lines (no action criteria).
  def player_visible?(name)
    n = name.to_s.downcase
    return false if @hide_players.include?(n)
    return false if @show_players.any? && !@show_players.include?(n)
    true
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
      @online[p[:name]] = p[:index]  # authoritative online seed (name → game index)
    end
    ts = Time.now.strftime('%H:%M:%S.%L')
    puts "#{ts}  [rcon]  connected players (#{players.size}): " +
         players.map { |p| "#{p[:name]} (##{p[:index]})" }.join(', ')
  end

  public

  # Names of players currently in-game (online tracking): seeded from the
  # RCON roster at startup, updated from NewPeerInfo / PeerDisconnect and
  # bound to game indexes by C→S heartbeats. Sorted for stable output.
  # Used by the HiveMind agent to know who is online.
  def online_players
    @online.keys.sort
  end

  # Snapshot of mirrored player attributes for the AI agent, with
  # online_time computed lazily against the current game tick:
  # [{name:, index:, connected:, admin:, online_time_ticks:}]
  def player_stats
    @attrs.snapshot(@game_tick)
  end

  # Pick the input-action SEGMENT-type mapping for the server's protocol
  # version. Explicit options[:protocol_version] (--protocol-version) wins;
  # else query RCON helpers.game_version once and cache in state (survives
  # hot reloads, which reset FactorioProtocol.segment_types to 2.1 default).
  def select_protocol_version
    version = @options[:protocol_version] || @state.protocol_version
    if version.nil? && @rcon
      version = @rcon.server_version
      @state.protocol_version = version if version
    end
    return unless version
    label = FactorioProtocol.select_version(version)
    puts "[protocol] factorio #{version} — action tables: #{label}"
  rescue => e
    warn "Protocol version detection failed: #{e.class}: #{e.message}"
  end

  # ── Interactive filter console (stdin) ──────────────────────────

  # Handle one line from the interactive filter console. Called by the
  # entry point's stdin thread; survives hot reloads (filters live in
  # state, the thread re-points at each new sniffer instance). Chat
  # (write_to_console) is always printed and exempt from these filters.
  def handle_command(line)
    parts = line.strip.split(/\s+/)
    return if parts.empty?
    case parts[0]
    when '/help', '/?'
      puts <<~HELP
        filter console (type a command, Enter):
          /players                     list online players
          /show NAME...                only show these players (* = clear)
          /show +NAME  /show -NAME     add / remove one player
          /hide NAME...                hide these players
          /hide +NAME  /hide -NAME
          /actions NAME...             only show these action types
          /noise NAME...               hide these action types
          /chat                        toggle chat-only mode (hide all non-chat)
          /quiet                       toggle quiet mode (noise actions)
          /filter                      show current filter state
          /stats                       print session stats
          /compact                     run Hivemind memory compaction now (manual)
          /forget | /clear             clear Hivemind's session (keeps long-term memories)
      HELP
    when '/players'
      puts "online (#{online_players.size}): #{online_players.join(', ')}"
    when '/filter'
      puts "show_players=#{@show_players.inspect} hide_players=#{@hide_players.inspect}"
      puts "show_actions=#{@show_actions.inspect} hide_actions=#{@hide_actions.inspect}"
      puts "chat_only=#{@chat_only} quiet=#{@quiet}"
    when '/show'  then modify_filter(:@show_players, parts[1..])
    when '/hide'  then modify_filter(:@hide_players, parts[1..])
    when '/actions' then modify_filter(:@show_actions, parts[1..])
    when '/noise' then modify_filter(:@hide_actions, parts[1..])
    when '/chat'
      @chat_only = !@chat_only
      puts "chat-only mode: #{@chat_only ? 'ON' : 'OFF'}"
    when '/quiet'
      @quiet = !@quiet
      puts "quiet mode: #{@quiet ? 'ON' : 'OFF'}"
    when '/stats'
      print_summary
    when '/compact'
      if @agent && @agent.memory_enabled?
        # Runs in a background thread so the console stays responsive (the
        # compaction LLM call takes seconds; it queues behind any live ask).
        Thread.new { @agent.compact_memory!('manual') }
        puts 'memory compaction started — see [hivemind] logs'
      else
        puts 'memory compaction unavailable (AI agent disabled or memory store off)'
      end
    when '/forget', '/clear'
      if @agent
        # Forgetting is explicit and fast — separate from compaction: the
        # session is wiped but SOUL/KNOWLEDGE/player memories are kept
        # (run /compact first to distill the session before you wipe it).
        @agent.clear_session!
        puts 'session cleared — Hivemind starts fresh (long-term memories preserved)'
      else
        puts 'no Hivemind agent (AI agent disabled) — nothing to clear'
      end
    else
      puts "unknown command #{parts[0]} — try /help"
    end
  rescue StandardError => e
    warn "filter console error: #{e.class}: #{e.message}"
  end

  # /show|/hide|/actions|/noise argument handling: replace mode (bare
  # names), +add / -remove modifiers, or * to clear. Filters are downcased.
  def modify_filter(iv, args)
    list = instance_variable_get(iv)
    if args.nil? || args.empty?
      puts "#{iv}: #{list.inspect}"
    elsif args == ['*']
      list = []
    elsif args.first.start_with?('+', '-')
      args.each do |a|
        name = a[1..].downcase
        a.start_with?('+') ? list = (list + [name]).uniq : list -= [name]
      end
    else
      list = args.map(&:downcase)
    end
    instance_variable_set(iv, list)
    puts "#{iv}: #{list.inspect}"
  end

  private

  # (everything below here is private as before)

  # One-shot seed of mirrored LuaPlayer attributes (connected/admin/
  # online_time) from RCON for ALL known players. After this, the packet
  # stream maintains them (PlayerAttrs). A failed/truncated query is
  # non-fatal — attrs are enrichment; the roster/stream keep working.
  def load_player_attrs
    return if @state.attrs_loaded
    @state.attrs_loaded = true
    return unless @rcon
    attrs = @rcon.player_attributes
    return if attrs.nil? || attrs.empty?
    attrs.each do |a|
      @attrs.seed(a[:name], index: a[:index], connected: a[:connected],
                   admin: a[:admin], online_time: a[:online_time],
                   afk_time: a[:afk_time])
      # Players already online per RCON are authoritative for @online too
      @online[a[:name]] ||= a[:index] if a[:connected]
    end
    ts = Time.now.strftime('%H:%M:%S.%L')
    admins = attrs.select { |a| a[:admin] }.map { |a| a[:name] }
    puts "#{ts}  [rcon]  player attrs seeded (#{attrs.size} players): " +
         (admins.empty? ? 'no admins' : "admins: #{admins.join(', ')}")
  rescue => e
    warn "Player attrs seed failed: #{e.class}: #{e.message}"
  end

  def print_summary
    puts "[summary] packets=#{@stats[:packets]} factorio=#{@stats[:factorio_packets]} actions=#{@stats[:actions]}"
    puts "[summary] packets not captured (keepalives/outgoing/transfer)=#{@stats[:capture_skipped]}" if @stats[:capture_skipped]&.positive?
    puts "[summary] outgoing broadcasts skipped (server mode)=#{@stats[:outgoing_skipped]}" if @options[:server]
  end

  # Clean-quit signal in server mode: called from the C→S PeerDisconnect
  # sync action (the client's final heartbeat — the observed quit path) and
  # from C→S msg 14 (RequestForHeartbeatWhenDisconnecting, kept as a
  # documented fallback). Resolve the player by src_ip — @conn_ip_name for
  # index-confirmed players, @conn_names for players who quit while still
  # downloading the map (never bound to an index) — and mark them offline.
  # Note: crashes and timeouts send neither — those leave stale @online
  # entries until a reload/restart (server mode has no S→C analysis).
  def handle_client_disconnect(src_ip, ts)
    name = @conn_ip_name.delete(src_ip) || @conn_names&.delete(src_ip)
    return unless name
    @online.delete(name)
    @attrs.disconnect(name, @game_tick)
    @agent&.on_player_event(:left, name)
    ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
    puts "#{ts_str}  #{name} left the game" if player_visible?(name)
  end

  # Reassemble a chat message split across input-action segments. The
  # segment metadata (total_segs/seg_no) marks split messages that arrive
  # in SEPARATE packets; fragments are buffered per (player, total_segs)
  # and merged in seg_no order when complete. Returns the merged payload,
  # or nil while the group is incomplete (skip printing/feeding until the
  # full message arrives). Buffers older than 15s are dropped (UDP loss
  # may strand a fragment).
  def chat_action_data(act, pname, ts)    total = act[:total_segs]
    data = act[:data]
    return data unless total && total > 1

    key = [pname, total]
    group = (@chat_segments[key] ||= {})
    group[:ts] = ts
    group[act[:seg_no]] = data

    @chat_segments.delete_if do |_k, g|
      g[:ts] && (ts - g[:ts]) > 15
    end

    return nil unless (0...total).all? { |n| group.key?(n) }
    merged = (0...total).map { |n| group[n] }.join
    @chat_segments.delete(key)
    merged
  end

  # ── Auto-named capture (--save-capture flag) ─────────────────────

  def new_pcap_writer(path)
    PcapWriter.new(path, gzip: @options[:save_capture_gz], keep: @options[:keep], max_size: @options[:max_size])
  end

  # Default captures/ directory (created on demand), relative to cwd.
  def default_capture_dir
    dir = File.join(Dir.pwd, 'captures')
    FileUtils.mkdir_p(dir) unless File.directory?(dir)
    dir
  end

  # <identity>-<timestamp>.pcap[.gz] — unique per run, never overwrites.
  def auto_capture_path(dir, id)
    ts = Time.now.strftime('%Y%m%d-%H%M%S')
    ext = @options[:save_capture_gz] ? '.pcap.gz' : '.pcap'
    File.join(dir, "#{id}-#{ts}#{ext}")
  end

  # Client mode: the server IP is unknown at startup — resolve it from the
  # first packet where one endpoint is the local client (--local-ip) and
  # the other is the server; fall back to plain "client" otherwise.
  def ensure_pcap_writer(src_ip, dst_ip)
    return unless @pending_capture
    local = @options[:local_ip]
    server_ip = if local && src_ip == local
      dst_ip
    elsif local && dst_ip == local
      src_ip
    end
    id = server_ip ? "client-#{server_ip}" : 'client'
    path = auto_capture_path(@pending_capture, id)
    @pcap_writer = new_pcap_writer(path)
    @pending_capture = nil
    puts "capturing to #{path}"
  end
end
