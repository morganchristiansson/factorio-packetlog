# frozen_string_literal: true

require 'time'
require_relative 'factorio_protocol'
require_relative 'item_db'
require_relative 'player_db'
require_relative 'pcap'
require_relative 'live_capture'
require_relative 'rcon_client'
require_relative 'hivemind'
require_relative 'player_attrs'

# Mutable session state carried across hot reloads. The entry point keeps
# one of these; on Ctrl-C it snapshots the running sniffer into it, reloads
# the code, and rebuilds a sniffer with the same state — so the capture
# file keeps its position, player names survive, and stats are continuous.
class SnifferState
  attr_accessor :player_db, :pcap_writer, :unknown_writer, :stats,
                :self_ip, :self_name, :self_index, :peer_names,
                :ip_names, :roster_loaded, :ai_agent, :attrs,
                :game_tick, :attrs_loaded, :protocol_version, :chat_segments,
                :show_players, :show_actions, :hide_actions,
                :debug, :timeout_watchdog
end

# ─────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────
class FactorioSniffer
  # Seconds without a C→S heartbeat before a player is considered gone
  # (server mode only). Clients heartbeat continuously (every 2 ticks at
  # 60 UPS ≈ 33ms), so this is a very conservative ceiling: a false
  # positive is essentially impossible, and a false negative just delays
  # the timeout. Deliberately NO knob — the cadence isn't fully documented
  # and slightly-high beats slightly-low (a late timeout just registers
  # late). Raised 30→60 after a verified false positive: a client whose
  # game link stayed healthy (no server-side drop countdown, still online
  # per RCON) showed 38–53s gaps in captured traffic (NAT/laggy path); the
  # old threshold fired mid-gap. Note the watchdog has no resurrection
  # path — touch() never revives a disconnected record — so a false
  # positive sticks until rejoin/restart; keep headroom generous.
  HEARTBEAT_TIMEOUT = 60.0

  def initialize(options, state = nil)
    @options = options
    @state = state || SnifferState.new
    @player_db = @state.player_db || PlayerDatabase.new(options[:player_db])
    @grief = nil
    @stats = @state.stats || { packets: 0, factorio_packets: 0, actions: 0, outgoing_skipped: 0, capture_skipped: 0 }
    # Capture is ALWAYS on for live capture (auto-named + rotated); pcap-read
    # analysis (-r) doesn't re-capture. Auto-naming uses a STABLE base
    # (captures/server-<port>.pcap) — the writer hangs exactly one rotation
    # timestamp off it, and a restart preserves the previous run via
    # PcapWriter#rotate_on_restart. Client mode defers until the first packet
    # reveals the server identity. The state's writer (hot reload) is reused.
    @pcap_writer = @state.pcap_writer
    @pending_capture = nil
    if !options[:pcap] && !@pcap_writer
      dir = default_capture_dir
      if options[:server]
        port = @options[:port]
        id = "server#{port ? "-#{port}" : ''}"
        @pcap_writer = new_pcap_writer(capture_path(dir, id))
        puts "capturing to #{@pcap_writer.path}#{retention_hint}"
      else
        @pending_capture = dir  # client: resolve the server identity on the first packet
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
    # The live roster + liveness live entirely in @attrs (PlayerAttrs):
    # "online" == record with :connected, whose :hb field drives the timeout
    # watchdog. One structure, one lock — no parallel copies to drift.
    @timeout_watchdog = @state.timeout_watchdog
    ensure_timeout_watchdog
    # src_ip → [name, confirmed]: every player seen connecting (msg 4
    # username), flipped to confirmed once their first C→S heartbeat action
    # binds a game index. Lets liveness touches and clean-quit signals
    # (C→S PeerDisconnect sync action / msg 14) resolve WHO without S→C
    # analysis. Survives hot reloads via state.
    @ip_names = @state.ip_names || {}
    # Cross-packet chat segment reassembly buffer: [player, total_segs] =>
    # {seg_no => payload}. Split chat messages arrive as separate
    # input-action segments across packets; merged when complete. Survives
    # hot reloads via state.
    @chat_segments = @state.chat_segments || {}
    # Mirrored LuaPlayer attributes (connected/admin/online_time): seeded
    # once from RCON, maintained by packet decoding. See PlayerAttrs.
    # Also owns the live roster (connected records) + liveness (:hb).
    @attrs = @state.attrs || PlayerAttrs.new
    # Latest game tick observed in heartbeat tick closures — the clock for
    # lazy online_time computation (60 ticks/s, tick is in every closure).
    @game_tick = @state.game_tick || 0
    # Interactive output filters (stdin console, /show /actions /noise /debug).
    # Survive hot reloads via state. Empty list = no restriction.
    @show_players = @state.show_players || []
    @show_actions = @state.show_actions || []
    @hide_actions = @state.hide_actions || []
    # Whether decoded per-action lines print. The runtime /debug toggle wins
    # over the --debug startup flag (state survives hot reloads). Default is
    # OFF — the normal operator output is chat + join/leave events + warnings.
    @debug = @state.debug.nil? ? !!@options[:debug] : @state.debug
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
      # heartbeat action below. (@ip_names, defined above for all modes.)
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
      # say "hivemind". Auto-enabled by the entry point (server mode +
      # HIVE_API_KEY); survives hot reloads (kept in SnifferState so the
      # LLM context and rate limiter carry over).
      @agent = @state.ai_agent
      # Re-point the agent's online-player source at THIS sniffer instance —
      # needed on every construction (fresh or hot-reloaded) since the agent
      # persists while the sniffer object is rebuilt.
      # NOTE: hot reload swaps CODE, not object shape — the agent keeps its
      # boot-time ivars. Changes that add/remove instance state need a full
      # restart; method/tool/prompt changes hot-reload fine.
      @agent.ensure_followup_scheduler if @agent
      @agent.online_provider = -> { online_players } if @agent
      @agent.player_stats_provider = -> { player_stats } if @agent
      if options[:ai_agent] && !@agent
        if @rcon
          @agent = HiveMindAgent.new(rcon: @rcon)
          @agent.online_provider = -> { online_players }
          @agent.player_stats_provider = -> { player_stats }
          unless @agent.disabled?
            puts "[hivemind] AI agent online — answering chat for \"#{HiveMindAgent::TRIGGERS.join(', ')}\" (model #{@agent.model})"
          end
        else
          warn '[hivemind] AI agent auto-enabled (server mode) but RCON is unavailable (--no-rcon?); agent disabled'
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
      puts 'Decoded per-action lines hidden — use /debug (or --debug) to show them (chat + events + warnings always print).' unless @debug
      if @options[:local_ip]
        puts "Filtering: showing only packets involving #{@options[:local_ip]}"
      end
      capturer.each_packet { |*args| process_packet(*args) }
    end
  end

  # Finalize the session: summary, persist player names, close writers.
  # Memory is NOT distilled here — compaction is manual only (`/compact`).
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
      st.ip_names = @ip_names
      st.chat_segments = @chat_segments
      st.roster_loaded = @state.roster_loaded
      st.ai_agent = @agent
      st.attrs = @attrs
      st.game_tick = @game_tick
      st.attrs_loaded = @state.attrs_loaded
      st.protocol_version = @state.protocol_version
      st.show_players = @show_players
      st.show_actions = @show_actions
      st.hide_actions = @hide_actions
      st.debug = @debug
      st.timeout_watchdog = @timeout_watchdog
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

    # Liveness: any incoming C→S packet proves the client is connected —
    # stamped BEFORE parse so even packets dropped from analysis/capture
    # (TransferBlocks, keepalives) keep the player alive.
    touch_heartbeat(src_ip) if @options[:server]

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
          @ip_names[src_ip] = [cc[:username], false]
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
        # Join = liveness proof (connect stamps hb); index bound once a
        # C→S heartbeat confirms it.
        @attrs.connect(sa[:username], @game_tick)
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

    # The SENDER's game index: in a C→S tick closure the first real action
    # carries the SENDER's game index (delta chain starts from 0xFFFF, so
    # the first delta IS the index+1). A heartbeat carrying input actions
    # IS the liveness proof — identify by index, not by src_ip.
    idx = nil
    if hdr[:msg_type] == 6 && hb[:tick_closures]&.any?
      hb[:tick_closures].each do |tc|
        real = tc[:actions]&.find { |a| a[:type] != 0 && a[:type] != 84 }
        if real
          idx = real[:player]
          break
        end
      end
    end

    # Liveness by NAME (server mode): stamp the roster record matching the
    # sender's game index. This reaches everyone the src_ip touch can't:
    # players seeded from the RCON roster (already in-game at startup —
    # they never send msg 4, so their IP was never learned) and NAT'd
    # clients sharing one source IP. Also learns the src_ip binding so
    # later keepalive-only heartbeats (no actions → no index) still touch
    # via touch_heartbeat(src_ip).
    touch_heartbeat_index(idx + 1, src_ip) if @options[:server] && idx

    # Bind usernames to game indexes from C→S heartbeat actions (joins:
    # msg 4 name + first real action's index → "confirmed as game player").
    if idx && hdr[:msg_type] == 6 && hb[:tick_closures]&.any?
      if @options[:server]
        # Server mode: learn EVERY client's name→index. msg 4 gave us
        # src_ip→name; the first real action in their C→S heartbeat gives
        # the game index. RCON /players is the authoritative cross-check.
        entry = @ip_names[src_ip]
        name = entry && !entry[1] ? entry[0] : nil  # unconfirmed only
        if name
          entry[1] = true  # confirmed — never re-fire the join event
          @player_db.add(idx + 1, name)
          @player_db.remove_other_entries_for(name, idx + 1)
          @attrs.set_index(name, idx + 1)  # confirming heartbeat = liveness proof
          # src_ip → name for connected players: lets the clean-quit
          # signals (C→S PeerDisconnect sync action, msg 14 fallback)
          # resolve the leaver on C→S alone. Server mode has no S→C
          # analysis (NewPeerInfo/PeerDisconnect broadcasts are dropped),
          # so joins are detected here and leaves via the final
          # heartbeat's PeerDisconnect sync action.
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
        @attrs.set_index(@self_name, idx + 1)
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
    # spam. Split messages are reassembled across packets
    # (chat_action_data) before decoding.
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
    # The decoded per-action line is the volume culprit with many players —
    # gated behind --debug. Everything important (chat, join/leave events,
    # and invalid/missing-decode warnings) prints regardless; this is only
    # the per-action dump, shown when inspecting decodes.
    return unless @debug
    puts "#{ts_str}  #{arrow} #{pname.ljust(16)} #{act[:name].ljust(28)}#{data_str}#{suffix}"
  end

  # ── Interactive filter console (stdin) ──────────────────────────

  # Visibility of an action line: player + action-type filters. Chat is
  # always exempt; join/leave events and decode warnings print outside this
  # path, so no filter ever hides them.
  def visible?(pname, act)
    name = pname.to_s.downcase
    return false if @show_players.any? && !@show_players.include?(name)
    return false if @hide_actions.include?(act[:name])
    return false if @show_actions.any? && !@show_actions.include?(act[:name])
    true
  end

  # Same player filtering for join/leave lines (no action criteria).
  def player_visible?(name)
    n = name.to_s.downcase
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
      # Authoritative live-roster seed (connected + index + fresh hb);
      # time accounting is player_attributes' job (load_player_attrs).
      @attrs.roster_online(p[:name], p[:index])
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
    @attrs.online_names
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
          /actions NAME...             only show these action types
          /noise NAME...               hide these action types
          /debug                       toggle decoded per-action lines
          /filter                      show current filter state
          /stats                       print session stats
          /compact                     distill session into memory, then start fresh
      HELP
    when '/players'
      puts "online (#{online_players.size}): #{online_players.join(', ')}"
    when '/filter'
      puts "show_players=#{@show_players.inspect}"
      puts "show_actions=#{@show_actions.inspect} hide_actions=#{@hide_actions.inspect}"
      puts "debug=#{@debug}"
    when '/show'  then modify_filter(:@show_players, parts[1..])
    when '/actions' then modify_filter(:@show_actions, parts[1..])
    when '/noise' then modify_filter(:@hide_actions, parts[1..])
    when '/debug'
      @debug = !@debug
      puts "decoded per-action lines: #{@debug ? 'SHOWN' : 'hidden'}"
    when '/stats'
      print_summary
    when '/compact'
      if @agent && @agent.memory_enabled?
        # Runs in a background thread so the console stays responsive (the
        # compaction LLM call takes seconds; it queues behind any live ask).
        # The session is wiped only after a SUCCESSFUL pass — if compaction
        # errors, compact_memory! logs it (warn → console) and returns
        # false, and the session is kept: a stuck/failed pass must never
        # silently wipe an un-distilled session. Both calls serialize on
        # the agent mutex.
        Thread.new do
          if @agent.compact_memory!('manual')
            @agent.clear_session!
          else
            puts 'memory compaction FAILED — session kept (see [hivemind] error above)'
          end
        end
        puts 'memory compaction started — session resets when done (see [hivemind] logs)'
      else
        puts 'memory compaction unavailable (AI agent disabled or memory store off) — session NOT cleared'
      end
    else
      puts "unknown command #{parts[0]} — try /help"
    end
  rescue StandardError => e
    warn "filter console error: #{e.class}: #{e.message}"
  end

  # /show|/actions|/noise argument handling: replace mode (bare names),
  # +add / -remove modifiers, or * to clear. Filters are downcased.
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
                   afk_time: a[:afk_time])  # connected seeds join the live roster
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
  # Resolve a leaver by src_ip and mark them offline. Called for clean
  # quits only — crashes/timeouts send nothing and are caught by the
  # heartbeat watchdog instead.
  def handle_client_disconnect(src_ip, ts)
    entry = @ip_names.delete(src_ip)
    name = entry && entry[0]
    return unless name
    @attrs.disconnect(name, @game_tick)
    @agent&.on_player_event(:left, name)
    ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
    puts "#{ts_str}  #{name} left the game" if player_visible?(name)
  end

  # Record liveness for a player: ANY incoming C→S packet — real-action or
  # keepalive heartbeat — proves the client is connected. Called for every
  # incoming packet BEFORE parsing, so even packets later dropped from
  # analysis/capture (e.g. TransferBlocks) keep a joiner alive mid-download.
  # Server mode only — client mode sees the server's own detection via the
  # S→C PeerDisconnect broadcast and needs no watchdog.
  def touch_heartbeat(src_ip)
    entry = @ip_names[src_ip]
    @attrs.touch(entry[0]) if entry
  end

  # Liveness by game index (server mode): a C→S heartbeat carrying input
  # actions names its sender by game index — no IP needed. Stamps EVERY
  # connected roster record with that index (exactly one in practice),
  # covering roster-seeded players (never sent msg 4 → no src_ip binding)
  # and NAT'd clients sharing one source IP. Also learns the src_ip binding
  # (first claim wins; NAT means it can't be exact) so later keepalive-only
  # heartbeats keep touching via touch_heartbeat(src_ip).
  def touch_heartbeat_index(game_index, src_ip)
    names = @attrs.touch_by_index(game_index)
    return if names.empty? || @ip_names.key?(src_ip)
    @ip_names[src_ip] = [names.first, true]  # index-bound ⇒ confirmed
  end

  # Watchdog tick: drop players whose heartbeats stopped (crashes/power
  # loss send nothing — clean quits announce via PeerDisconnect instead).
  # Scans every second, then re-verifies each candidate under attrs' lock so
  # a packet that arrived since the scan can't get a live player dropped.
  # Fires on_player_event(:timeout) — the console line makes the LLM aware
  # — and folds the session via attrs.disconnect. Client mode needs NO
  # watchdog: the server detects the drop itself and broadcasts
  # PeerDisconnect (S→C), which the normal leave path handles.
  def check_heartbeat_timeouts
    @attrs.stale_online(HEARTBEAT_TIMEOUT).each { |name, idle| timeout_player(name, idle) }
  end

  def timeout_player(name, idle)
    # Refreshed since the scan → still alive.
    return unless @attrs.still_stale?(name, HEARTBEAT_TIMEOUT)
    @attrs.disconnect(name, @game_tick)
    @agent&.on_player_event(:timeout, name)
    ts_str = Time.now.strftime('%H:%M:%S.%L')
    puts "#{ts_str}  #{name} timed out (no heartbeat for #{idle.round}s) — likely crashed or disconnected; may re-join" if player_visible?(name)
  end

  # One watchdog thread for the process: started on construction in live
  # SERVER mode; stored in state so a hot reload (threads keep running
  # across `load`) doesn't spawn a duplicate. The thread calls this object's
  # method, which after a reload resolves to the NEW class definition while
  # operating on the SAME shared state objects (@attrs records etc.).
  def ensure_timeout_watchdog
    return unless @options[:server] && @options[:interface] && !@options[:pcap]
    return if @timeout_watchdog&.alive?
    @timeout_watchdog = Thread.new do
      Thread.current.name = 'heartbeat-watchdog'
      loop do
        sleep 1.0
        check_heartbeat_timeouts
      rescue StandardError => e
        warn "#{Time.now.strftime('%H:%M:%S')}  heartbeat watchdog error: #{e.class}: #{e.message}"
      end
    end
    @state.timeout_watchdog = @timeout_watchdog
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

  # ── Always-on auto-named capture ────────────────────────────────

  def new_pcap_writer(path)
    PcapWriter.new(path, gzip: @options[:save_capture_gz], keep: @options[:keep], max_size: @options[:max_size])
  end

  # Default captures/ directory (created on demand), relative to cwd.
  def default_capture_dir
    dir = File.join(Dir.pwd, 'captures')
    FileUtils.mkdir_p(dir) unless File.directory?(dir)
    dir
  end

  # STABLE capture base path (no run timestamp): the writer appends exactly
  # one rotation timestamp when it rolls a file (server-<port>-<ts>.pcap),
  # and a restart appends one via rotate_on_restart. This keeps every
  # rotated file under the same stem, so pruning (--keep/--max-size) covers
  # ALL runs of this identity, not just the current one.
  def capture_path(dir, id)
    ext = @options[:save_capture_gz] ? '.pcap.gz' : '.pcap'
    File.join(dir, "#{id}#{ext}")
  end

  # Human hint about rotation for the capture startup line.
  def retention_hint
    if @options[:keep]
      " (rotating hourly, keep #{@options[:keep]}h)"
    elsif @options[:max_size]
      " (rotating at #{@options[:max_size]}MB)"
    else
      ' (rotating off — pass --keep HOURS / --max-size MB to bound disk)'
    end
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
    path = capture_path(@pending_capture, id)
    @pcap_writer = new_pcap_writer(path)
    @pending_capture = nil
    puts "capturing to #{path}#{retention_hint}"
  end
end
