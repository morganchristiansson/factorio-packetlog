# frozen_string_literal: true

require 'time'
require_relative 'factorio_protocol'
require_relative 'item_db'
require_relative 'player_db'
require_relative 'pcap'
require_relative 'live_capture'
require_relative 'rcon_client'
require_relative 'log_tail'
require_relative 'plugins'
require_relative 'server_detect'
require_relative 'player_attrs'

# Hot reload (Ctrl-C / SIGHUP): the RUNNING instance reloads its own code
# IN PLACE — no rebuild, no state snapshot, no capture reopen. `load`
# reopens the class definitions; this object keeps every ivar (and the
# open capture handle), so new code applies on the next dispatch with
# zero packet loss. A second interrupt within QUIT_WINDOW quits.

# ─────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────
class FactorioPacketTools
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
  HEARTBEAT_TIMEOUT = 20.0

  # Lib files reloaded on Ctrl-C/SIGHUP (relative to lib/). `load` re-reads
  # each file (redefining classes); `require` would only load once.
  # Constant-redefinition warnings are expected and silenced during load.
  # Optional features (hivemind, translation) are NOT listed: their files
  # come from Plugins.files (plus the agent's own plugin files), so a
  # feature that is switched off is never read back in.
  RELOADABLE_LIBS = %w[
    factorio_protocol item_db player_db pcap live_capture rcon_client log_tail agent_events memory_store player_attrs input_actions_20 factorio_packet_tools
    factorio_protocol/packets/factorio_packet
    factorio_protocol/packets/heartbeat_packet
    factorio_protocol/packets/connection_packets
  ].freeze

  # Seconds between two Ctrl-C/SIGHUP presses that count as "quit".
  # Monotonic time, so wall-clock changes (NTP, manual) don't matter.
  QUIT_WINDOW = 5

  # How far past the known roster a player index may sit before it counts as
  # a desync rather than a player we have no name for. The DISTANCE decides,
  # not membership: on the 2026-10-03 set, 10,036 packets were flagged for
  # index 357 and 736 for 360 — both real players (both chatting under their
  # Player_N placeholders), just past the last index this cache names. That
  # made `packets with a suspected desync` a false-positive machine (11 196
  # of 11 265 flags) and buried the corpus under 1.4 MB of nothing. A real
  # desync throws the index thousands of places away (33024, 53354).
  UNKNOWN_PLAYER_WINDOW = 100

  # Always-on capture rotation defaults (hardcoded — config.yaml can
  # override). Without ANY bound the active capture grows forever (observed:
  # a 511 MB server-34197.pcap plus 2.9 GB of never-pruned restarts) and
  # rotation only happened on restart. Three independent bounds, three
  # knobs: rotate hourly or at `rotate_size`, keep for `keep` hours, and
  # keep the rotated files under `max_size` MB in total.
  DEFAULT_KEEP_HOURS = 72
  DEFAULT_ROTATE_SIZE_MB = 256
  DEFAULT_MAX_SIZE_MB = 512

  def initialize(options, pcap_writer: nil, unknown_pcap_writer: nil)
    # What lands in the pcap is ONE axis (was two half-overlapping flags):
    #   normal — filtered (drop keepalive-only heartbeats, server-mode
    #            outgoing broadcasts, msg 13 map-download blocks)
    #   full   — record everything
    #   save   — record ONLY the msg 13 TransferBlocks, for
    #            tools/extract_save_from_pcap.rb
    @capture_mode = (options[:capture] || 'normal').to_s
    raise ArgumentError, "capture: #{@capture_mode.inspect} (normal, full, save)" unless
      %w[normal full save].include?(@capture_mode)
    @options = options
    @player_db = PlayerDatabase.new(options[:player_db])
    @stats = { packets: 0, factorio_packets: 0, actions: 0, outgoing_skipped: 0, capture_skipped: 0,
               bad_string: 0, unknown: 0, desync: 0, decode_error: 0 }
    @unknown_names = {} # undecoded action type -> how often we saw it
    # Capture is ALWAYS on for live capture (auto-named + rotated); pcap-read
    # analysis (-r) doesn't re-capture. Auto-naming writes timestamped files
    # directly (captures/server-<port>-<ts>.pcap) — the latest file IS the
    # live one, no renames, no stable path. Restarts just open a new file.
    # Client mode defers until the first packet reveals the server identity.
    # Tests inject a fake writer via the pcap_writer: kwarg (dependency
    # injection, not config).
    @pcap_writer = pcap_writer
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
    # Protocol-development capture is always on. Keep this separate from the
    # normal rolling capture so decoder failures can be replayed later.
    unknown_path = File.join(default_capture_dir, 'unknown.packets.pcap')
    # Tests inject a fake here too (same kwarg pattern as pcap_writer):
    # a real writer means one empty unknown.packets-<ts>.pcap per test run,
    # dropped in the repo's captures/ and never closed.
    @unknown_writer = unknown_pcap_writer ||
                      PcapWriter.new(unknown_path, keep: effective_keep,
                                     rotate_size: effective_rotate_size, max_size: effective_max_size,
                                     timestamped: true)
    puts "saving unknown packets to #{@unknown_writer.path}"
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
    @self_ip = nil
    @self_name = nil
    # peer_id (network) -> name, for join/leave events (peer ids are NOT
    # game indexes; game indexes come from heartbeat actions instead).
    @peer_names = {}
    # The live roster + liveness live entirely in @attrs (PlayerAttrs):
    # "online" == record with :connected, whose :hb field drives the timeout
    # watchdog. One structure, one lock — no parallel copies to drift.
    @last_timeout_check = 0.0
    # src_ip → [name, confirmed]: every player seen connecting (msg 4
    # username), flipped to confirmed once their first C→S heartbeat action
    # binds a game index. Lets liveness touches and clean-quit signals
    # (C→S PeerDisconnect sync action / msg 14) resolve WHO without S→C
    # analysis. Survives hot reloads via state.
    @ip_names = {}
    # Cross-packet chat segment reassembly buffer: [player, total_segs] =>
    # {seg_no => payload}. Split chat messages arrive as separate
    # input-action segments across packets; merged when complete.
    @chat_segments = {}
    # Mirrored LuaPlayer attributes (connected/online_time/afk_time):
    # seeded once from RCON, maintained by packet decoding.
    # Admin status lives in PlayerDatabase (players-cache.json). See PlayerAttrs.
    # Also owns the live roster (connected records) + liveness (:hb).
    @attrs = PlayerAttrs.new
    # Latest game tick observed in heartbeat tick closures — the clock for
    # lazy online_time computation (60 ticks/s, tick is in every closure).
    @game_tick = 0
    # Interactive output filters (stdin console, /show /actions /noise /debug).
    # Empty list = no restriction.
    @show_players = []
    @show_actions = []
    @hide_actions = []
    # Whether decoded per-action lines print. The runtime /debug toggle wins
    # over the --debug startup flag. Default is OFF — the normal operator
    # output is chat + join/leave events + warnings.
    @debug = !!@options[:debug]
    # Features (config.yaml `plugins:`): one Plugins object for this owner,
    # which builds them from the list and dispatches what we emit below.
    # This file names none of them. hivemind and translation are objects
    # this host drives, not features it emits to. MODE-INDEPENDENT and
    # outside any mode block: the packet path emits on_player_color in
    # every mode (pcap replay included), so @plugins must always exist.
    # Every listed name is a feature: PluginSet builds it lazily on the
    # first event/access. Hivemind's sniffer-specific bits — its live tick
    # provider and the sniffer's own plugin list (for the tool gate) — are
    # handed down as the feature's constructor kwargs via the args: slot.
    listed = Array(options[:plugins]).map { |n| n.to_s.to_sym }
    @plugins = Plugins::PluginSet.new(listed, self, args: {hivemind: {current_tick: -> { @game_tick }, sniffer_plugins: options[:plugins]}})
    # Server mode: this host IS the game server. Classify packet direction
    # by comparing src/dst against our own IPs and analyze ONLY incoming
    # (client→server) traffic — the outgoing direction is a broadcast of
    # every action to all N clients (N duplicates per action).
    if options[:server]
      # This host's IPs: the configured `ip:` (the entry point normalizes
      # it into :host_ips) or the auto-detected list; else all local IPv4s.
      @host_ips = (options[:host_ips] || []).dup
      @host_ips = ServerDetect.local_ipv4 if @host_ips.empty?
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
            f = File.join(@rcon.script_output_dir, 'factorio-packettools-items.txt')
            if File.exist?(f) && File.size(f) > 0
              @item_db = ItemDB.new(f)
              puts "Item DB populated from RCON: #{@item_db.size} items"
            end
          end
          unless @entity_db
            f = File.join(@rcon.script_output_dir, 'factorio-packettools-entities.txt')
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
      # helpers.game_version (cached on @protocol_version — an ivar, so it
      # survives hot reloads with the instance). Main action types are
      # version-stable and need no switch — only segments follow
      # defines.input_action.
      # Optional features: plugin FEATURES in @plugins (built lazily by
      # PluginSet), so hot reload swaps the CODE under the same objects and
      # there are no feature ivars to carry over or re-point.
      # Hivemind AI agent: reads packet-decoded chat and answers players who
      # say "hivemind". Needs the `hivemind` plugin (config.yaml `plugins:`)
      # AND server mode with RCON plus a key for its startup model — the
      # constructor enforces those (missing → "[plugin] hivemind disabled"
      # warn; nothing builds), like any feature. Context comes from the
      # packet-derived @attrs cache (seeded from RCON at startup, maintained
      # by packets); online players and stats are cached. Player admin is
      # stored in PlayerDatabase (players-cache.json); targeted RCON attrs
      # lookups happen once for newly joined players only.
      if @plugins.enabled?(:hivemind) && @rcon
        hivemind = @plugins[:hivemind]
        if hivemind
          hivemind.plugins[:followups]&.ensure_followup_scheduler
          hivemind.plugins[:logwatcher]&.ensure_log_watcher(ServerDetect.log_path)
          puts "[hivemind] AI agent online — answering chat for \"#{hivemind.triggers.join(', ')}\" (model #{hivemind.model})"
        end
      end

      # Translation agent: auto-translates chat for foreign players. Needs
      # the `translation` plugin; no API key required.
      # Backend and Google API key come from config-translation.yaml
      # (`google_api_key:`) with the env overriding it.
      if @plugins.enabled?(:translation) && @rcon
        if (t = @plugins[:translation])
          backend = t&.backend
          if [:hybrid, :google].include?(backend) && t&.google_api_key?
            puts "[translate] Translation agent online — auto-translating foreign player chat (hybrid: argos + google cloud fallback)"
          else
            puts "[translate] Translation agent online — auto-translating foreign player chat (#{backend} backend)"
          end
        end
      end

      # Discord: relays chat between a Factorio channel and a Discord
      # channel, and lets Discord users address the Hivemind agent. Needs the
      # `discord` plugin + RCON (to post in-game) + DISCORD_TOKEN
      # (env-first) + channel_id from config-discord.yaml. Built as a plugin
      # feature by PluginSet (Discord.new(owner)) — it owns a live gateway
      # thread and reaches the agent through the shared publish_chat relay.
      if @plugins.enabled?(:discord) && @rcon
        begin
          discord = @plugins[:discord]
          # forward_chat runs off the capture thread via the bridge's worker
          # (AgentEvents#enqueue); the agent publishes :hivemind replies through
          # the shared publish_chat relay instead of a reply_callback.
          puts "[discord] online — relaying chat with Discord channel #{discord.channel_id}" if discord
        rescue => e
          warn "[discord] disabled: #{e.message}"
        end
      end
    end


    # Version → segment-type mapping (server mode may also query RCON here;
    # the RCON client is only created in server mode). Runs on every
    # construction, including hot reloads.
    select_protocol_version
  end

  # What a feature gets as its owner: this host, and these are the shared
  # things most features want. Nil is a real answer — no RCON in client mode.
  # `attrs` is the live PlayerAttrs mirror (roster + play time): a feature
  # that keeps a name-keyed base it adds to the totals (player_backup) reads
  # it through set_foreign_bases.
  attr_reader :rcon, :player_db, :attrs

  # THE EVENT CATALOGUE — what the sniffer tells features, and the whole
  # plugin API. Every event is a no-op on Plugins::Feature, so it is emitted
  # unconditionally and a feature implements only the ones it uses: adding a
  # feature never means editing this file, only adding an EVENT does (a
  # no-op on Plugins::Feature plus the emitter here).
  #
  # A player joined and the ONE targeted RCON query for them came back: their
  # name, their bound game index, and attrs (index, name, connected, admin,
  # online_time, afk_time, locale, plus on the join query the whole quickbar:
  # the 10×10 grid, nil for an empty bar, :failed if the Lua read raised).
  # Emitted on the join thread, so a feature may talk to the server here.
  def on_join_enriched(name, index, attrs)
    @plugins.emit(:on_join_enriched, name, index, attrs)
  end

  # A player left the game — clean quit (the C→S PeerDisconnect, or the
  # S→C broadcast in client mode) or the heartbeat watchdog. Their play time
  # for THIS save, already folded into PlayerAttrs: the last moment the
  # player_backup feature can record what the current save is worth before a
  # new one starts on top of it.
  def on_player_left(name, online_time_ticks)
    @plugins.emit(:on_player_left, name, online_time_ticks)
  end

  # A player changed their colour: the 4 UNORM bytes R,G,B,A (0..255) from the
  # set_player_color action (2.0 wire 296, 2.1 311), as [r,g,b,a] 0..1. On the
  # packet thread, and only while the value actually CHANGES — the colour
  # picker sends ~25 samples/second while it is open, so an unchanged colour
  # must not reach the files.
  def on_player_color(name, rgba)
    @plugins.emit(:on_player_color, name, rgba)
  end

  # Chat relay hub: the single chat event every chat feature is reached by.
  # publish_chat fans :on_chat to the plugin features — discord, translation
  # and hivemind — all sync-light on_chat that enqueue their blocking work to
  # their OWN workers (emit itself runs on the capture thread). Sources:
  # :factorio (player chat, from log_action), :discord, :hivemind (an agent
  # reply). Each feature self-skips its own source: discord skips :discord;
  # translation translates :factorio in-game chat only (Discord text and
  # Hivemind replies are never re-translated); hivemind skips :hivemind (its
  # replies
  # are already in its conversation context). player_id is the packet's
  # 1-indexed game index (nil for non-Factorio sources): translation needs it
  # for its index-keyed relay, discord and the agent ignore it.
  def publish_chat(source, author, text, player_id: nil)
    @plugins.emit(:on_chat, source, author, text, player_id)
    nil
  end

  # Startup, once the RCON client exists (server mode only): the whole-roster
  # dump — every player the save knows, offline included, with colour and the
  # entire quickbar, in one helpers.write_file query (RconClient#roster_backup).
  # Features that keep per-player state they want for players who joined
  # BEFORE we started (the player_backup plugin's snapshot) seed from this;
  # a join can only ever tell a feature about players who come after.
  def on_start
    @plugins.emit(:on_start)
  end

  # Run the capture/analysis loop. Blocks until the source is exhausted
  # (pcap) or Interrupt is raised (live capture). Does NOT finalize — the
  # entry point calls #finish when actually shutting down, so a hot reload
  # can keep the capture file and state alive.
  def run
    if @options[:server] && @host_ips.empty?
      puts 'Error: server mode could not determine the server IP.'
      puts '  Set `ip: <ip>` in config.yaml to set it explicitly.'
      exit 1
    end

    if @options[:server]
      puts 'SERVER MODE: analyzing only incoming (client→server) packets — no broadcast duplicates'
      puts "  server IP(s): #{@host_ips.join(', ')}"
      puts '  map-download TransferBlocks (save file) excluded from analysis and capture'
      if @pcap_writer && @capture_mode == 'normal'
        puts '  capture: incoming-only + no keepalive-only heartbeats (~20MB per 5h vs ~460MB; `capture: full` records everything)'
      end
    elsif @pcap_writer && @capture_mode == 'normal'
      puts '  capture: TransferBlocks (msg 13) and keepalive-only heartbeats excluded (`capture: full` records everything)'
    end

    # Client mode has no RCON and only sees players who join from now on, so
    # the map download is the only source for the players already in the game.
    if map_download_hook
      puts '  roster: seeded from the map download when we join (the only way to learn the players already here)'
    end

    if @options[:pcap]
      read_pcaps
    elsif @options[:interface]
      # Seed the roster before capturing so existing players' names are
      # known from the start (RCON is authoritative; later joiners are
      # learned from the packet stream). Runs again after every in-place
      # reload — see load_roster for why that re-seed matters.
      load_roster if @rcon
      load_player_attrs if @rcon
      on_start if @rcon
      # Memoized: a reload must NOT reopen the capture device. Reusing this
      # handle across reloads is what makes them lossless (and avoids two
      # BPF listeners duplicating every packet).
      @capturer ||= LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
        transfer_block_sink: (@capture_mode == 'normal' ? nil : @pcap_writer),
        transfer_block_hook: map_download_hook,
      )
      puts "Listening on #{@options[:interface]} port #{@options[:port]}..."
      puts 'Press Ctrl+C to reload code; Ctrl+C again to quit.'
      puts 'Decoded per-action lines hidden — use /debug (or --debug) to show them (chat + events + warnings always print).' unless @debug
      if (ips = @options[:host_ips].to_a).any?
        puts ips.size > 1 ? "Filtering: #{@options[:server] ? 'to' : 'from'} #{ips.join(', ')}" : "Filtering: #{@options[:server] ? 'to' : 'from'} #{ips.first}"
      end
      @capturer.each_packet { |*args| process_packet(*args) }
    end
  rescue Interrupt
    handle_interrupt!
    retry
  end

  # Finalize the session: summary and close writers.
  # Memory is NOT distilled here — compaction is manual only (`/compact`).
  def finish
    @map_download&.stop
    @plugins[:hivemind]&.close_events
    @plugins[:translation]&.close_events
    @plugins[:discord]&.close
    print_summary
    @pcap_writer&.close
    @unknown_writer&.close
  end

  # Ctrl-C / SIGHUP inside #run: FIRST press reloads all sniffer libs IN
  # PLACE and resumes (same objects, same open capture handle — zero packet
  # loss); a second press within QUIT_WINDOW re-raises so the entry point
  # finalizes and quits. Later presses are fresh reloads again.
  def handle_interrupt!
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    # Bare `raise` would re-raise $! (works inside the live Ctrl-C rescue, but
    # raises RuntimeError when called directly — e.g. the double-tap spec).
    raise Interrupt if @last_interrupt && (now - @last_interrupt) <= QUIT_WINDOW
    @last_interrupt = now
    reload_code!
  end

  # Reload the sniffer libs without rebuilding anything: `load` REOPENS
  # each class definition, so this running instance keeps every ivar (and
  # the capture handle) while its methods become the new code — dispatch
  # goes through the class at call time. After loading, revive whatever
  # depends on post-load state: the protocol-version mapping (reload resets
  # FactorioProtocol's segment tables to their 2.1 defaults) and the
  # agent's follow-up scheduler thread (may have died under old code).
  def reload_code!
    puts "\nInterrupt — reloading code in place; session preserved."
    puts "  Press Ctrl+C (or SIGHUP) again within #{QUIT_WINDOW} seconds to quit."
    old_verbose = $VERBOSE
    $VERBOSE = nil
    begin
      root = File.expand_path('..', __dir__)
      reload_files.each { |lib| load lib.start_with?('/') ? lib : File.expand_path("lib/#{lib}.rb", root) }
    ensure
      $VERBOSE = old_verbose
    end
    select_protocol_version
    hivemind = @plugins[:hivemind]
    hivemind&.plugins&.[](:followups)&.ensure_followup_scheduler
    hivemind&.plugins&.[](:logwatcher)&.ensure_log_watcher(ServerDetect.log_path)
    # Hot reload swaps code under the same hivemind object; re-point
    # the cached attrs/tick provider in case this is the first
    # reload after the agent was constructed (or libs changed
    # the ivar shape).
    hivemind&.attrs = @attrs
    hivemind&.current_tick = -> { @game_tick }
    hivemind.player_db = @player_db if hivemind
    # Agent event queues/workers persist on the same objects across reloads.
  end

  private

  # Every lib file a reload re-reads: the core list, the loaded features'
  # files, and the loaded hivemind plugins' files. Absolute paths come from
  # Plugins (a feature may live outside lib/), bare names are lib/ files.
  def reload_files
    (RELOADABLE_LIBS + @plugins.files + [@plugins[:hivemind]].compact.flat_map(&:plugin_files)).uniq
  end

  # Whether to persist this packet to the capture file. `capture: full`
  # keeps everything, `capture: save` only the TransferBlocks; the
  # default drops (a) keepalive-only heartbeats (no input
  # actions / sync actions / heartbeat requests — ~40% of packets in a
  # typical session) and (b) in server mode, outgoing (server→client)
  # broadcasts: analysis only reads incoming packets, so the outgoing
  # direction is N duplicates of the same data (~47% of a server capture).
  def capture_recordable?(src_ip, dst_ip, udp_data)
    return @capture_mode != 'save' unless @capture_mode == 'normal'
    if @options[:server]
      return false unless @host_ips.include?(dst_ip)
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

    # Protocol version from the connection request a client sends when it
    # joins (msg 2 carries it). Nothing announces 2.0, so the tables already
    # default to 2.0 — this exists to notice a server that says otherwise
    # (an experimental 2.1 build), and to reject a capture from a version
    # whose numbering the tables cannot serve.
    detect_protocol_version(udp_data) if (udp_data.getbyte(0) & 0x1F) == 2 && @protocol_version.nil?

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
    # pointless disk usage from N copies of the same save. `capture: full`
    # / `save` keep them (falls through to the msg-13 gate below, which
    # writes).
    if @options[:server] && (udp_data.getbyte(0) & 0x1F) == 13 && @capture_mode == 'normal'
      @stats[:capture_skipped] += 1 if @pcap_writer
      return
    end

    # TransferBlock (msg 13) packets carry raw save data — never analyzed,
    # and at ~20k pps the per-packet parse cost is what overflowed the
    # capture buffer before. Record them only when explicitly requested
    # (--save-transfer-blocks / --full-capture); the default is to drop them:
    # they contain no player actions and added ~12% to a 4.9M-packet capture.
    if (udp_data.getbyte(0) & 0x1F) == 13
      if @pcap_writer && @capture_mode != 'normal'
        @pcap_writer.write_frame(raw_frame, Time.at(ts))
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
        @pcap_writer.write_frame(raw_frame, Time.at(ts))
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
      unless @host_ips.include?(dst_ip)
        @stats[:outgoing_skipped] += 1
        return
      end
    elsif (client_ips = @options[:host_ips].to_a).any?
      # Client mode: only packets FROM our game (the `ip:` setting).
      return unless client_ips.include?(src_ip)
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
        @player_db[pid] = {name: p[:name], locale: nil}
        puts "#{ts_str}  [server]  online peer #{p[:peer_id]} -> #{p[:name]} (candidate index #{pid})"
      end
    end

    # A message whose STRING field would not decode is a misdecode (the
    # length ran past the buffer, or the bytes are not valid UTF-8 — FactorioWire
    # returns nil instead of scrubbing a different name). Keep the frame: a
    # scrubbed name would silently become another player.
    if raw_frame && string_decode_failed?(parsed)
      @stats[:bad_string] += 1
      @unknown_writer&.write_frame(raw_frame, Time.at(ts))
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
        @player_db[pid] = {name: sa[:username], locale: nil}
        # Join = liveness proof (connect stamps hb); index bound once a
        # C→S heartbeat confirms it.
        @attrs.connect(sa[:username], @game_tick)
        ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
        # Don't print our own join as "joined the game" (we know we connected)
        unless @self_name == sa[:username]
          @plugins.emit(:on_player_event, :joined, sa[:username])
          puts "#{ts_str}  #{sa[:username]} joined the game (peer #{sa[:peer_id]}, index #{pid})" if player_visible?(sa[:username])
        end
      end
      if sa[:name] == 'PeerDisconnect'
        if sa[:peer_id]
          # S→C broadcast form (client mode): names the departed peer.
          pname = @peer_names[sa[:peer_id]] || @player_db.lookup(sa[:peer_id] + 1)
          @attrs.disconnect(pname, @game_tick) if pname
          @plugins.emit(:on_player_event, :left, pname) if pname
          @plugins.emit(:on_player_left, pname, @attrs.online_time_ticks(pname, nil)) if pname
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
          idx = real[:game_player]
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
    touch_heartbeat_index(idx, src_ip) if @options[:server] && idx

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
          @player_db[idx] = {name: name, locale: nil}
          @player_db.remove_other_entries_for(name, idx)
          @attrs.set_index(name, idx)  # confirming heartbeat = liveness proof
          # src_ip → name for connected players: lets the clean-quit
          # signals (C→S PeerDisconnect sync action, msg 14 fallback)
          # resolve the leaver on C→S alone. Server mode has no S→C
          # analysis (NewPeerInfo/PeerDisconnect broadcasts are dropped),
          # so joins are detected here and leaves via the final
          # heartbeat's PeerDisconnect sync action.
          @plugins.emit(:on_player_event, :joined, name)
          # One targeted RCON query for everything only the server knows
          # about a joiner: their locale and their whole quickbar (the C→S
          # actions report it as deltas, so a join is the one moment the
          # bar is knowable). Rare event, off the capture thread.
          enrich_joined_player(name, idx)
          ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
          puts "#{ts_str}  #{name} confirmed as game player ##{idx}"
        end
      elsif @self_name && src_ip == @self_ip
        # ONCE per binding: this block runs for every heartbeat that carries
        # an action, and re-stating the same index wrote the whole cache
        # (and printed the line) thousands of times in a 5h capture. The
        # attrs index is (re)stated either way — it is in-memory and needed
        # for the session's own stats.
        @attrs.set_index(@self_name, idx)
        if @player_db.id_for(@self_name) != idx
          @player_db[idx] = {name: @self_name, locale: nil}
          # Peer-id-based guess (peer_id+1) may differ for returning players;
          # remove any other slot claiming our name.
          @player_db.remove_other_entries_for(@self_name, idx)
          ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
          puts "#{ts_str}  [self]  #{@self_name} confirmed as game player ##{idx}"
        end
      end
    end

    # tick closures → player actions
    # Ghost flag is in bit 0 of next_receive timeshift
    @ghost_mode = hb[:next_receive] ? (hb[:next_receive] & 1) == 1 : false
    
    # Keep protocol-development packets that expose a decoder failure. Besides
    # hit_unknown, an action attributed to a player far outside the
    # authoritative roster is evidence that an earlier action length
    # desynchronized the stream.
    #
    known_players = @player_db.players.keys
    known_players.concat(@attrs.roster_pairs.map { |p| p[:index] })
    roster_ceiling = known_players.max.to_i + UNKNOWN_PLAYER_WINDOW
    invalid_players = if known_players.empty?
                        []
                      else
                        hb[:tick_closures]&.filter_map do |tc|
                          tc[:actions]&.map { |a| a[:game_player] }&.uniq
                        end&.flatten&.reject { |pid| known_players.include?(pid) || pid <= roster_ceiling } || []
                      end
    @desync_before = @stats[:desync]
    if hb[:hit_unknown] || invalid_players.any?
      # A desync: an action type with no length (or one before it desynced),
      # so the rest of this packet's actions were misread. Counted for the
      # summary — `undecoded actions` is the decoder's to-do list, this is the
      # damage it did.
      @stats[:desync] += 1
      last_act = hb[:tick_closures]&.filter_map { |tc| tc[:actions]&.last }&.last
      if @options[:validate] && hb[:hit_unknown] && last_act
        warn "[WARN] type #{last_act[:type]}(#{last_act[:name]}) triggered hit_unknown — previous action may have wrong data length"
      end
    end

    # Keep a frame when anything about this packet is undecoded or misread:
    # a suspected desync (above), an action type we have no name/layout for,
    # or a quickbar action whose payload implies a desync. One frame per
    # packet, no matter how many actions in it are affected.
    keep_frame = false
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each do |act|
        @stats[:actions] += 1
        # Decoder coverage: an action type we have no name/layout for. Counted
        # always (it is the answer to "what is still undecoded?"), not only
        # under --validate. The packet is kept too: an Unknown action in the
        # main list carries its MEASURED length, so the rest of the packet
        # still parses and hit_unknown never fires — without this the frame
        # holding the action we cannot decode was thrown away.
        if act[:name].to_s.start_with?('Unknown')
          @stats[:unknown] += 1
          @unknown_names[act[:name]] = @unknown_names.fetch(act[:name], 0) + 1
          keep_frame = true
        end
        # NOT `keep_frame ||= track_quickbar(act)`: that would short-circuit
        # and skip the tracking itself on every action after the first hit.
        keep_frame = true if track_quickbar(act)
        log_action(ts, act, hdr[:msg_type] == 7, ghost: @ghost_mode, raw_frame: raw_frame)
      end
    end
    keep_frame ||= @stats[:desync] > @desync_before
    @unknown_writer&.write_frame(raw_frame, Time.at(ts)) if keep_frame && raw_frame
  rescue StandardError => e
    # ONE malformed packet costs ONE packet. The decoder reads lengths off
    # the wire and trusts them, so a length can point past the end of a
    # payload; the frame goes to unknown.packets-*.pcap (the same file the
    # hit_unknown / bad-string paths use) and the run continues. Without
    # this the exception escaped process_packet, escaped the pcap reader,
    # and ended the rest of the capture file ("stopped reading this file") —
    # on one 22MB capture that silently cost 36k packets and 43k actions.
    @stats[:decode_error] += 1
    @unknown_writer&.write_frame(raw_frame, Time.at(ts))
    warn_decode_error(e)
  ensure
    # Check AFTER this packet refreshes liveness, including sender-index binding.
    check_timeouts_if_due
  end

  # Report a decode crash without flooding the console: the first few name
  # the error, then every 1000th. The frames themselves are all in
  # unknown.packets-*.pcap; the count is in the summary line.
  DECODE_ERROR_REPORT_EVERY = 1000
  def warn_decode_error(e)
    n = @stats[:decode_error]
    return unless n <= 5 || (n % DECODE_ERROR_REPORT_EVERY).zero?
    warn "[decode] packet #{@stats[:packets]} raised #{e.class}: #{e.message} " \
         "(#{n} so far, frame saved to unknown.packets)"
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
        dname = FactorioTypes::DIR_NAMES[dir] || dir
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
    when "quick_bar_set_slot", "quick_bar_pick_slot",
         "quick_bar_set_selected_page", "change_active_quick_bar"
      qb = FactorioProtocol::QuickBar.decode(act)
      return " #{quickbar_str(qb)}" if qb.is_a?(Hash)
    when "copy"
      return " flags=#{d.unpack1('v')}" if d.bytesize >= 2
    when "cheat"
      return ''
    end

    return '' unless @options[:dump_raw_types]
    hex = d.bytes.first(8).map { |b| '%02x' % b }.join
    " [#{hex}#{d.bytesize > 8 ? '..' : ''}]"
  end

  # Quickbar slot/page state from the quickbar input actions, kept in
  # players-cache.json (PlayerDatabase#set_quickbar_slot / _page). A
  # set_slot names the item and the slot but NOT the page, so the page the
  # slot lands on is the one the player last switched to.
  #
  # Returns TRUE when the action could not be decoded, or named a page/slot
  # outside the quickbar. Both mean an EARLIER action's length desynced the
  # closure — the quickbar action is merely the first to show it — and the
  # caller forwards the frame to the unknown-packet writer, which is the
  # corpus for fixing that length. The generic flag (hit_unknown / unknown
  # player) misses those: the closure parsed to the end, just wrongly.
  # Measured over captures/server-*.pcap: 355 frames, 104 of which the
  # generic flag never sees (35080 packets of 496953).
  def track_quickbar(act)
    qb = FactorioProtocol::QuickBar.decode(act)
    return true if qb == :undecodable # a quickbar payload we cannot read
    return false unless qb            # not a quickbar action
    if qb.key?(:page)
      !@player_db.set_quickbar_page(act[:game_player], qb[:page])
    elsif act[:name] == 'quick_bar_set_slot'
      # op 1 = clear the slot (drop its filter)
      item = qb[:op] == 0 ? qb[:item] : nil
      !@player_db.set_quickbar_slot(act[:game_player], @player_db.quickbar_page(act[:game_player]),
                                    qb[:slot], item)
    else
      false # pick_slot: the selection, no state to keep and nothing to check
    end
  end

  # Ask the server about a joiner: ONE targeted RCON query
  # (RconClient#player_attributes_for) carrying their attrs AND their whole
  # quickbar, on its own thread — joins are minutes apart and a blocked
  # capture thread would drop packets. Folds the locale (used by the
  # translation agent) and the quickbar into players-cache.json; the active
  # quickbar page still comes from the packets, the game has no API for it.
  # Queried by game INDEX: the join heartbeat that triggered this already
  # bound it, so no name ever has to be quoted into Lua.
  # Returns the thread (tests join it) or nil when RCON isn't available.
  def enrich_joined_player(name, idx)
    return nil unless @rcon
    Thread.new do
      attrs = @rcon.player_attributes_for(idx)
      unless attrs
        warn "[join] #{name} ##{idx}: RCON enrichment returned nothing"
        next
      end
      @player_db.set_locale_by_id(idx, attrs[:locale]) if attrs[:locale]
      # The colour rides along with the locale: an identity the packets
      # carry but we do not decode yet, and a join is the one moment the
      # server hands it over.
      @player_db[idx] = { color: attrs[:color] } if attrs[:color]
      bar = attrs[:quickbar]
      if bar == :failed
        warn "[join] #{name} ##{idx}: quickbar read failed in Lua (API shape vs " \
             "#{@rcon.server_version || 'unknown version'}?) — attrs kept"
      else
        # The read is authoritative, empty bar included (nil clears the cache).
        @player_db.replace_quickbar(idx, bar)
      end
      # Features see every join, after the store: player_backup restores an
      # empty bar here and re-stores it, so its value is the one that sticks.
      on_join_enriched(name, idx, attrs)
      unless bar == :failed
        puts "[join] #{name} ##{idx}: locale=#{attrs[:locale] || '?'} " \
             "quickbar=#{Array(bar).flatten.compact.size} slot(s)"
      end
    rescue StandardError => e
      warn "[join] #{name} ##{idx}: RCON enrichment failed (#{e.class}: #{e.message})"
    end
  end

  # Decoded quickbar action, for the per-action console line. Item ids, not
  # names: the quickbar is stored and read as wire ids (see
  # PlayerDatabase#set_quickbar_slot), so nothing here needs item_db.
  def quickbar_str(qb)
    return " page=#{qb[:page]}" if qb.key?(:page)
    s = +" slot=#{qb[:slot]}"
    if qb.key?(:src) && qb[:op] != 0
      s << ' (cleared)'
    else
      s << " item=#{qb[:item]}"
      s << " from inv##{qb[:src]}" if qb[:src]
    end
    s
  end

  def log_action(ts, act, is_server, ghost: false, raw_frame: nil)
    pid = act[:game_player]
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
        # A '?' in the printed chat means decode_chat's scrub() replaced
        # bytes: the payload is not valid UTF-8, so the chat decode (or the
        # segment split) is wrong — keep the frame for review. Checked on
        # the BYTES, not the string, so a real "?" never lands here.
        if raw_frame && !data.dup.force_encoding('UTF-8').valid_encoding?
          @unknown_writer&.write_frame(raw_frame, Time.at(ts))
        end
        msg = FactorioProtocol.decode_chat(data)
        if msg
          puts "#{log_ts(ts)}  #{arrow} #{pname}: #{msg}"
          publish_chat(:factorio, pname, msg, player_id: act[:game_player])
        end
      end
      return
    end

    # set_player_color (2.0 wire 296 / 2.1 311): FOUR UNORM bytes R,G,B,A,
    # 0..255. Measured over the whole capture set (2313 occurrences, all one
    # player with the colour picker open, no desync around them): bytes 0..2
    # sweep the full range — [0,0,255] alone is blue, [0,255,0] green,
    # [255,255,255] white, so the order is R,G,B — and byte 3 is 127 in EVERY
    # sample. The save settles it: karada's LuaPlayer.color [1,1,1,0.5] is
    # [255,255,255,127] on the wire (the 8-bit alpha truncates 0.5, hence
    # 0.498 here). RCON is authoritative and still seeds both files at
    # startup; this keeps them current for a player who changes colour while
    # we run, without waiting for their next join. A colour with no NAME
    # (an index we never bound) is dropped: the cache is keyed by name, and a
    # nameless record would poison whoever takes that slot later.
    if act[:name] == 'set_player_color' && act[:data]&.bytesize == 4 && pname &&
       !pname.start_with?('Player_')
      rgba = act[:data].unpack('C4').map { |v| (v / 255.0).round(4) }
      @player_db[pid] = { color: rgba }
      on_player_color(pname, rgba)
    end

    return unless visible?(pname, act)

    return if act[:name].start_with?('Unknown')
    # Skip server-internal actions (no real player)
    return if act[:game_player] <= 0
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
    puts "#{log_ts(ts)}  #{arrow} #{pname.ljust(16)} #{act[:name].ljust(28)}#{data_str}#{suffix}"
  end

  # Console timestamp. Built at the PRINT sites only: formatting it per
  # action cost ~13% of a full capture decode (Time.at + strftime on every
  # action, almost all of which are filtered out before printing).
  def log_ts(ts)
    Time.at(ts).strftime('%H:%M:%S.%L')
  end

  # ── Pcap replay (one process for the whole set) ──────────────────

  # Every -r path in order, in ONE process: the rolling set is hundreds of
  # files and N Ruby startups (~0.3s each) was minutes of the run. Sniffer
  # state carries across files (players, attrs, the name index), so a set
  # reads as one session — which is what it is. A file that cannot be read
  # (a .gz capture still being written, a truncated rotation) is reported and
  # skipped: whatever it yielded before failing is kept.
  def read_pcaps
    paths = Array(@options[:pcaps])
    paths = [@options[:pcap]] if paths.empty?
    prescan_pcap_version(paths.first)
    paths.each_with_index do |path, i|
      puts "[pcap] #{i + 1}/#{paths.size} #{path}" if paths.size > 1
      begin
        PcapReader.new(path).each_packet { |*args| process_packet(*args) }
      rescue StandardError => e
        warn "[pcap] #{path}: #{e.class}: #{e.message} — stopped reading this file"
      end
    end
  end

  # Which tables a replay gets. The default is 2.0 (the only released
  # version), so the connection request (msg 2) in a capture is only needed
  # to spot an EXPERIMENTAL 2.1 server — and it arrives at the client's JOIN,
  # thousands of packets in, so everything before it would decode with the
  # 2.0 tables. Cheap fix: read the first capture once more, up to that
  # request, and pick the tables before decoding starts. Stops at the
  # request, so it reads a fraction of one file.
  def prescan_pcap_version(path)
    return unless path && @options[:protocol_version].nil?
    PcapReader.new(path).each_packet do |_n, _ts, _src, _dst, _sp, _dp, udp, _frame|
      next unless udp.getbyte(0) && (udp.getbyte(0) & 0x1F) == 2
      version = FactorioProtocol.detect_version(udp)
      next unless version
      @protocol_version = version
      puts "[protocol] factorio #{version} — action tables: #{FactorioProtocol.select_version(version)} (pre-scanned from #{path})"
      break
    end
  rescue StandardError => e
    warn "[pcap] version pre-scan of #{path}: #{e.class}: #{e.message} — decoding with the default tables"
  end

  # The messages that carry strings (username, game name, mod list, peer
  # names). The key is PRESENT but nil when the parse failed — a fragment > 0
  # omits the key entirely, which is not a failure.
  STRING_MESSAGES = %i[connection_request connection_confirm connection_accept].freeze
  def string_decode_failed?(parsed)
    STRING_MESSAGES.any? { |k| parsed.key?(k) && parsed[k].nil? }
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

  # Query the RCON roster and merge {name -> index} into the player DB, so
  # players connected at startup are named immediately. Players who join
  # later are captured from the packet stream (msg 4 username + first C→S
  # heartbeat game index). A failed query is skipped silently.
  #
  # Runs on EVERY run attempt — fresh boot AND each in-place reload. The
  # reload case is deliberate: it re-anchors the packet-maintained roster
  # to the server's authoritative view after any interruption. The roster
  # data itself lives on the persistent @attrs object, so nothing is lost
  # between runs either way.
  def load_roster
    return unless @rcon
    # Use player_attributes which now includes locale
    attrs = @rcon.player_attributes
    # load_player_attrs (same startup call site, back-to-back) reuses this
    # exact dump instead of re-querying RCON.
    @attrs_query = attrs
    return if attrs.nil? || attrs.empty?
    connected = attrs.select { |a| a[:connected] }
    return if connected.empty?
    connected.each do |a|
      @player_db[a[:index]] = {name: a[:name], locale: a[:locale], admin: a[:admin], color: a[:color]}
      @player_db.remove_other_entries_for(a[:name], a[:index])
      # Authoritative live-roster seed (connected + index + fresh hb);
      # time accounting is player_attributes' job (load_player_attrs).
      @attrs.roster_online(a[:name], a[:index])
    end
    ts = Time.now.strftime('%H:%M:%S.%L')
    puts "#{ts}  [rcon]  connected players (#{connected.size}): " +
         connected.map { |a| "#{a[:name]} (##{a[:index]})" }.join(', ')
  end

  public

  # Names of players currently in-game (online tracking): seeded from the
  # RCON roster at startup, updated from NewPeerInfo / PeerDisconnect and
  # bound to game indexes by C→S heartbeats. Sorted for stable output.
  # Used by the interactive console status line.
  def online_players
    @attrs.online_names
  end

  # Pick the input-action SEGMENT-type mapping for the server's protocol
  # version. Explicit options[:protocol_version] (--protocol-version) wins;
  # else query RCON helpers.game_version once and cache in state (survives
  # hot reloads, which reset FactorioProtocol.segment_types to 2.1 default).
  def select_protocol_version
    version = @options[:protocol_version] || @protocol_version
    if version.nil? && @rcon
      version = @rcon.server_version
      @protocol_version = version if version
    end
    return unless version
    label = FactorioProtocol.select_version(version)
    puts "[protocol] factorio #{version} — action tables: #{label}"
  rescue => e
    warn "Protocol version detection failed: #{e.class}: #{e.message}"
  end

  # Same, from the wire: a joining client's connection request (msg 2)
  # advertises the version, so a capture needs no RCON and no flag. Stashed in
  # @protocol_version so a hot reload re-applies the same tables.
  def detect_protocol_version(udp_data)
    version = FactorioProtocol.detect_version(udp_data)
    return unless version
    @protocol_version = version
    label = FactorioProtocol.select_version(version)
    puts "[protocol] factorio #{version} — action tables: #{label} (from the connection request)"
  rescue => e
    warn "Protocol version detection from the connection request failed: #{e.class}: #{e.message}"
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
          /model [MODEL]               show or switch LLM model at runtime (Hivemind only)
          /try MODEL [MESSAGE]         one-off dry-run with a configured model — not persisted, not sent to game
          /compact                     distill session into memory, then start fresh
          /simulate NAME LANG MSG      test the translation backend with MSG in LANG
          /locales                     list per-player language overrides
          /locales NAME LANG[,...]     set a player's languages (- clears) e.g. /locales KrlosUltimate en,pt
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
    when '/model'
      if @plugins[:hivemind].nil?
        puts "hivemind disabled (no HIVE_API_KEY or init failed) — model N/A"
      elsif parts[1].nil?
        puts "model: #{@plugins[:hivemind].model} (configured in config-hivemind.yaml)"
        puts "available: #{@plugins[:hivemind].models.join(', ')}"
        puts "usage: /model <model-id>"
      else
        model = parts[1..].join(' ').strip.gsub(/\A["']|["']\z/, '')
        puts @plugins[:hivemind].switch_model!(model)
      end
    when '/try'
      if @plugins[:hivemind].nil?
        puts "hivemind disabled — cannot try"
      elsif parts[1].nil?
        puts "usage: /try <model> [message]  — e.g. /try gpt-4o hivemind how is the factory?"
        puts "       replays last trigger with MODEL one-off (not persisted, not sent to game)"
      else
        model = parts[1].strip.gsub(/\A["']|["']\z/, '')
        msg = parts[2..]&.join(' ')
        msg = nil if msg && msg.strip.empty?
        puts @plugins[:hivemind].try_model!(model, msg)
      end
    when '/simulate'
      # Test the translation backend directly: translate MSG from LANG to English.
      # Usage: /simulate <player_name> <language_code> <message>
      # (player_name is decorative — the backend has no per-player state.)
      if @plugins[:translation].nil?
        puts 'translation agent not enabled — cannot simulate'
        return
      end
      if parts[1].nil? || parts[2].nil?
        puts 'usage: /simulate <player_name> <language_code> <message>'
        puts 'example: /simulate dlruen ru "Zdravstvuyte"'
        return
      end
      player_name = parts[1]
      lang_code = parts[2]
      # Rejoin the rest as the message (may contain spaces); strip wrapping
      # quotes so the documented `... "some text"` form works.
      msg = parts[3..]&.join(' ')&.gsub(/\A["']|["']\z/, '')
      if msg.nil? || msg.strip.empty?
        puts 'usage: /simulate <player_name> <language_code> <message>'
        return
      end
      begin
        translated = @plugins[:translation]&.simulate_translation(player_name, lang_code, msg)
        puts "[simulate] player=#{player_name} lang=#{lang_code} msg='#{msg}' => translated='#{translated}'"
      rescue StandardError => e
        warn "[simulate] error: #{e.class}: #{e.message}"
      end
    when '/locales'
      if @player_db.nil?
        puts 'no player db — cannot manage locale overrides'
      elsif parts[1].nil?
        # bare /locales: list every override
        all = @player_db.all_locale_overrides
        puts all.empty? ? 'no locale overrides' : all.map { |n, l| "#{n}: #{l.join(',')}" }.join("\n")
      elsif parts[2].nil?
        # /locales NAME: show the override
        langs = @player_db.locale_overrides(parts[1])
        puts langs.to_a.empty? ? "#{parts[1]}: no override (game locale used)" : "#{parts[1]}: #{langs.join(',')}"
      else
        # /locales NAME en,pt   or   /locales NAME - (clear)
        if parts[2] == '-'
          @player_db.set_locale_overrides(parts[1], [])
          puts "/locales #{parts[1]}: cleared"
        else
          langs = parts[2..].join(',').split(',').filter_map { |l|
            b = l.split('-').first&.downcase&.strip
            b unless b.empty?
          }.uniq
          @player_db.set_locale_overrides(parts[1], langs)
          puts "/locales #{parts[1]}: #{langs.join(',')}"
        end
      end
    when '/compact'
      # Compaction is one of Hivemind's own plugins (config-hivemind.yaml
      # `plugins:`); the only other way in is no running agent. Past that
      # compact_memory! itself returns false for a disabled memory store, so
      # the session is kept and nothing is cleared.
      hivemind = @plugins[:hivemind]
      unless hivemind&.plugin?(:compaction)
        puts 'memory compaction unavailable (no agent, or the compaction plugin is off in config-hivemind.yaml) — session NOT cleared'
        return
      end
      # Runs in a background thread so the console stays responsive (the
      # compaction LLM call takes seconds; it queues behind any live ask).
      # The session is wiped only after a SUCCESSFUL pass — if compaction
      # is disabled or errors, compact_memory! returns false and the
      # session is kept. Both calls serialize on the agent mutex.
      Thread.new do
        if hivemind.compact_memory!('manual')
          # Trim, don't wipe: drop the messages the pass saw (minus a
          # recent tail kept for flow); mid-pass console lines survive.
          hivemind.trim_session_after_compaction!
        else
          puts 'memory compaction FAILED — session kept (see [hivemind] error above)'
        end
      end
      puts 'memory compaction started — session resets when done (see [hivemind] logs)'
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

  # One-shot seed of mirrored LuaPlayer attributes (connected /
  # online_time / afk_time) from RCON for ALL known players. Admin is
  # stored in PlayerDatabase (players-cache.json). After this, the packet
  # stream maintains attrs (PlayerAttrs). A failed/truncated query is
  # non-fatal — attrs are enrichment; the roster/stream keep working.
  def load_player_attrs
    return if @attrs_loaded
    @attrs_loaded = true
    return unless @rcon
    attrs = @attrs_query || @rcon.player_attributes
    @attrs_query = nil
    return if attrs.nil? || attrs.empty?
    attrs.each do |a|
      @player_db[a[:index]] = {admin: a[:admin]}
      @attrs.seed(a[:name], index: a[:index], connected: a[:connected],
                   online_time: a[:online_time],
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
    puts "[summary] packets kept for a failed string decode=#{@stats[:bad_string]}" if @stats[:bad_string]&.positive?
    puts "[summary] packets whose decode RAISED (saved to unknown.packets)=#{@stats[:decode_error]}" if @stats[:decode_error]&.positive?
    return if @unknown_names.empty?
    puts "[summary] packets with a suspected desync: #{@stats[:desync]}" if @stats[:desync]&.positive?
    puts "[summary] undecoded actions: #{@stats[:unknown]}/#{@stats[:actions]} " \
         "(#{@unknown_names.size} type(s)) — top: " \
         "#{@unknown_names.sort_by { |_, v| -v }.first(12).map { |k, v| "#{k}=#{v}" }.join(', ')}"
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
    @plugins.emit(:on_player_event, :left, name)
    @plugins.emit(:on_player_left, name, @attrs.online_time_ticks(name, nil))
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
    # Liveness comes from packet-derived heartbeats, not periodic
    # RCON roster refreshes (load_roster stays as-is on startup/reload).
    @attrs.disconnect(name, @game_tick)
    @plugins.emit(:on_player_event, :timeout, name)
    @plugins.emit(:on_player_left, name, @attrs.online_time_ticks(name, nil))
    ts_str = Time.now.strftime('%H:%M:%S.%L')
    puts "#{ts_str}  #{name} timed out (no heartbeat for #{idle.round}s) — likely crashed or disconnected; may re-join" if player_visible?(name)
  end

  # ponytail: total silence delays timeout announcements until the next packet;
  # restore a timer only if detecting silence independently becomes important.
  def check_timeouts_if_due
    return unless @options[:server] && @options[:interface] && !@options[:pcap]
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    return if now - @last_timeout_check < 1.0
    @last_timeout_check = now
    check_heartbeat_timeouts
  rescue StandardError => e
    warn "heartbeat timeout check failed: #{e.class}: #{e.message}"
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

  # ── Live map-download roster seed (client mode) ───────────────────

  # Client mode never sees the players who were already in the game: the
  # wire only carries joins from now on, and there is no RCON. The map
  # download is the server's own save, and a save holds the whole roster, so
  # we reassemble it off the live stream (MapDownload, off the capture
  # thread) and seed the roster from it. Server mode has both the save on
  # disk and RCON, so it does neither.
  def map_download_hook
    return nil if @options[:server] || !@options[:interface] || @options[:player_db].nil?
    @map_download ||= MapDownload.new(dir: default_capture_dir) do |zip, blocks|
      seed_roster_from_save(zip, blocks)
    end
  end

  # Runs on the MapDownload worker thread, never the capture thread. The
  # roster scan is the tool's job (it is the tested implementation), so this
  # shells out to it and reloads the in-memory cache afterwards — otherwise
  # the names would only reach the file, not the running session.
  def seed_roster_from_save(zip, blocks)
    tool = File.expand_path('../tools/extract_players_from_save.rb', __dir__)
    out = IO.popen([RbConfig.ruby, tool, zip, @options[:player_db], '--merge'], err: [:child, :out], &:read)
    if $?.success?
      @player_db.reload!
      puts out.lines.grep(/\A(?:roster|new|play time):/).map { |l| "[map-download] #{l}" }
      File.delete(zip) # the roster was the point; the pcap keeps the blocks if wanted
    else
      warn "[map-download] roster seeding failed, save kept at #{zip}:\n#{out}"
    end
  rescue StandardError => e
    warn "[map-download] roster seeding failed: #{e.class}: #{e.message}"
  end

  # ── Always-on auto-named capture ────────────────────────────────

  def new_pcap_writer(path)
    PcapWriter.new(path, gzip: @options[:save_capture_gz], keep: effective_keep, rotate_size: effective_rotate_size, max_size: effective_max_size, timestamped: true)
  end

  # Default captures/ directory (created on demand), relative to cwd.
  def default_capture_dir
    dir = File.join(Dir.pwd, 'captures')
    FileUtils.mkdir_p(dir) unless File.directory?(dir)
    dir
  end

  # Capture identity path (never written directly): the writer timestamps
  # it on open (`server-<port>-<ts>.pcap`), so every file under the stem is
  # one identity and retention covers ALL runs, not just the current one.
  def capture_path(dir, id)
    ext = @options[:save_capture_gz] ? '.pcap.gz' : '.pcap'
    File.join(dir, "#{id}#{ext}")
  end

  # Human hint about rotation for the capture startup line.
  def retention_hint
    " (rotating hourly/at #{effective_rotate_size}MB, keep #{effective_keep}h / #{effective_max_size}MB total)"
  end

  # Effective retention: explicit flags win, otherwise the hardcoded
  # defaults above (capture is always on — unbounded is never an option).
  def effective_keep
    @options[:keep] || DEFAULT_KEEP_HOURS
  end

  def effective_rotate_size
    @options[:rotate_size] || DEFAULT_ROTATE_SIZE_MB
  end

  # Total budget for the rotated files (nil = age-only retention).
  def effective_max_size
    @options.key?(:max_size) ? @options[:max_size] : DEFAULT_MAX_SIZE_MB
  end

  # Client mode: the server IP is unknown at startup — resolve it from the
  # first packet where one endpoint is one of our host IPs (`ip:`) and the
  # other is the server; fall back to plain "client" otherwise.
  def ensure_pcap_writer(src_ip, dst_ip)
    return unless @pending_capture
    local = Array(@options[:host_ips])
    server_ip = if local.include?(src_ip)
      dst_ip
    elsif local.include?(dst_ip)
      src_ip
    end
    id = server_ip ? "client-#{server_ip}" : 'client'
    path = capture_path(@pending_capture, id)
    @pcap_writer = new_pcap_writer(path)
    @pending_capture = nil
    puts "capturing to #{path}#{retention_hint}"
  end
end
