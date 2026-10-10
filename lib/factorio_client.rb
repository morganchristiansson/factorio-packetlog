# frozen_string_literal: true

require 'socket'
require_relative 'factorio_protocol'
require_relative 'factorio_protocol/build'
require_relative 'factorio_save'
require_relative 'server_probe'
require_relative 'pcap'

class FactorioClient
  # Client state machine (matches Factorio's ClientState enum)
  CLIENT_STATE_CONNECTED       = 2  # ClientChangedState after handshake
  CLIENT_STATE_DOWNLOADING     = 3  # Map download started
  CLIENT_STATE_LOADING         = 4  # Map loading
  CLIENT_STATE_CATCHING_UP     = 5  # Catching up to server tick
  CLIENT_STATE_WAITING_TCL     = 6  # Waiting for command to start tick closures
  CLIENT_STATE_INGAME          = 7  # InGame — fully connected
  CLIENT_STATE_DISCONNECTING   = 8  # Disconnecting

  attr_reader :accept, :server_tick, :sent_heartbeats, :received, :blocks_received

  def initialize(host:, port: 34_197, username: 'packettools', record: nil, log: ->(m) { puts m },
                 version: nil, build: nil, save: nil)
    @host = host
    @port = port
    @username = username
    @log = log
    @version = version
    @build = build
    @actions = []
    @received = 0
    @blocks_received = 0
    @next_block_request = 0
    @total_blocks = nil
    @map_download_started = false
    @sent_heartbeats = 0
    @client_state = 0
    @last_map_progress = -1
    @catchup_progress = 0
    @loading_step = 0
    @server_first_closure_tick = nil
    # Per-drain S->C tick arrivals (reset at each drain, appended in
    # track_server_heartbeat): the seed reads this drain's newcomers.
    @drain_ticks = []
    @pre_drain_tick = nil   # freshest confirmed tick BEFORE the current drain
    @pre_drain_wall = nil   # receipt time of that tick (nil = none yet)
    @empty_drains = 0       # consecutive packet-less drains (dead-stream trip)
    @last_drain_count = 0
    @ingame_beats = 0       # INGAME beats while unseeded (dense-seed window)
    @seed_bias = 32         # dense-seed bias, alternating 32/31 per attempt
    @writer = record ? PcapWriter.new(record) : nil
    @has_random = false  # never claim encryption nonce on C->S heartbeats; the server's S->C flag is not echoed
    # Optional save-tick calibration: read the server's stored tick from its
    # save file.  When the UDP stream is too short to drain (or frozen during
    # a save), the client has no real-time tick — the save tick + mtime gives
    # an estimate of the server's current tick (game.tick = save_tick +
    # elapsed * 60).  It does NOT replace the UDP stream's authoritative tick;
    # it is a fallback for `@server_tick` when the drain fails.  (Closures
    # are never seeded from it: the first closure is seeded off the live
    # S->C tick stream, see send_heartbeat.)
    if save
      @save_tick = FactorioSave.tick_from_save(save)
      @save_mtime = File.mtime(save).to_f
      log("save #{save}: tick=#{@save_tick}, mtime=#{Time.at(@save_mtime)}") if @save_tick
    end
  end

  def server_version
    return [@version, @build] if @version
    info = FactorioServerProbe.info("#{@host}:#{@port}")
    raise "#{@host}:#{@port} did not answer a GameInformationRequest" unless info
    log("#{@host}:#{@port} — #{info[:name].to_s.strip} #{info[:version]} build #{info[:build]}, " \
        "#{info[:players].length} players, #{info[:mods].length} mods")
    [info[:version], info[:build]]
  end

  # Handshake from capture:
  # 1. msg 2 (ConnectionRequest) → msg 3 (ConnectionRequestReply, may be fragmented)
  # 2. msg 3 gives assigned_client_id, server_id, instance_id
  # 3. msg 4 (ConnectionConfirm, non-fragmented, msg_id=1) with empty token
  # 4. msg 5 (ConnectionAcceptOrDeny)
  # 5. Map download (msg 13) + heartbeats (msg 6/7)
  def connect(timeout: 6)
    # A reconnect is a NEW peer (new seq, new ticks): drop every per-session
    # counter or the new peer sends the old peer's closures on its first
    # beat — the server has no expectation for it yet ("wrong tick closure
    # (53) instead of (18446744073709551615)") and kills it at once, and
    # every beat after the kill reads as "outside latency window".
    @server_tick = nil
    @stream_recv_wall = nil
    @client_state = 0
    @state2_sent = nil
    @map_download_started = false
    @blocks_received = 0
    @next_block_request = 0
    @total_blocks = nil
    @last_map_progress = -1
    @loading_step = 0
    @catchup_progress = 0
    @wait_tcl_beats = nil
    @closure_tick = nil
    @server_first_closure_tick = nil
    @drain_ticks = []
    @pre_drain_tick = nil
    @pre_drain_wall = nil
    @empty_drains = 0
    @last_drain_count = 0
    @ingame_beats = 0
    # NOTE: @seed_bias persists across reconnects on purpose — dense seeds
    # alternate 32/31 per attempt so a running-game join converges.
    @last_closed_tick = nil
    @prev_stream2 = nil
    version, build = server_version
    @socket = UDPSocket.new
    @socket.connect(@host, @port)
    @local, @local_port = @socket.addr[3], @socket.addr[1]
    @remote_ip = @socket.peeraddr[3]  # resolved IP for pcap frame headers

    @client_id = 0xdedb3eda
    @connection_id = [0x75, 0xb5, 0x9e, 0xf9, 0x34, 0x91, 0x5b, 0x36].pack('C*')

    mods = [['base', '2.0.77', 1879415942]]

    5.times do |attempt|
      log("Handshake attempt #{attempt + 1}/5...")
      send_packet(FactorioProtocol.build_connection_request(version: version, build: build,
                                                           client_id: @client_id))
      raw3 = await(3, timeout)
      unless raw3
        log("No msg 3 received, retrying...")
        next
      end

      # Parse msg 3 payload
      # Body: [version(7)] [assigned_client_id(4)] [server_id(4)] [instance_id(2)]
      hdr = @msg3_header
      payload = raw3[hdr[:header_size]..-1]
      @assigned_client_id = payload[7..10].unpack1('V')
      @server_id = payload[11..14].unpack1('V')
      @instance_id = payload[15..16].unpack1('v')
      log("msg 3: assigned=0x#{@assigned_client_id.to_s(16)} server=0x#{@server_id.to_s(16)} " \
          "instance=#{@instance_id} has_random=#{hdr[:has_random]}")

      # Non-fragmented msg 4 with msg_id=1 (matching the capture)
      send_connection_confirm(mods, token: '', server_id: @server_id, instance_id: @instance_id)
      # NOTE: do NOT copy @has_random from msg 3 or S->C heartbeats.
      # The flag means the SERVER included a nonce, not that we should
      # echo it on outgoing packets (build_client_heartbeat doesn't emit
      # a nonce, so echoing the bit makes the server misparse our seq).
      if await(5, timeout)
        if @parsed && @parsed[:connection_accept]
          @accept = @parsed[:connection_accept]
          break
        end
      end
      log("attempt #{attempt + 1} failed (no valid msg 5)")
    end

    raise 'no ConnectionAcceptOrDeny (msg 5) after 5 attempts' unless @accept

    # msg 5 gives TWO counters: expect_seq (the server's outgoing seq the
    # client expects to receive) and send_seq (the first seq the client
    # should send). Verified live (handshake18.pcap: expect=3458
    # send=2024890531, first C->S hb seq=2024890531; test-server 2.0.77:
    # expect=576 = nextHeartbeatSequenceNumber, send=659285042 in the
    # 600M range of real-client seqs). Starting at expect_seq instead puts
    # every heartbeat below the server's latency window: log says
    # "heartbeat outside latency window" from beat one.
    # @latency is set BEFORE the drain because the seed logic (send_heartbeat)
    # needs it from the first beat on.
    # The starting C->S heartbeat seq IS send_seq (the real client's first
    # heartbeat sends exactly it); expect_seq is the server's outgoing
    # counter, and starting there rejects every beat ("outside latency
    # window" from beat one).
    @seq = @accept[:send_seq] || @accept[:expect_seq]
    @latency = @accept[:latency] || 32
    # Drain up to ~0.2s of server heartbeats to learn the current tick — but
    # NOT the old long drains: the server's per-peer heartbeat expectation
    # runs at ~60/s from the moment it adds the peer, and every heartbeat we
    # skip opens a gap in its latency window (log: "heartbeat outside latency
    # window" for the WHOLE session because the first hb arrived ~1s late).
    # The real client (handshake18.pcap) sends its first heartbeat within ms
    # of the connection and keeps ~60/s flowing even while downloading.
    deadline = Time.now + 0.2
    drain while Time.now < deadline
    # If the UDP drain didn't yield a server tick (frozen stream during a
    # save, or too few heartbeats in 0.2s), fall back to the save tick:
    #   game.tick ≈ save_tick + (now - save_mtime) * 60
    if !@server_tick && @save_tick && @save_mtime
      @server_tick = @save_tick + ((Time.now.to_f - @save_mtime) * 60).round
      log("server_tick from save: #{@server_tick} (save tick #{@save_tick}, " \
          "saved #{((Time.now.to_f - @save_mtime) * 60).round} ticks ago)")
    end

    log("joined as #{@username.inspect}; peers: #{(@accept[:peers] || []).map { |p| p[:name] }.join(', ')}; " \
        "start seq=#{@seq} (expect=#{@accept[:expect_seq]}, send=#{@accept[:send_seq]}, latency=#{@latency})")
    @accept
  end

  def send_connection_confirm(mods, token:, server_id: 0, instance_id: 0)
    # Non-fragmented msg 4 with msg_id=1
    send_packet(FactorioProtocol.build_connection_confirm(
      username: @username,
      connection_id: @connection_id,
      client_id: @assigned_client_id,
      server_id: server_id,
      instance_id: instance_id,
      token: token,
      mods: mods,
      message_id: 1
    ))
  end

  def run(seconds: nil, &on_packet)
    deadline = seconds && (Time.now + seconds)
    until deadline && Time.now >= deadline
      # Snapshot the confirmed stream BEFORE the drain: the seed compares
      # the drain's arrivals against these (see send_heartbeat).
      @pre_drain_tick = @server_tick
      @pre_drain_wall = @stream_recv_wall
      drain(&on_packet)
      # Dead-session detection by CONSECUTIVE EMPTY drains (~0.25s at 60Hz),
      # not by wall-clock silence: a scheduling stall (ours or the server's)
      # ends in a BURST, which resets the count, so a live session can never
      # suicide on a hiccup (a lone wall-clock trip once killed a healthy
      # session mid-recording). A truly dead stream drains empty forever and
      # still reconnects in a quarter second — far inside the server's own
      # peer timeout, and fast enough that a kill-cycle's rejected stragglers
      # stay a handful of log lines. Gated on INGAME like before: pre-join
      # phases have natural quiet spells (saves, catch-up).
      if @last_drain_count.to_i.zero?
        @empty_drains = (@empty_drains || 0) + 1
      else
        @empty_drains = 0
      end
      if @client_state >= CLIENT_STATE_INGAME && (@empty_drains || 0) >= 15
        log('stream dead ~0.25s, reconnecting...')
        close
        connect unless @stopping
        next
      end
      send_heartbeat
      sleep 1.0 / 60  # ~60Hz: keeps our heartbeat seq inside the server's
      # latency window. The server's per-peer counter advances at the game
      # tick rate (60/s); at 20Hz every heartbeat falls outside it and the
      # session is rejected from the first beat.
    end
  ensure
    @writer&.close
    @socket&.close
  end

  # Drop the connection so a new #connect (repeat join) can be made.
  def close
    # Best-effort clean exit: a closure carrying the player_leave_game action
    # (wire 233, identified via /toggle-action-logging). Live runs show peers
    # lingering to the server-side timeout anyway, so this is an attempt, not
    # a guarantee — the timeout path is equally clean (bare Disconnect).
    if @socket && !@socket.nil?
      begin
        tick = @closure_tick || @server_tick.to_i
        acts = FactorioProtocol.build_input_action(233, 1, '')
        closures = [[tick, 1, acts]]
        send_packet(FactorioProtocol.build_client_heartbeat(
                      seq: @seq, closures: closures, next_receive: (@server_tick || 0) + 1,
                      has_random: @has_random, sync_actions: []))
        @seq += 1
      rescue StandardError
        nil
      end
    end
    @writer&.close
    @writer = nil
    @socket&.close
    @socket = nil
  end

  def send_action(type, player_delta, data = '')
    @actions << [type, player_delta, data.b]
  end

  private

  def send_packet(payload)
    @socket.send(payload, 0)
    @writer&.write_frame(udp_frame(@local, @remote_ip || @host, @local_port, @port, payload), Time.now)
  end

  # Capture raw data for the next msg of the given type.
  # For fragmented msg 3, extracts payload from the raw data without ACKing.
  def await(type, timeout)
    deadline = Time.now + timeout
    @parsed = nil
    @msg3_header = nil
    while Time.now < deadline
      begin
        data = @socket.recvfrom_nonblock(65_535)[0]

        hdr = FactorioProtocol.parse_network_header(data) rescue nil
        if hdr && hdr[:msg_type] == 3
          # Store header info for connect() to parse payload
          @msg3_header = hdr
          return data if type == 3
        end

        handle(data)
        return @parsed if @parsed&.dig(:header, :msg_type) == type
      rescue IO::WaitReadable, Errno::EAGAIN
        sleep 0.05
        next
      end
    end
    nil
  end

  def drain(&on_packet)
    @drain_ticks = []
    n = 0
    loop do
      handle(@socket.recvfrom_nonblock(65_535)[0], &on_packet)
      n += 1
    rescue IO::WaitReadable, Errno::EAGAIN
      @last_drain_count = n
      return
    end
  end

  def handle(data, &on_packet)
    @received += 1
    @writer&.write_frame(udp_frame(@remote_ip || @host, @local, @port, @local_port, data), Time.now)
    raw_type = data.getbyte(0) & 0x1F

    # Handle msg 13 (TransferBlock): lockstep block requests, exactly like
    # the real client (handshake18.pcap: 1093 requests, 1093 blocks,
    # contiguous 0..1092 — racing ahead made the server answer only ~555 of
    # 1234 and then go silent). The first batch of 7 goes out with
    # MapReadyForDownload (below); every further block is requested as its
    # predecessor arrives.
    if raw_type == 13
      @blocks_received += 1
      if @next_block_request < (@total_blocks || 4948)
        send_packet(FactorioProtocol.build_transfer_block_request(@next_block_request))
        @next_block_request += 1
      end
    end

    begin
      @parsed = FactorioProtocol.parse_udp_payload(data)
    rescue StandardError => e
      log("parse error on msg #{raw_type}: #{e.message}")
      @parsed = { header: (FactorioProtocol.parse_network_header(data) rescue nil) }
    end

    if @parsed
      type = @parsed[:header][:msg_type]
      case type
      when 7 then track_server_heartbeat(@parsed[:heartbeat])
      end
      on_packet&.call(@parsed, data)
    end
  end

  def track_server_heartbeat(hb)
    return unless hb
    ticks = hb[:tick_closures].filter_map { |tc| tc[:tick] }
    unless ticks.empty?
      @server_tick = ticks.max
      @stream_recv_wall = Time.now.to_f
      @drain_ticks.concat(ticks)
    end

    hb[:sync_actions].each do |sa|
      case sa[:type]
      when 2 then log("join: #{sa[:username]} (peer #{sa[:peer_id]})")
      when 1 then log("left: peer #{sa[:peer_id] || 'us'}")
      when 4  # ClientShouldStartSendingTickClosures
        if sa[:data] && sa[:data].bytesize >= 8
          catchup_tick = sa[:data].unpack1('Q<')
          @server_first_closure_tick = catchup_tick
          log("catch-up start at tick #{catchup_tick}")
        end
      when 5  # MapReadyForDownload
        if !@map_download_started
          log('map ready, starting block download')
          @map_download_started = true
          @last_map_progress = -1
          # Extract total blocks from data_size (if available)
          if sa[:data_size]
            @total_blocks = (sa[:data_size] + 503) / 504
            log("map data size: #{sa[:data_size]} bytes ≈ #{@total_blocks} blocks")
          end
          # Request the first blocks in batch to complete the download before
          # timeout; the rest follows lockstep in handle() above.
          7.times { |i| send_packet(FactorioProtocol.build_transfer_block_request(@next_block_request + i)) }
          @next_block_request += 7
        end
      when 15 then log("skipped closure for tick #{sa[:tick]}")
      when 16 then log("confirm for tick #{sa[:tick]}")
      end
    end
    return if hb[:heartbeat_requests].empty?
    log("server asked us to resend heartbeats #{hb[:heartbeat_requests].join(', ')}")
  end

  def send_heartbeat
    sync_actions = []
    closures = []

    # Ensure we've transitioned past state 1 (CONNECTED) after handshake
    @client_state = CLIENT_STATE_CONNECTED if @accept && @client_state < CLIENT_STATE_CONNECTED

    # ── State machine: send sync actions as the state transitions ──

    if @client_state == CLIENT_STATE_CONNECTED
      # State 2 (CONNECTED) goes out on the FIRST heartbeat after the
      # handshake, like the real client — not after seconds of draining.
      if @state2_sent
        if @map_download_started
          @client_state = CLIENT_STATE_DOWNLOADING
          sync_actions << FactorioProtocol.build_sync_action(0x03, [CLIENT_STATE_DOWNLOADING].pack('C'))
          sync_actions << FactorioProtocol.build_sync_action(0x09, [0].pack('C'))  # MapDownloading(0)
        end
      else
        @state2_sent = true
        sync_actions << FactorioProtocol.build_sync_action(0x03, [CLIENT_STATE_CONNECTED].pack('C'))
      end
    elsif @client_state == CLIENT_STATE_DOWNLOADING
      if @total_blocks && @blocks_received >= @total_blocks
        # Download complete → loading
        @client_state = CLIENT_STATE_LOADING
        sync_actions << FactorioProtocol.build_sync_action(0x03, [CLIENT_STATE_LOADING].pack('C'))
        sync_actions << FactorioProtocol.build_sync_action(0x06, [0].pack('C'))  # MapLoading(0)
        sync_actions << FactorioProtocol.build_sync_action(0x09, [255].pack('C'))  # MapDownloading(255)
      else
        # Send download progress
        progress = (@blocks_received * 255 / @total_blocks).clamp(0, 255) if @total_blocks
        if progress && progress != @last_map_progress && progress > 0
          @last_map_progress = progress
          sync_actions << FactorioProtocol.build_sync_action(0x09, [progress].pack('C'))
        end
      end
    elsif @client_state == CLIENT_STATE_LOADING
      # Staged loading progress like the real client (handshake18.pcap):
      # Loading(0) rode with state 4, then 254 on the next heartbeat, then 255
      # together with state 5 — the loading phase takes several heartbeats,
      # not one instant transition (which the server may read as skipped).
      if @loading_step == 0
        @loading_step = 1
        sync_actions << FactorioProtocol.build_sync_action(0x06, [254].pack('C'))
      else
        @client_state = CLIENT_STATE_CATCHING_UP
        @catchup_progress = 114
        sync_actions << FactorioProtocol.build_sync_action(0x06, [255].pack('C'))
        sync_actions << FactorioProtocol.build_sync_action(0x03, [CLIENT_STATE_CATCHING_UP].pack('C'))
        sync_actions << FactorioProtocol.build_sync_action(0x0a, [@catchup_progress].pack('C'))
      end
    elsif @client_state == CLIENT_STATE_CATCHING_UP
      # Real progress steps: 114 → 127 → 255 (161/195/229 were ours).
      case @catchup_progress
      when 114
        @catchup_progress = 127
        sync_actions << FactorioProtocol.build_sync_action(0x0a, [@catchup_progress].pack('C'))
      when 127
        @catchup_progress = 255
        @client_state = CLIENT_STATE_WAITING_TCL
        sync_actions << FactorioProtocol.build_sync_action(0x03, [CLIENT_STATE_WAITING_TCL].pack('C'))
        sync_actions << FactorioProtocol.build_sync_action(0x0a, [255].pack('C'))
      end
    elsif @client_state == CLIENT_STATE_WAITING_TCL
      # Minimal dwell (real client sends its first closure almost immediately).
      @wait_tcl_beats = (@wait_tcl_beats || 0) + 1
      if @wait_tcl_beats >= 2
        @client_state = CLIENT_STATE_INGAME
        sync_actions << FactorioProtocol.build_sync_action(0x03, [CLIENT_STATE_INGAME].pack('C'))
      end
    end

    # InGame closure block. Two phases: seeding the first closure, then the
    # steady stream. The seed rides WITH the state-7 beat when its drain
    # already holds the burst (idle.pcap #2600: closures=[32] + sync=[state
    # 7]), otherwise on the first later beat that qualifies.
    if @client_state >= CLIENT_STATE_INGAME
      @ingame_beats = (@ingame_beats || 0) + 1 if @closure_tick.nil?
      if @closure_tick.nil?
        # ── Seed ──
        # The server freezes its expected first closure at the join
        # (updateTick_at_join + latency, msg 5's latency). Three wire shapes:
        #
        # 1. The server tells us verbatim via ClientShouldStartSendingTick-
        #    Closures (type 4: idle.pcap tick 32 -> closure [32]). Always
        #    right; rare (our test server never sends it).
        # 2. Paused join: the S->C tick stream stalls mid-join (server busy
        #    saving + processing the join) and resumes with a burst whose
        #    minimum IS the frozen tick (e.g. burst {8,9,10} with the join
        #    at 8 -> first closure 40; burst {11,12} -> 43; idle.pcap's
        #    first tick {0} -> 32). The burst is the first post-state-7
        #    pre-drain stream and (b) follows a >40ms tick gap (normal
        #    cadence is 16ms; join stalls are 50-190ms). Seed pre+1+latency:
        #    pre is the last pre-freeze tick so pre+1 is the frozen one
        #    (pre+1 form, not the burst minimum: it also survives a lost
        #    burst-min and a reordered pre, which the minimum does not).
        # 3. Dense running join: ticks flow every beat, no stall to read.
        #    The frozen tick is the live edge +-1 (a tick in flight), so
        #    seed live-edge + bias with bias alternating 32/31 per dense
        #    attempt: one of the two is right, a miss kills instantly and
        #    the reconnect retries with the other. Only inside the first 3
        #    INGAME beats — later the frozen expectation is long past and
        #    any seed overshoots (then staying passive beats a kill loop;
        #    the ~24s no-closures drop will cycle us to a fresh join).
        #
        # Sampling the live stream past the burst, or wall-clock estimates
        # (the game is paused mid-download), overshoot: every variant reads
        # "wrong tick closure (X) instead of (Y)", and the kill's aftermath
        # floods the log with "heartbeat outside latency window".
        fresh = @pre_drain_tick.nil? ? @drain_ticks : @drain_ticks.select { |t| t > @pre_drain_tick }
        unless fresh.empty?
          gap = @pre_drain_wall.nil? ? Float::INFINITY : (Time.now.to_f - @pre_drain_wall)
          if @server_first_closure_tick
            @closure_tick = @server_first_closure_tick
            log("first closure tick #{@closure_tick} (type 4, server-told)")
          elsif @pre_drain_tick.nil?
            @closure_tick = fresh.min + @latency
            log("first closure tick #{@closure_tick} (first ticks ever, min #{fresh.min} + latency #{@latency})")
          elsif gap > 0.040 && (@ingame_beats || 0) <= 20
            @closure_tick = @pre_drain_tick + 1 + @latency
            log("first closure tick #{@closure_tick} " \
                "(post-stall burst after #{(gap * 1000).round}ms, pre #{@pre_drain_tick} + 1 + latency #{@latency})")
          elsif (@ingame_beats || 0) <= 3
            @closure_tick = fresh.max + @seed_bias
            log("first closure tick #{@closure_tick} (dense stream, live #{fresh.max} + bias #{@seed_bias})")
            @seed_bias = (@seed_bias == 32 ? 31 : 32)
          end
        end
        if @closure_tick
          @prev_stream2 = @server_tick
          @last_closed_tick = @closure_tick
          closures = [[@closure_tick, 0, '']] if @actions.empty?
          unless @actions.empty?
            acts = @actions.map { |t, d, data| FactorioProtocol.build_input_action(t, d, data) }.join
            closures = [[@closure_tick, @actions.size, acts]]
            @actions = []
          end
        end
      elsif sync_actions.empty?
        # ── Steady ──
        # self-syncing: advance by the stream's own advancement, and CLOSE
        # EVERY tick: at ~55Hz beats vs 60 ticks/s a one-per-beat stream
        # falls behind and the server kills at ~1.3s; multi-closure beats
        # (like the real client) carry the whole (last+1 .. now) range.
        @closure_tick += [@server_tick - (@prev_stream2 || @server_tick), 0].max
        @last_closed_tick ||= @closure_tick
        ticks = ((@last_closed_tick + 1)..@closure_tick).to_a
        @last_closed_tick = @closure_tick
        @prev_stream2 = @server_tick
        if @actions.empty?
          closures = ticks.map { |t| [t, 0, ''] }
        else
          acts = @actions.map { |t, d, data| FactorioProtocol.build_input_action(t, d, data) }.join
          closures = [[@closure_tick, @actions.size, acts]]
          @actions = []
        end
        send_packet(FactorioProtocol.build_client_heartbeat(
                      seq: @seq, closures: closures, next_receive: (@server_tick || 0) + 1,
                      has_random: @has_random, sync_actions: sync_actions
                    ))
        @seq += 1
        @sent_heartbeats += 1
        return
      end
    end

    send_packet(FactorioProtocol.build_client_heartbeat(
                  seq: @seq, closures: closures, next_receive: (@server_tick || 0) + 1,
                  has_random: @has_random, sync_actions: sync_actions
                ))
    @seq += 1
    @sent_heartbeats += 1
  end

  def udp_frame(src, dst, sport, dport, payload)
    ip = "\x45\x00" + [20 + 8 + payload.bytesize].pack('n') + "\x00\x00\x00\x00\x40\x11\x00\x00" +
         src.split('.').map(&:to_i).pack('C4') + dst.split('.').map(&:to_i).pack('C4')
    ("\x00" * 12 + [0x0800].pack('n')) + ip +
      [sport, dport, 8 + payload.bytesize, 0].pack('nnnn') + payload
  end

  def log(msg)
    @log.call(msg)
  end
end
