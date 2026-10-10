# frozen_string_literal: true

require_relative '../factorio_wire'

module FactorioProtocol
  extend FactorioWire  # provides encode_string, encode_uint32v, encode_uint16v

  # The three messages a CLIENT sends, built from the same primitives the
  # decoders in packets/ read them with (FactorioWire's varint/string codec —
  # `extend`ed above, so these are module-level calls).
  #
  # These exist for FactorioClient (lib/factorio_client.rb), the fake client
  # that joins a server and records it. Nothing in the sniffer uses them; the
  # decoders are untouched, so a message we can build is also a message the
  # existing parse path must round-trip (test/factorio_client_test.rb builds
  # the real captured bytes back and compares).
  #
  # Ground truth is the captures, not the format description: every layout
  # below was read off a real C→S packet (see the fixture comments), so the
  # round-trip test can rebuild them byte for byte.

  # The network header byte. Only msg types 2 and 4 carry a message_id.
  def self.build_header(msg_type, has_random: false, fragmented: false, last_frag: false)
    flags = msg_type | (has_random ? 0x20 : 0) | (fragmented ? 0x40 : 0) | (last_frag ? 0x80 : 0)
    [flags].pack('C')
  end

  # ConnectionRequest (2) — "here is my version". 14 bytes, one of the most
  # common packets in a join:
  #   flags(1) message_id(2, always present on msg 2) major minor patch
  #   build(u32 LE) client_id(u32 LE)
  # Captured: 02000002004d3b4a0100da3edbde = 2.0.77 build 19003, client
  # 0xdedb3eda.
  def self.build_connection_request(version:, build:, client_id:, message_id: 0, has_random: false)
    maj, min, patch = version.split('.').map(&:to_i)
    build_header(2, has_random: has_random) + [message_id].pack('v') +
      [maj, min, patch].pack('C3') + [build].pack('V') + [client_id].pack('V')
  end

  # ConnectionRequestReplyConfirm (4) — the username, and the mod list +
  # mod settings the deterministic sim needs. The inverse of
  # ConnectionConfirmPacket#parse_confirm:
  #   client_id(4) server_id(4) instance_id(4) username
  #   flag(0) session_token client_timestamp connection_id(8)
  #   [u8 count] mods + settings tree
  # `mods:` is the [[name, "2.0", crc, trailing_byte], ...] shape
  # parse_client_mods returns. `settings:` defaults to an EMPTY tree
  # (LIST, count 0 — `05 00` + a u32 0, 6 bytes), which decodes back to {}
  # and is what a client with no settings changes sends.
  #
  # A client joins TWICE: once with no session token (the pre-auth attempt)
  # and once with the token the server handed back. One confirm is enough to
  # get a token-less peer accepted on a server that needs no auth.
  # `connection_id:` is the raw 8 bytes of the per-connection id.
  def self.build_connection_confirm(username:, connection_id:, client_id: 0, server_id: 0,
                                    instance_id: 0, token: '', client_time: '',
                                    mods: [], settings: nil, message_id: 1)
    mods_blob = +''.b
    mods.each do |name, version, crc|
      # Version is 3 bytes: major(1) + minor(1) + sub(1), each a uint8.
      # Followed by crc(4, uint32 LE). No trailing byte.
      maj, min, sub = version.to_s.split('.').map(&:to_i)
      mods_blob << encode_string(name) << [maj, min, sub].pack('CCC') << [crc].pack('V')
    end
    build_header(4) + [message_id].pack('v') +
      [client_id, server_id, instance_id].pack('V3') +
      encode_string(username) +
      [0].pack('C') + encode_string(token) + encode_string(client_time) +
      connection_id.b +
      [mods.length].pack('C') + mods_blob +
      (settings || build_empty_settings)
  end

  # The empty mod-settings tree: LIST type, any_type 0, zero entries. The
  # property tree is [type][any_type][payload] and the count is a plain u32
  # (see FactorioPropertyTree.value), so an empty one is 6 bytes that decode
  # back to `{}` and consume exactly themselves.
  def self.build_empty_settings
    "\x05\x00" + [0].pack('V')
  end

  # ClientToServerHeartbeat (6) — the inverse of HeartbeatPacket#parse_heartbeat:
  #   flags(1) seq(u32) [closure count(u8)] tick closures [next_receive(u64)]
  #   [requests]
  # A tick closure is `tick(u64)` plus, unless all closures are empty, a
  # uint32v `action_count << 1 | has_segments` and the actions. `closures:` is
  # [[tick, action_count, actions_bytes], ...] — the actions already encoded
  # (see build_input_action), so a caller can put anything on the wire. The
  # 8-byte [tick][pad] trailer goes inside `actions_bytes`, after the last one.
  #
  # An IDLE client sends EMPTY closures for every tick it "played": the server
  # only learns a client's tick from its closures and cannot know what the
  # client would have done, so zero-action closures keep the session alive
  # with no simulation at all.
  # `requests:` are the sequence numbers the server asked us to resend
  # (parse_heartbeat reads them from a flag-0x01 heartbeat).
  def self.build_client_heartbeat(seq:, closures:, next_receive:, requests: [], has_random: false, sync_actions: [])
    all_empty = closures.all? { |_, _, actions| actions.nil? || actions.to_s.empty? }
    has_tcl = closures.size > 0
    has_sync = !sync_actions.empty?
    flags = 0
    flags |= 0x02 if has_tcl                       # has tick closures
    flags |= 0x04 if has_tcl && closures.size == 1  # single closure → no count byte
    flags |= 0x08 if all_empty && has_tcl          # no per-closure action count
    flags |= 0x10 if has_sync                      # has synchronizer action
    flags |= 0x01 unless requests.empty?           # has heartbeat requests
    body = closures.map do |tick, count, actions|
      blob = [tick].pack('Q<')
      next blob if all_empty
      blob + encode_uint32v(count.to_i << 1) + actions.to_s
    end
    out = build_header(6, has_random: has_random) + [flags].pack('C') + [seq].pack('V')
    out += [closures.size].pack('C') if (flags & 0x02) != 0 && (flags & 0x04).zero?
    out + body.join + [next_receive].pack('Q<') +
      (has_sync ? encode_uint32v(sync_actions.size) + sync_actions.join : ''.b) +
      (requests.empty? ? ''.b : [requests.size].pack('C') + requests.pack('V*'))
  end

  # Build a synchronizer action for C→S heartbeats.
  # format: type(uint8) + data
  # 0x03 ClientChangedState: type(1) + state(1)
  # 0x06 MapLoadingProgressUpdate: type(1) + progress(1)
  # 0x09 MapDownloadingProgressUpdate: type(1) + progress(1)
  # 0x0a CatchingUpProgressUpdate: type(1) + progress(1)
  def self.build_sync_action(type, data = '')
    [type].pack('C') + data.b
  end

  # 0x06 MapLoadingProgressUpdate: type(1) + progress(1)
  def self.map_loading_sync_action(progress = 254)
    [0x06, progress].pack('CC')
  end

  # One input action inside a closure:
  #   type(uint16v) player_delta(uint16v) data
  # The 8-byte [tick][pad] closure trailer is NOT part of the action — it goes
  # after the LAST action of the last closure, so it is the caller's job
  # (see build_client_heartbeat / FactorioClient#input_action).
  def self.build_input_action(type, player_delta, data = '')
    encode_uint16v(type) + encode_uint16v(player_delta) + data.b
  end

  # msg 12: TransferBlockRequest — asks the server for the next map data block.
  def self.build_transfer_block_request(block_index, has_random: false)
    build_header(12, has_random: has_random) + [block_index].pack('V')
  end
end