# frozen_string_literal: true

require_relative 'factorio_packet'
require_relative '../../factorio_property_tree'
require_relative '../../factorio_save'

module FactorioProtocol
  # ConnectionRequest (2) — client announces its version.
  class ConnectionRequestPacket < FactorioPacket
    private

    def parse_body
      @result[:connection_request] = parse_request(@data, @header[:header_size])
    end

    def parse_request(data, offset)
      return nil if data.bytesize < offset + 9
      maj = data.getbyte(offset)
      min = data.getbyte(offset + 1)
      patch = data.getbyte(offset + 2)
      build = data.unpack1('V', offset: offset + 3) & 0xFFFF
      cid   = data.unpack1('V', offset: offset + 5)
      { version: "#{maj}.#{min}.#{patch} (build #{build})", client_id: cid }
    end
  end

  # ConnectionRequestReplyConfirm (4) — the client's username AND its mod
  # list + mod settings (the settings are a PropertyTree — the mod-settings.dat
  # format, see FactorioPropertyTree and docs/protocol-notes.md for the layout
  # and the fragmentation caveat).
  #   client_id(4) + server_id(4) + instance_id(4) + username string +
  #   session block (flag + session token + client timestamp + 8-byte
  #   connection id) + [u8 count] mods + settings PropertyTree
  # A client joins TWICE: the first msg 2/msg 4 carry no session token (LAN /
  # pre-auth), the second carries the token and the timestamp.
  #   mod := [len]name + u16 version + u32 crc + u8 ?  (the trailing byte is
  #   not identified; it is 0 for some mods and >0 for others)
  class ConnectionConfirmPacket < FactorioPacket
    private

    def parse_body
      @result[:connection_confirm] = parse_confirm(@data, @header[:header_size])
    end

    def parse_confirm(data, offset)
      return nil if data.bytesize < offset + 12
      client_id = data.unpack1('V', offset: offset)
      offset += 12  # clientID(4) + serverID(4) + instanceID(4)
      off, len = decode_uint32v(data, offset)
      return nil if len.nil? || off + len > data.bytesize
      username = data[off, len].force_encoding('UTF-8').scrub('?')
      return nil if username.nil? || username.empty?
      # Sanity: usernames are printable ASCII
      return nil unless username.bytes.all? { |b| b >= 0x20 && b <= 0x7E }
      session, at = parse_session(data, off + len)
      return nil unless session
      { client_id: client_id, username: username, session: session }.merge(parse_client_mods(data, at))
    end

    # The block between the username and the mod list. Verified over 90
    # fragment-0 joins: a flag byte (always 0), a session token and a client
    # timestamp — BOTH empty on a client's FIRST join and both present on its
    # second, which is why every client sends msg 2 and msg 4 TWICE with two
    # client ids (the first is the LAN / pre-auth attempt) — then an 8-byte
    # per-connection id, then the mod count. The token is the auth session
    # token ("DYPfkzXZscNvs86TzMGACg==" is 24 chars of base64) and the stamp is
    # the client's clock ("260925030027" = 2026-09-25 00:51:06, matching the
    # capture to the second).
    def parse_session(data, at)
      flag = data.getbyte(at)
      return nil unless flag == 0
      at += 1
      at, token = decode_string(data, at, allow_empty: true)
      return nil unless token
      at, stamp = decode_string(data, at, allow_empty: true)
      return nil unless stamp
      id = data.byteslice(at, 8)
      return nil unless id
      [{ flag: flag, token: token, client_time: stamp, connection_id: id.unpack1('H*') }, at + 8]
    end

    # The client's mod list and mod settings, which follow the username.
    # FRAGMENT 0 ONLY: a modded client's msg 4 arrives in up to 6 packets
    # (flags 0x40, frag_number 0..last_frag) and nothing here is reassembled,
    # so `truncated` is the normal case for a big loadout — the names decoded
    # so far are still correct, the list is just incomplete.
    def parse_client_mods(data, at)
      count = data.getbyte(at)
      return {} if count.nil? || count.zero?
      at += 1
      mods = []
      count.times do
        name = string_at(data, at)
        break unless name
        at = name[1]
        version = data.byteslice(at, 2)&.unpack1('v')
        break unless version
        mods << [name[0], "#{version >> 8}.#{version & 0xFF}", data.byteslice(at + 2, 4)&.unpack1('V'),
                 data.getbyte(at + 6)]
        at += 7
      end
      settings, after = FactorioPropertyTree.value(data, at) # `05 00` = a dictionary
      { mods: mods, settings: settings, mods_truncated: mods.size < count,
        settings_truncated: after.nil? || after != data.bytesize }
    end
  end

  # ConnectionAcceptOrDeny (5) — server's player list.
  #   client_id(4) status(1) gameName serverHash description latency(1)
  #   max_updates(u32v) game_id(4) steam_id(8) clientsPeerInfo
  #     serverUsername map_saving_progress(1) savingFor(1+n*u16v)
  #     clientPeerInfo: [u32v count][(u16v peer_id, username, flags...)]*
  #   expect_seq(4) send_seq(4) new_peer_id(2) mods...
  #
  # NOTE: clientPeerInfo ids are NETWORK PEER ids, NOT game player
  # indexes (verified: morganc's peer id=101 but game index=11).
  # result[:connection_accept] = { client_id:, status:, game_name:,
  #   server_hash:, server_username:, peers: [{peer_id:, name:}] }
  class ConnectionAcceptPacket < FactorioPacket
    private

    def parse_body
      @result[:connection_accept] = parse_accept(@data, @header[:header_size])
    end

    def parse_accept(data, offset)
      return nil if data.bytesize < offset + 20
      res = {}
      res[:client_id] = data.unpack1('V', offset: offset); offset += 4
      res[:status] = data.getbyte(offset); offset += 1
      offset, res[:game_name] = decode_string(data, offset)
      offset, res[:server_hash] = decode_string(data, offset)
      offset, res[:description] = decode_string(data, offset)
      return nil if offset.nil?
      offset += 1  # latency
      offset, res[:max_updates] = decode_uint32v(data, offset)
      offset += 4  # game_id
      offset += 8  # steam_id

      # clientsPeerInfo
      offset, server_username = decode_string(data, offset)
      return nil if offset.nil?
      res[:server_username] = server_username
      offset += 1  # map_saving_progress
      saving_count = data.getbyte(offset); offset += 1
      saving_count.to_i.times do
        offset, = decode_uint16v(data, offset)
      end
      offset, client_count = decode_uint32v(data, offset)
      return nil if client_count.nil? || client_count > 1024
      res[:peers] = []
      client_count.to_i.times do
        break if offset.nil?
        offset, peer_id = decode_uint16v(data, offset)
        offset, name = decode_string(data, offset)
        break if offset.nil?
        flags = data.getbyte(offset); offset += 1
        [0x01, 0x02, 0x04, 0x08, 0x10].each { |b| offset += 1 if (flags & b) != 0 }
        res[:peers] << { peer_id: peer_id, name: name }
      end
      res
    end
  end
end
