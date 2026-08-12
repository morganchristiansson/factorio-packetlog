# frozen_string_literal: true

require_relative 'factorio_packet'

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

  # ConnectionRequestReplyConfirm (4) — carries the client's username.
  #   client_id(4) + server_id(4) + instance_id(4) + username string +
  #   password hash string + server key string + timestamp(8)
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
      username = data[off, len]
      return nil if username.nil? || username.empty?
      # Sanity: usernames are printable ASCII
      return nil unless username.bytes.all? { |b| b >= 0x20 && b <= 0x7E }
      { client_id: client_id, username: username }
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
