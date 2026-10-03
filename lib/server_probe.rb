# frozen_string_literal: true

require 'socket'
require_relative 'factorio_protocol'

# A direct UDP probe of ONE server: one header-only GameInformationRequest
# (msg 16), then the server's GameInformationReply (msg 17) — no login, no
# session, no save download, the same exchange the game client does when it
# talks to a server directly. `tools/query_server.rb HOST:PORT` is the CLI;
# `tools/server_rank.rb` uses the threaded refresher to keep a whole list
# live.
#
# The transport here is the only thing in this file. The wire format lives
# with the rest of it on FactorioProtocol: `GAME_INFO_REQUEST` builds the
# request, `reassemble_fragments` puts a split reply back together
# (a 505-mod server's reply splits), `parse_game_info` parses it and
# `strip_markup` de-tags the rich text in the description.
#
# NOT the server browser: that is the HTTPS matchmaking API
# (FactorioMatchmaking, lib/matchmaking.rb).
class FactorioServerProbe
  # Raw reassembled reply payload for an address (header stripped), or nil
  # when the server stays silent. Accepts "ip:port", "[v6]:port", bare IPs
  # (default port 34197) and DNS names. A name resolving to both families
  # tries IPv6 first (the matchmaking list is v4 only, so v6 comes from DNS
  # or word of mouth). Retries on fragment gaps (UDP loss).
  def self.probe(addr, timeout: 2, tries: 2)
    host, _, port = addr.rpartition(':')
    if host.empty? || (host.count(':') > 0 && !addr.match?(/\[.*\]/))
      host, port = addr.delete('[]'), '34197' # bare v6 / bare name
    end
    targets = resolve(host.delete('[]'), port.to_i)
    return nil if targets.empty?
    targets.each do |family, ip|
      tries.times do
        s = UDPSocket.new(family)
        s.bind(family == Socket::AF_INET6 ? '::' : '0.0.0.0', 0)
        begin
          s.connect(ip, port.to_i)
        rescue StandardError
          s.close
          next
        end
        s.send(FactorioProtocol::GAME_INFO_REQUEST, 0)
        frames = []
        payload = nil
        while IO.select([s], nil, nil, timeout)
          data, = s.recvfrom(65535)
          hdr = FactorioProtocol.parse_network_header(data)
          next unless hdr && hdr[:msg_type] == 17
          if hdr[:fragmented]
            frames << data
            payload = FactorioProtocol.reassemble_fragments(frames)
          else
            payload = data.byteslice(hdr[:header_size], data.bytesize - hdr[:header_size])
          end
          break if payload
        end
        s.close
        return payload if payload
      end
    end
    nil
  end

  # Resolve host to [[family, ip]] with IPv6 first. Literal IPs pass
  # through untouched; unresolvable names yield [].
  def self.resolve(host, port)
    Addrinfo.getaddrinfo(host, port, :UNSPEC, :DGRAM, nil, Socket::AI_NUMERICHOST)
            .map { |a| [a.afamily, a.ip_address] }
  rescue SocketError
    begin
      Addrinfo.getaddrinfo(host, port, :UNSPEC, :DGRAM)
              .sort_by { |a| a.afamily == Socket::AF_INET6 ? 0 : 1 }
              .map { |a| [a.afamily, a.ip_address] }
    rescue SocketError
      []
    end
  end

  # Parsed info hash for "ip:port" (see parse_game_info), or nil.
  def self.info(addr, **opts)
    raw = probe(addr, **opts)
    raw && FactorioProtocol.parse_game_info(raw)
  end

  # Live player count for "ip:port", or nil if unanswered/unparsable.
  def self.player_count(addr, **opts)
    i = info(addr, **opts)
    i && i[:players].length
  end

  # Counts for many addresses (threaded, batched; failures → nil).
  # Returns {addr => Integer or nil}.
  def self.refresh_counts(addrs, batch: 32)
    live = {}
    mutex = Mutex.new
    addrs.each_slice(batch) do |group|
      group.map do |addr|
        Thread.new do
          n = begin
            player_count(addr)
          rescue StandardError
            nil
          end
          mutex.synchronize { live[addr] = n }
        end
      end.each(&:join)
    end
    live
  end
end
