# frozen_string_literal: true

require 'socket'
require_relative 'factorio_protocol'

# Direct per-server queries over UDP: one header-only GameInformationRequest
# (msg 16) per server, no auth, no session, no save download — the same
# packet the game client sends when probing a server. The reply (msg 17)
# carries name/version/mods/tags/player list; parsing lives in
# FactorioProtocol.parse_game_info, reassembly here.
module ServerQuery
  # The entire request: flags byte with msg_type 16, nothing else.
  REQUEST = "\x10".b

  # Factorio rich-text ([color=...], [img=...], [entity=...]) → plain text.
  def self.strip_tags(s)
    s.to_s.gsub(/\[[^\]]*\]/, '').strip.squeeze(' ')
  end

  # Full-detail lines for an info hash (shared by query_server/rank --interactive).
  def self.format_info(info)
    lines = ["#{strip_tags(info[:name])} (#{info[:host]})"]
    lines << "  version: #{info[:version]} (build #{info[:build]}), time: #{info[:time_min].round(1)} min"
    lines << "  description: #{info[:description][0, 120].inspect}" unless info[:description].empty?
    lines << "  mods (#{info[:mods].length}): #{info[:mods].map { |m| "#{m[0]} #{m[1]}" }.join(', ')[0, 300]}"
    lines << "  tags: #{info[:tags].inspect}" unless info[:tags].empty?
    lines << "  players (#{info[:players].length}): #{info[:players].join(', ')[0, 300]}"
    lines
  end

  # Raw reassembled reply payload for an address (header byte stripped), or
  # nil when the server stays silent. Accepts "ip:port", "[v6]:port",
  # bare IPs (default port 34197) and DNS names. A name resolving to both
  # families tries IPv6 first (matchmaking lists v4 only, so v6 comes from
  # DNS or word of mouth). Retries on fragment gaps (UDP loss).
  def self.raw_info(addr, timeout: 2, tries: 2)
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
        s.send(REQUEST, 0)
        frags = {}
        last = nil
        while IO.select([s], nil, nil, timeout)
          data, = s.recvfrom(65535)
          if data.getbyte(0) & 0x40 != 0
            frags[data.getbyte(3)] = data[4..]
            last = data.getbyte(3) if data.getbyte(0) & 0x80 != 0
            break if !last.nil? && (0..last).all? { |i| frags.key?(i) }
          else
            s.close
            return data[1..]
          end
        end
        s.close
        return frags.sort.map(&:last).join if !last.nil? && (0..last).all? { |i| frags.key?(i) }
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
    raw = raw_info(addr, **opts)
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
