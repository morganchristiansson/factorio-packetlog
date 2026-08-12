# frozen_string_literal: true

# Auto-detection of a running Factorio server's configuration.
#
# Factorio servers are almost always running on the host that uses the
# sniffer in --server mode, so instead of requiring the operator to pass
# --server-ip / --port / --rcon-* by hand we read the live process:
#
#   * pid:  pgrep -x factorio (fallback: /proc/*/cmdline scan)
#   * game port:    listening UDP sockets owned by the process
#                   (/proc/<pid>/fd socket inodes matched against
#                   /proc/<pid>/net/udp[6]) — e.g. 0.0.0.0:34197
#   * rcon port:    listening TCP socket on 127.0.0.1 (e.g. :27015)
#   * rcon host/password: parsed from the process cmdline
#                   (--rcon-bind host:port, --rcon-password pw)
#   * server IPs:   local IPv4 addresses, default-route interface first
#
# All reads are permissive: any step that fails degrades gracefully and
# callers fall back to their own defaults.
module ServerDetect
  # Flags that ONLY a dedicated (headless) server accepts. The full game
  # client never uses these — so any match means the process is a
  # dedicated server.
  DEDICATED_ONLY_FLAGS = %w[
    --start-server --rcon-bind --rcon-password --server-settings
    --console-log --max-players --autosave-interval --autosave-slots
    --autosave-only-on-server --disallow-commands
    --ignore-player-limit-for-returning-players --non-blocking-saving
    --use-server-whitelist --server-adminlist --server-banlist
    --server-whitelist
  ].freeze

  # Flags the full game client ALSO accepts (usually to host a local game
  # from the client, or to preview a scenario). On a dedicated setup they
  # always accompany DEDICATED_ONLY_FLAGS. Realistically these mean the
  # process is serving, but they are not 100% proof of "dedicated".
  CLIENT_ALSO_FLAGS = %w[
    --start-server-load-scenario --start-server-load-latest
    --map-settings --map-gen-settings
  ].freeze

  # PIDs of all factorio processes, or [].
  def self.find_pids
    out = `pgrep -x factorio 2>/dev/null`
    pids = out.split.map(&:to_i)
    if pids.empty?
      pids = Dir['/proc/[0-9]*/cmdline'].filter_map do |f|
        next unless File.readable?(f)
        cmd = File.read(f).tr("\0", ' ')
        next unless cmd =~ /factorio/
        f[/\d+/].to_i
      end
    end
    pids.uniq
  end

  # PID of the factorio process that is actually serving, or nil.
  # Prefers a process with a listening UDP socket (the game server);
  # falls back to any factorio process.
  def self.find_pid
    pids = find_pids
    return nil if pids.empty?
    pids.find { |pid| !listen_sockets(pid)[:udp].empty? } || pids.first
  end

  # Socket inode numbers owned by pid (targets of /proc/<pid>/fd symlinks).
  def self.socket_inodes(pid)
    Dir["/proc/#{pid}/fd/*"].filter_map do |fd|
      tgt = File.readlink(fd)
      tgt[/^socket:\[(\d+)\]$/, 1]&.to_i
    rescue Errno::ENOENT, Errno::EACCES
      nil
    end
  end

  # Decode the LE hex address column of /proc/net/{udp,tcp}[6] to an IP string.
  def self.decode_ip(proto, hex)
    if proto.end_with?('6')
      # 8 groups of 4 hex chars, each little-endian; 128-bit address
      groups = hex.scan(/.{8}/).map { |g| g.scan(/.{2}/).reverse.join }
      groups.map { |g| g.to_i(16) }.join(':')
    else
      hex.scan(/.{2}/).map { |b| b.to_i(16) }.join('.')
    end
  end

  # Listening sockets owned by pid: { udp: [{ip:, port:}], tcp: [...] }.
  # State 07 = unconnected/listening. Empty hash when nothing found.
  def self.listen_sockets(pid)
    inodes = socket_inodes(pid)
    return { udp: [], tcp: [] } if inodes.empty?

    res = { udp: [], tcp: [] }
    %w[udp udp6 tcp tcp6].each do |proto|
      path = "/proc/#{pid}/net/#{proto}"
      next unless File.exist?(path)
      File.foreach(path) do |line|
        next if line =~ /^\s*sl/
        f = line.split
        next if f.size < 10
        next unless inodes.include?(f[9].to_i) # inode column
        next unless f[3] == '07'               # state: 07 = unconnected/listening
        ip_hex, port_hex = f[1].split(':')     # local address
        key = proto.start_with?('udp') ? :udp : :tcp
        res[key] << { ip: decode_ip(proto, ip_hex), port: port_hex.to_i(16) }
      end
    rescue Errno::ENOENT, Errno::EACCES
      next
    end
    res
  end

  # Name of the interface carrying the default route (e.g. "ens18"), or nil.
  def self.default_route_iface
    File.foreach('/proc/net/route') do |line|
      f = line.split
      return f[0] if f.size >= 2 && f[1] == '00000000'
    end
    nil
  rescue Errno::ENOENT, Errno::EACCES
    nil
  end

  # Interface the server explicitly bound via --bind <ip>, or nil.
  # The game socket itself binds 0.0.0.0 (all interfaces), so the bind
  # address — when given — is the only way to pin down the capture
  # interface from the server config.
  def self.bind_iface(cmdline)
    return nil unless cmdline =~ /--bind\s+(\S+)/
    ip = $1
    require 'socket'
    a = Socket.getifaddrs.find { |x| x.addr&.ip? && x.addr.ip_address == ip }
    a&.name
  rescue StandardError
    nil
  end

  # Pick the capture interface automatically.
  #   * exactly one non-loopback interface ⇒ use it (unambiguous)
  #   * several ⇒ the server's --bind IP's interface, else the default
  #     route's interface
  def self.capture_iface(cmdline = nil)
    require 'socket'
    ifaces = Socket.getifaddrs
                   .select { |a| a.addr&.ipv4? && a.name != 'lo' }
                   .map(&:name)
                   .uniq
    return ifaces.first if ifaces.size == 1
    bind_iface(cmdline) || default_route_iface
  rescue StandardError
    nil
  end

  # Local IPv4 addresses, default-route interface first, loopback excluded.
  def self.local_ipv4
    require 'socket'
    iface = default_route_iface
    addrs = Socket.getifaddrs
                   .select { |a| a.addr&.ipv4? && a.name != 'lo' }
                   .map { |a| a.addr.ip_address }
                   .uniq
    if iface
      # Move the default-route interface's IP(s) to the front
      on_iface = Socket.getifaddrs
                       .select { |a| a.name == iface && a.addr&.ipv4? }
                       .map { |a| a.addr.ip_address }
      addrs = (on_iface + (addrs - on_iface)).uniq
    end
    addrs
  end

  # Which of the given flags appear in the cmdline (as whole args, so
  # "--start-server" doesn't match "--start-server-load-scenario").
  def self.matching_flags(cmdline, list)
    return [] unless cmdline
    list.select { |f| cmdline.split.include?(f) }
  end

  # Directory where the server's helpers.write_file output lands:
  # <user-data>/script-output, where user-data is the process's working
  # directory (NOT the binary dir). See docs/rcon-knowledge.md.
  def self.script_output_dir(pid)
    return nil unless pid && File.directory?("/proc/#{pid}")
    cwd = File.realpath("/proc/#{pid}/cwd")
    File.join(cwd, 'script-output')
  rescue SystemCallError
    nil
  end

  # Full detection of the running server.
  # Returns {} when no factorio process is found; otherwise:
  #   { pid:, cmdline:, game_port:, rcon_host:, rcon_port:, rcon_password:,
  #     server_ips: [], dedicated:, dedicated_flags:, hosting_flags: }
  def self.detect
    pid = find_pid
    return {} unless pid

    info = { pid: pid, server_ips: local_ipv4 }
    info[:cmdline] = File.read("/proc/#{pid}/cmdline").tr("\0", ' ')

    socks = listen_sockets(pid)

    # Game port: listening UDP (prefer wildcard bind).
    udp = socks[:udp]
    game = udp.find { |s| s[:ip] == '0.0.0.0' || s[:ip] == '::' } || udp.first
    info[:game_port] = game[:port] if game

    # RCON port: listening TCP (prefer loopback bind).
    tcp = socks[:tcp]
    rcon = tcp.find { |s| s[:ip] =~ /^127\./ || s[:ip] == '::1' } || tcp.first
    info[:rcon_port] = rcon[:port] if rcon

    # RCON host/password from cmdline args (authoritative when present).
    if info[:cmdline] =~ /--rcon-bind\s+(\S+)/
      host, port = $1.split(':')
      info[:rcon_host] = host if host
      info[:rcon_port] = port.to_i if port
    end
    info[:rcon_password] = $1 if info[:cmdline] =~ /--rcon-password\s+(\S+)/

    # Dedicated server? --start-server / --rcon-* / --server-settings etc.
    # are dedicated-only; --start-server-load-* / --map-* also exist in the
    # full client (usually to host) so they only count as "hosting".
    info[:dedicated_flags] = matching_flags(info[:cmdline], DEDICATED_ONLY_FLAGS)
    info[:hosting_flags] = matching_flags(info[:cmdline], CLIENT_ALSO_FLAGS)
    info[:dedicated] = !info[:dedicated_flags].empty?

    # Is this process actually SERVING a game (vs a plain client)?
    # Dedicated/hosting flags are proof; a wildcard-bound listening UDP
    # socket also counts (covers games hosted from the in-game client,
    # which has no server flags). A plain client connects to a remote
    # address instead (its socket shows a rem_address / connected state).
    info[:wildcard_udp] = udp.any? { |s| s[:ip] == '0.0.0.0' || s[:ip] == '::' }
    info[:serving] = serving?(info)

    info
  end

  # True when the info hash describes a process that is serving a game.
  def self.serving?(info)
    return false if info.nil? || info.empty?
    return true if info[:dedicated]
    return true if info[:hosting_flags]&.any?
    return true if info[:wildcard_udp]
    false
  end
end
