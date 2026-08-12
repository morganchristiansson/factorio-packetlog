# frozen_string_literal: true

# PCAP Writer (for saving live capture)
# ─────────────────────────────────────────────────────────────────────
class PcapWriter
  def initialize(path)
    @path = path
    @file = File.open(path, 'wb')
    # Write pcap global header directly (avoids pack issues)
    @file.write([0xd4, 0xc3, 0xb2, 0xa1].pack('C4'))  # magic LE
    @file.write([2, 4].pack('v2'))  # version
    @file.write([0, 0].pack('V2'))  # timezone, sigfigs
    @file.write([65535].pack('V'))   # snaplen
    @file.write([1].pack('V'))       # linktype = Ethernet
    @start_time = Time.now
    # Buffered writes flushed by a BACKGROUND thread: the capture loop only
    # appends to the buffer (fast, non-blocking). Flushing on the capture
    # thread stalls it on disk I/O (the workspace is a Docker bind mount),
    # which overflowed the kernel capture buffer during map downloads.
    @mutex = Mutex.new
    @buf = +''.b
    @closed = false
    @flush_thread = Thread.new { flush_loop }
  end

  def write_packet(ip_payload)
    write_record(Time.now, ip_payload)
  end

  # Write a real captured Ethernet frame as-is (fast path for live capture;
  # avoids rebuilding fake IP/UDP headers per packet).
  def write_frame(frame, ts = Time.now)
    write_record(ts, frame)
  end

  def close
    @closed = true
    @flush_thread.join(2)
    @mutex.synchronize do
      @file.write(@buf) unless @buf.empty?
      @buf = +''.b
    end
    @file.close if @file
  end

  private

  def write_record(ts, data)
    ts_sec = ts.to_i
    ts_usec = ((ts.to_f - ts_sec) * 1_000_000).to_i
    hdr = [ts_sec, ts_usec, data.bytesize, data.bytesize].pack('VVVV')
    @mutex.synchronize { @buf << hdr << data.b }
  end

  def flush_loop
    until @closed
      sleep 0.2
      chunk = @mutex.synchronize do
        c = @buf
        @buf = +''.b
        c
      end
      @file.write(chunk) unless chunk.empty?
    end
  rescue IOError
    # file closed
  end
end

# PCAP Reader
# ─────────────────────────────────────────────────────────────────────
class PcapReader
  def initialize(path)
    @path = path
  end

  def each_packet(&block)
    data = File.binread(@path)
    magic = data.unpack1('V')
    endian = (magic == 0xa1b2c3d4) ? :little : :big
    raise "Not a pcap file" unless [:little, :big].include?(endian)

    gh = data.unpack(endian == :little ? 'VvvVVVV' : 'NnnNNNN')
    linktype = gh[6]
    pkt_num = 0

    offset = 24
    while offset + 16 <= data.bytesize
      ph = data.unpack(endian == :little ? 'VVVV' : 'NNNN', offset: offset)
      ts_sec, ts_usec, incl_len, _ = ph
      offset += 16
      break if offset + incl_len > data.bytesize
      pkt_data = data[offset, incl_len]
      offset += incl_len
      pkt_num += 1

      # Strip link layer
      raw = case linktype
      when 1 then pkt_data[14..]
      when 0 then pkt_data[4..]
      when 113 then pkt_data[16..]
      else pkt_data
      end
      next if raw.nil? || raw.bytesize < 28

      # Parse IP + UDP
      ihl = (raw.getbyte(0) & 0x0F) * 4
      next unless raw.getbyte(9) == 17  # UDP only
      next if raw.bytesize < ihl + 8

      sport = raw.unpack1('n', offset: ihl)
      dport = raw.unpack1('n', offset: ihl + 2)
      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.bytesize < 1

      src_ip = raw[12..15].bytes.join('.')
      dst_ip = raw[16..19].bytes.join('.')

      yield(pkt_num, ts_sec + ts_usec / 1_000_000.0,
            src_ip, dst_ip, sport, dport, udp_data)
    end
  end
end
