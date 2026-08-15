# frozen_string_literal: true

require 'zlib'
require 'stringio'
require 'fileutils'

# PCAP Writer (for saving live capture)
# ─────────────────────────────────────────────────────────────────────
class PcapWriter
  attr_reader :path

  # gzip: true = write the stream gzip-compressed (use a .gz path).
  # keep: rolling retention in HOURS — rotate the capture every hour
  #   (renaming the finished file with a timestamp) and delete rotated
  #   files older than `keep` hours. nil = single file, keep everything.
  # max_size: rotate a capture file when it exceeds this size (MB) and
  #   prune rotated files so TOTAL rotated size stays ≤ max_size.
  # Restarts: a pre-existing capture at `path` is renamed with a
  #   timestamp on open instead of being overwritten.
  def initialize(path, gzip: false, keep: nil, max_size: nil)
    @path = path
    @gzip = gzip
    @keep_hours = keep
    @max_size_bytes = max_size ? max_size * 1024 * 1024 : nil
    @start_time = Time.now
    @file_start = Time.now
    rotate_on_restart  # never silently destroy the previous run's capture
    @file = open_file(@path)
    # Write pcap global header directly (avoids pack issues)
    @file.write([0xd4, 0xc3, 0xb2, 0xa1].pack('C4'))  # magic LE
    @file.write([2, 4].pack('v2'))  # version
    @file.write([0, 0].pack('V2'))  # timezone, sigfigs
    @file.write([65535].pack('V'))   # snaplen
    @file.write([1].pack('V'))       # linktype = Ethernet
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
      @file.close if @file
      @file = nil
    end
  end

  private

  def open_file(path)
    io = File.open(path, 'wb')
    @gzip ? Zlib::GzipWriter.new(io) : io
  end

  def write_record(ts, data)
    ts_sec = ts.to_i
    ts_usec = ((ts.to_f - ts_sec) * 1_000_000).to_i
    hdr = [ts_sec, ts_usec, data.bytesize, data.bytesize].pack('VVVV')
    @mutex.synchronize do
      return if @closed || @file.nil?
      rotate_if_due
      @buf << hdr << data.b
    end
  end

  # If @path already holds a capture (previous run / restart), rename it
  # with a timestamp instead of overwriting — history is preserved.
  def rotate_on_restart
    return unless File.exist?(@path) && File.size(@path) > 0
    finished = timestamped_path(File.mtime(@path).strftime('%Y%m%d-%H%M%S'))
    finished = timestamped_path(Time.now.strftime('%Y%m%d-%H%M%S')) if File.exist?(finished)
    File.rename(@path, finished)
    prune_rotated
  end

  # Hourly and/or size-based rotation + retention: flush/close the
  # finished active file, rename it with a timestamp, open a fresh one,
  # prune rotated files beyond the retention bounds. Runs under the write
  # mutex (once per hour / per size threshold — a few ms of disk I/O on
  # the capture thread is negligible off-burst).
  def rotate_if_due
    due = @keep_hours && (Time.now - @file_start) >= 3600
    if @max_size_bytes
      sz = (File.size(@path) rescue 0) + @buf.bytesize
      due = true if sz >= @max_size_bytes
    end
    return unless due
    @file.write(@buf) unless @buf.empty?
    @buf = +''.b
    @file.close
    @file = nil
    finished = timestamped_path(@file_start.strftime('%Y%m%d-%H%M%S'))
    File.rename(@path, finished) if File.exist?(@path)
    @file = open_file(@path)
    @file_start = Time.now
    prune_rotated
  end

  def timestamped_path(ts)
    ext = File.extname(@path)
    "#{@path[0...-ext.length]}-#{ts}#{ext}"
  end

  # Delete rotated files beyond the retention bounds: older than `keep`
  # hours, and — when max_size is set — the OLDEST files until total
  # rotated size is ≤ max_size.
  def prune_rotated
    rotated = rotated_files
    if @keep_hours
      cutoff = Time.now - (@keep_hours * 3600)
      rotated.each { |f| File.delete(f) if File.mtime(f) < cutoff }
      rotated = rotated_files
    end
    if @max_size_bytes
      total = rotated.sum { |f| File.size(f) }
      rotated.sort_by { |f| File.mtime(f) }.each do |f|
        break if total <= @max_size_bytes
        total -= File.size(f)
        File.delete(f)
      end
    end
  rescue Errno::ENOENT
    # file vanished between glob and delete
  end

  def rotated_files
    ext = File.extname(@path)
    stem = File.basename(@path, ext)
    Dir.glob(File.join(File.dirname(@path), "#{stem}-*#{ext}"))
  end

  def flush_loop
    until @closed
      sleep 0.2
      @mutex.synchronize do
        next if @buf.empty? || @file.nil?
        chunk = @buf
        @buf = +''.b
        @file.write(chunk)
      end
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

  private

  # Decompress a gzip stream, tolerating a missing trailer (capture being
  # written concurrently): return everything that decompresses.
  def gunzip_best_effort(raw)
    out = +''.b
    gz = Zlib::GzipReader.new(StringIO.new(raw))
    loop { out << gz.readpartial(1 << 20) }
    out
  rescue EOFError
    out
  rescue Zlib::GzipFile::Error => e
    warn "Warning: gzip stream incomplete (#{e.message}); using #{out.bytesize} decompressed bytes"
    out
  end

  public

  def each_packet(&block)
    raw = File.binread(@path)
    # Gzip-autodetect: [0x1f 0x8b] magic → gunzip in memory (keeps all
    # downstream tools — extract_save_from_pcap, analysis — working on
    # compressed captures unchanged). A gz file being written concurrently
    # has no trailer yet; read what decompresses and warn on truncation.
    data =
      if raw.bytesize >= 2 && raw.getbyte(0) == 0x1f && raw.getbyte(1) == 0x8b
        gunzip_best_effort(raw)
      else
        raw
      end

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
