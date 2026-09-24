# frozen_string_literal: true

require 'zlib'
require 'stringio'
require 'tempfile'
require 'fileutils'

# PCAP Writer (for saving live capture)
# ─────────────────────────────────────────────────────────────────────
class PcapWriter
  attr_reader :path

  # gzip: true = write the stream gzip-compressed (use a .gz path).
  # keep: rolling retention in HOURS — rotate the capture every hour and
  #   delete files older than `keep` hours. nil = keep everything.
  # max_size: rotate a capture file when it exceeds this size (MB) and
  #   prune files so TOTAL size stays ≤ max_size.
  # timestamped: write straight to a timestamped file
  #   (`base-<YYYYMMDD-HHMMSS>.pcap`) — the latest file IS the live one,
  #   no renames, no stable path. Restarts just open a new file. Used for
  #   both the normal capture and the small unknown-packet capture.
  def initialize(path, gzip: false, keep: nil, max_size: nil, timestamped: false)
    @base_path = path
    @timestamped = timestamped
    @gzip = gzip
    @keep_hours = keep
    @max_size_bytes = max_size ? max_size * 1024 * 1024 : nil
    @start_time = Time.now
    @file_start = Time.now
    if timestamped
      @path = unique_timestamped_path(Time.now)
    else
      @path = path
      rotate_on_restart  # never silently destroy the previous run's capture
    end
    @file = open_file(@path)
    write_global_header
    # Ruby IO (or GzipWriter) and the kernel buffer writes. No per-record
    # flush/fsync; close on rotation/shutdown finalizes the buffered stream.
  end

  # Write a real captured Ethernet frame as-is (fast path for live capture;
  # avoids rebuilding fake IP/UDP headers per packet).
  def write_frame(frame, ts = Time.now)
    write_record(ts, frame)
  end

  def close
    return unless @file
    @file.close
    @file = nil
    # Logical bytes also identify an empty gzip stream correctly.
    File.delete(@path) if @timestamped && @bytes_written == 24 && File.exist?(@path)
  end

  private

  def open_file(path)
    io = File.open(path, 'wb')
    @gzip ? Zlib::GzipWriter.new(io) : io
  end

  def write_record(ts, data)
    return unless data
    ts_sec = ts.to_i
    ts_usec = ((ts.to_f - ts_sec) * 1_000_000).to_i
    hdr = [ts_sec, ts_usec, data.bytesize, data.bytesize].pack('VVVV')
    return unless @file
    rotate_if_due
    @file.write(hdr + data.b)
    @bytes_written += hdr.bytesize + data.bytesize
  end

  # If @path already holds a capture (previous run / restart), rename it
  # with a timestamp instead of overwriting — history is preserved.
  # Header-only files (24-byte pcap global header, zero packets — e.g. a
  # seconds-long run) carry nothing worth preserving: delete instead of
  # renaming, so restarts don't accumulate 4K timestamped clutter.
  def rotate_on_restart
    return unless File.exist?(@path)
    if File.size(@path) <= 24
      File.delete(@path)
      return
    end
    finished = timestamped_path(File.mtime(@path).strftime('%Y%m%d-%H%M%S'))
    finished = timestamped_path(Time.now.strftime('%Y%m%d-%H%M%S')) if File.exist?(finished)
    File.rename(@path, finished)
    prune_rotated
  end

  # Hourly and/or size-based rotation + retention: close the finished
  # file and open a fresh timestamped one (timestamped mode — nothing to
  # rename; the finished file's name was final from the start), then prune
  # beyond the retention bounds. Single owner: the capture thread.
  # Size rotation counts uncompressed bytes, including buffered data; for
  # gzip this is conservative. Retention still counts actual file sizes.
  def rotate_if_due
    due = @keep_hours && (Time.now - @file_start) >= 3600
    if @max_size_bytes
      due = true if @bytes_written >= @max_size_bytes
    end
    return unless due
    @file.close
    @file = nil
    if @timestamped
      @path = unique_timestamped_path(Time.now)
    else
      finished = timestamped_path(@file_start.strftime('%Y%m%d-%H%M%S'))
      File.rename(@path, finished) if File.exist?(@path)
    end
    @file = open_file(@path)
    write_global_header
    @file_start = Time.now
    prune_rotated
  end

  # Pcap global header on every freshly opened file (init AND rotation —
  # the old code forgot the rotation case, leaving headerless files).
  def write_global_header
    @bytes_written = 24
    # Written directly (avoids pack issues)
    @file.write([0xd4, 0xc3, 0xb2, 0xa1].pack('C4'))  # magic LE
    @file.write([2, 4].pack('v2'))  # version
    @file.write([0, 0].pack('V2'))  # timezone, sigfigs
    @file.write([65535].pack('V'))   # snaplen
    @file.write([1].pack('V'))       # linktype = Ethernet
  end

  def timestamped_path(ts)
    suffix = if @base_path.end_with?('.pcap.gz')
               '.pcap.gz'
             else
               File.extname(@base_path)
             end
    stem = @base_path[0...-suffix.length]
    "#{stem}-#{ts}#{suffix}"
  end

  # First free `base-<ts>.pcap` at or after `time` (same-second restarts
  # must not collide).
  def unique_timestamped_path(time)
    t = time
    loop do
      cand = timestamped_path(t.strftime('%Y%m%d-%H%M%S'))
      return cand unless File.exist?(cand)
      t += 1
    end
  end

  # Delete rotated files beyond the retention bounds: older than `keep`
  # hours, and — when max_size is set — the OLDEST files until total
  # rotated size is ≤ max_size.
  def prune_rotated
    rotated = rotated_files
    if @keep_hours
      cutoff = Time.now - (@keep_hours * 3600)
      rotated.each do |f|
        if File.mtime(f) < cutoff
          puts "retention: deleted #{f} (older than #{@keep_hours}h)"
          File.delete(f)
        end
      end
      rotated = rotated_files
    end
    if @max_size_bytes
      total = rotated.sum { |f| File.size(f) }
      rotated.sort_by { |f| File.mtime(f) }.each do |f|
        break if total <= @max_size_bytes
        total -= File.size(f)
        puts "retention: deleted #{f} (over #{@max_size_bytes / 1024 / 1024}MB total)"
        File.delete(f)
      end
    end
  rescue Errno::ENOENT
    # file vanished between glob and delete
  end

  def rotated_files
    ext = File.extname(@base_path)
    stem = File.basename(@base_path, ext)
    Dir.glob(File.join(File.dirname(@base_path), "#{stem}-*#{ext}")) - [@path]
  end

end

# PCAP Reader
# ─────────────────────────────────────────────────────────────────────
class PcapReader
  def initialize(path)
    @path = path
  end

  def each_packet
    if gzip?
      Tempfile.create(['factorio-pcap', '.pcap']) do |file|
        file.binmode
        file.write(gunzip_best_effort(File.binread(@path)))
        file.flush
        read_capture(file.path) { |*args| yield(*args) }
      end
    else
      read_capture(@path) { |*args| yield(*args) }
    end
  end

  private

  def gzip?
    raw = File.binread(@path, 2)
    raw.getbyte(0) == 0x1f && raw.getbyte(1) == 0x8b
  end

  # Decompress what is available when a live gzip capture has no trailer yet.
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

  def read_capture(path)
    old_verbose = $VERBOSE
    $VERBOSE = nil
    require 'pcaprub'
    capture = PCAPRUB::Pcap.open_offline(path)
    header_size = case capture.datalink
                 when PCAPRUB::Pcap::DLT_NULL then 4
                 when PCAPRUB::Pcap::DLT_EN10MB then 14
                 when PCAPRUB::Pcap::DLT_LINUX_SLL then 16
                 else 0
                 end
    pkt_num = 0
    capture.each_packet do |packet|
      pkt_num += 1
      frame = packet.data
      raw = frame[header_size..]
      next if raw.nil? || raw.bytesize < 28 || raw.getbyte(9) != 17

      ihl = (raw.getbyte(0) & 0x0f) * 4
      next if raw.bytesize < ihl + 8
      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.empty?

      yield(pkt_num, packet.time + packet.microsec / 1_000_000.0,
            raw[12..15].bytes.join('.'), raw[16..19].bytes.join('.'),
            raw.unpack1('n', offset: ihl), raw.unpack1('n', offset: ihl + 2),
            udp_data, frame)
    end
  ensure
    capture&.close
    $VERBOSE = old_verbose
  end
end
