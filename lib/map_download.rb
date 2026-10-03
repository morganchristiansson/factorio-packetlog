# frozen_string_literal: true

# Map-download reassembly from the LIVE stream (client mode).
#
# On join, the server streams its whole save as TransferBlock (msg 13)
# packets: `[u8 msg=13][u32 block number][503 bytes]`, and blocks 0..N
# concatenated are the save archive — the same file
# tools/extract_save_from_pcap.rb rebuilds offline. That save carries the
# FULL roster, which is the one thing a client cannot learn any other way: the
# wire only ever shows the players who join after us. So we seed
# players-cache.json from it.
#
# NOTHING heavy happens on the capture thread: the download bursts at ~20k
# pps and blocking there is what overflowed the kernel buffer before. #add_block
# is one hash store under a mutex; a worker thread waits for the stream to go
# quiet, concatenates the blocks and hands the archive to the roster tool.
#
# Server mode does not use this at all — the server has the save on disk and
# RCON is authoritative.
class MapDownload
  BLOCK_SIZE = 503
  # Seconds without a block before we call the download finished. The last
  # block of a download is followed by silence, and a partial download is
  # harmless (see #process).
  QUIET_SECONDS = 5.0
  # Sanity bound: 200k blocks = 100 MB, far above any real save (41 MB).
  MAX_BLOCKS = 200_000

  attr_reader :blocks_seen, :downloads

  def initialize(dir:, quiet: QUIET_SECONDS, &on_complete)
    @dir = dir
    @quiet = quiet
    @on_complete = on_complete
    @blocks = {}
    @mutex = Mutex.new
    @cv = ConditionVariable.new
    @blocks_seen = 0
    @downloads = 0
    @thread = Thread.new { work }
  end

  # Called from the capture thread — keep it to a hash store.
  def add_block(number, payload)
    @mutex.synchronize do
      return if @blocks.size >= MAX_BLOCKS
      return if @blocks.key?(number) # a retransmit; keep the first copy
      @blocks[number] = payload
      @blocks_seen += 1
      @last_at = monotonic
      @cv.signal
    end
  end

  def stop
    @thread&.kill
  end

  private

  def monotonic
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  def work
    loop do
      blocks = take_download
      next unless blocks
      begin
        process(blocks)
      rescue StandardError => e
        # One bad download must not kill the reassembler for the session.
        warn "[map-download] reassembly failed: #{e.class}: #{e.message}"
      end
    end
  end

  # Block until a download has gone quiet, then take it. nil = keep waiting.
  def take_download
    @mutex.synchronize do
      @cv.wait(@mutex) while @blocks.empty?
      until @blocks.empty?
        left = @quiet - (monotonic - @last_at)
        break if left <= 0
        @cv.wait(@mutex, left)
      end
      next if @blocks.empty?
      taken = @blocks
      @blocks = {}
      taken
    end
  end

  # Concatenate and hand over. A download with holes in it is not a usable
  # archive (the zip central directory lives at the end), so we skip it and
  # say so rather than seeding a roster from a broken file.
  def process(blocks)
    numbers = blocks.keys.sort
    missing = numbers.first.upto(numbers.last).reject { |bn| blocks.key?(bn) }
    if missing.any?
      warn "[map-download] #{blocks.size} blocks, #{missing.size} missing (e.g. #{missing.first(3).inspect}) " \
           '— capture loss, roster not seeded'
      return
    end
    path = File.join(@dir, "map-download-#{Time.now.strftime('%Y%m%d-%H%M%S')}.zip")
    File.binwrite(path, numbers.map { |bn| blocks[bn] }.join)
    @downloads += 1
    @on_complete&.call(path, blocks.size)
  end
end
