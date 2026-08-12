# frozen_string_literal: true

# Live Capture (pcaprub)
# ─────────────────────────────────────────────────────────────────────
class LiveCapture
  def initialize(interface:, port:, bpf: nil, transfer_block_sink: nil)
    @interface = interface
    @port = port
    @bpf = bpf || (port ? "udp port #{port}" : 'udp')
    @last_drop_report = 0
    # Optional sink for map-download TransferBlocks: when set, transfer
    # frames are written straight here (e.g. the pcap writer) and skipped
    # from the parse pipeline entirely.
    @transfer_block_sink = transfer_block_sink
  end

  def self.list_interfaces
    require 'socket'
    Socket.getifaddrs.select { |a| a.addr&.ip? }.map { |a| a.name }.uniq
  rescue => e
    puts "Failed to list interfaces: #{e}"
    ['(none found)']
  end

  # Report libpcap kernel-buffer drops so capture loss is visible instead
  # of silently corrupting the session. stats => { 'recv' =>, 'drop' =>,
  # 'idrop' => }. 'drop' = packets the kernel buffer overflowed (the
  # capture loop was too slow); 'idrop' = dropped by the interface.
  def report_drops(cap, force: false)
    st = cap.stats
    return unless st.is_a?(Hash)
    drop = st['drop'].to_i
    idrop = st['idrop'].to_i
    return if drop.zero? && idrop.zero?
    return if !force && drop - @last_drop_report < 1000
    @last_drop_report = drop
    msg = +"[capture] kernel buffer drops: #{drop}"
    msg << " (interface: #{idrop})" if idrop > 0
    msg << " — capture can't keep up; use tcpdump for lossless capture" if drop > 0
    puts msg
  end

  def each_packet(&block)
    require 'pcaprub'

    # pcaprub 0.13.3 emits a one-time cosmetic "undefining the allocator of
    # T_DATA class" warning on the first open_live (Ruby 3.2 data-object
    # machinery + pcaprub's old-style Data_Make_Struct). Capture works fine;
    # silence it.
    old_verbose = $VERBOSE
    $VERBOSE = nil
    begin
      cap = PCAPRUB::Pcap.open_live(@interface, 65535, true, 1000)
    ensure
      $VERBOSE = old_verbose
    end
    cap.setfilter(@bpf)

    pkt_num = 0

    # Blocking batch read: pcaprub's each_data loops on pcap_dispatch and
    # waits on the capture fd when the buffer is empty (rb_thread_wait_fd).
    # This drains the kernel buffer continuously — the old next()+sleep(0.01)
    # poll let the kernel buffer overflow during map-download bursts
    # (~20k pps), silently dropping blocks.
    cap.each_data do |pkt|
      # Parse Ethernet header
      next if pkt.bytesize < 14
      eth_type = pkt.unpack1('n', offset: 12)
      next unless eth_type == 0x0800  # IPv4 only for now

      ihl = (pkt.getbyte(14) & 0x0F) * 4
      next if pkt.bytesize < 14 + ihl + 8

      # Fast path: map-download TransferBlocks (msg 13) need no parsing at
      # all — persist the frame if saving and skip the full yield/parse
      # pipeline (the bottleneck that overflowed the buffer before).
      if (pkt.getbyte(14 + ihl + 8) & 0x1F) == 13
        if @transfer_block_sink
          @transfer_block_sink.write_frame(pkt)
        end
        next
      end

      raw = pkt[14..]
      next if raw.nil? || raw.bytesize < 20

      ihl = (raw.getbyte(0) & 0x0F) * 4
      next if raw.bytesize < ihl + 8 || raw.getbyte(9) != 17

      sport = raw.unpack1('n', offset: ihl)
      dport = raw.unpack1('n', offset: ihl + 2)
      next if @port && sport != @port && dport != @port

      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.bytesize < 1

      ts = Time.now.to_f
      pkt_num += 1
      yield(pkt_num, ts,
            raw[12..15].bytes.join('.'),
            raw[16..19].bytes.join('.'),
            sport, dport, udp_data, pkt)

      # Surface capture loss early (report when it jumps by >= 1000)
      report_drops(cap) if pkt_num % 50_000 == 0
    end
  rescue PCAPRUB::PCAPRUBError => e
    puts "Capture error: #{e}"
    puts "Available interfaces: #{self.class.list_interfaces.join(', ')}"
  rescue Interrupt
    # Propagate so the entry point can decide between hot reload and quit.
    raise
  ensure
    report_drops(cap, force: true) if cap
  end
end
