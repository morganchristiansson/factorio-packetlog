# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'pcap'

class TestPcapWriter < Minitest::Test
  def test_reader_round_trips_plain_and_gzip_with_original_frame
    [false, true].each do |gzip|
      Dir.mktmpdir do |dir|
        path = File.join(dir, "capture#{gzip ? '.pcap.gz' : '.pcap'}")
        frame = udp_frame('10.0.0.1', '10.0.0.2', 34_197, 34_198, "\x10hello".b)
        writer = PcapWriter.new(path, gzip: gzip)
        writer.write_frame(frame, Time.at(123, 456_000))
        writer.close

        rows = []
        PcapReader.new(path).each_packet { |*args| rows << args }
        assert_equal 1, rows.size
        assert_equal 123.456, rows[0][1]
        assert_equal '10.0.0.1', rows[0][2]
        assert_equal '10.0.0.2', rows[0][3]
        assert_equal 34_197, rows[0][4]
        assert_equal 34_198, rows[0][5]
        assert_equal "\x10hello".b, rows[0][6]
        assert_equal frame, rows[0][7]
      end
    end
  end

  def test_buffered_plain_and_gzip_writes_rotate_and_close_without_threads
    [false, true].each do |gzip|
      Dir.mktmpdir do |dir|
        writer = PcapWriter.new("#{dir}/capture#{gzip ? '.gz' : '.pcap'}", gzip: gzip,
                                timestamped: true, rotate_size: 1)
        writer.instance_variable_set(:@rotate_bytes, 60)
        first = writer.path
        writer.write_frame('x' * 20, Time.at(123))
        writer.write_frame('y' * 20, Time.at(124))
        second = writer.path
        refute_equal first, second
        refute writer.instance_variable_defined?(:@flush_thread)
        writer.close
        writer.close
        [first, second].zip(%w[x y]).each do |path, char|
          bytes = gzip ? Zlib::GzipReader.open(path, &:read).b : File.binread(path)
          assert_equal 60, bytes.bytesize
          assert_equal [0xd4, 0xc3, 0xb2, 0xa1], bytes.bytes.first(4)
          assert_equal char * 20, bytes[40..]
          assert_equal [20, 20], bytes[32, 8].unpack('VV')
        end
        empty = PcapWriter.new("#{dir}/empty", gzip: gzip, timestamped: true)
        empty.close
        refute File.exist?(empty.path)
      end
    end
  end

  def test_max_size_prunes_oldest_rotated_files
    Dir.mktmpdir do |dir|
      writer = PcapWriter.new("#{dir}/capture.pcap", timestamped: true, rotate_size: 1, max_size: 1)
      writer.instance_variable_set(:@rotate_bytes, 60) # rotate every 2 frames
      writer.write_frame('x' * 20, Time.at(123))
      first = writer.path
      sleep 0.01
      writer.write_frame('y' * 20, Time.at(124))
      second = writer.path
      # The rotated file holds ~60 B (the active one is still buffered):
      # shrink the 1MB budget below that and the oldest file falls out.
      writer.instance_variable_set(:@max_size_bytes, 40)
      writer.send(:prune_rotated)
      refute File.exist?(first), 'oldest rotated file deleted (over max_size total)'
      assert File.exist?(second), 'newest rotated file kept'
      assert File.exist?(writer.path), 'active file never pruned'
      writer.close
    end
  end

  private

  def udp_frame(src, dst, sport, dport, payload)
    ip = "\x45\x00" + [20 + 8 + payload.bytesize].pack('n') + "\x00\x00\x00\x00\x40\x11\x00\x00" +
         src.split('.').map(&:to_i).pack('C4') + dst.split('.').map(&:to_i).pack('C4')
    ("\x00" * 12 + [0x0800].pack('n')) + ip + [sport, dport, 8 + payload.bytesize, 0].pack('nnnn') + payload
  end
end
