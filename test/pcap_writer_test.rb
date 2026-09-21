# frozen_string_literal: true
require 'minitest/autorun'
require 'tmpdir'
require 'pcap'

class TestPcapWriter < Minitest::Test
  def test_buffered_plain_and_gzip_writes_rotate_and_close_without_threads
    [false, true].each do |gzip|
      Dir.mktmpdir do |dir|
        writer = PcapWriter.new("#{dir}/capture#{gzip ? '.gz' : '.pcap'}", gzip: gzip,
                                timestamped: true, max_size: 1)
        writer.instance_variable_set(:@max_size_bytes, 60)
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
end
