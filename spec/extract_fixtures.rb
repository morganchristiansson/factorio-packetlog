#!/usr/bin/env ruby
# Extract real packet blobs from the pcap for use as test fixtures.
# Run: ruby -Ilib spec/extract_fixtures.rb

require 'fileutils'
require_relative '../lib/factorio_protocol'

FIXTURE_DIR = File.join(__dir__, 'fixtures')
FileUtils.mkdir_p(FIXTURE_DIR)

class PcapReader
  def initialize(path)
    @path = path
  end

  def each_packet(&block)
    data = File.binread(@path)
    magic = data.unpack1('V')
    endian = (magic == 0xa1b2c3d4) ? :little : :big
    raise 'Not a pcap file' unless %i[little big].include?(endian)
    gh = data.unpack(endian == :little ? 'VvvVVVV' : 'NnnNNNN')
    linktype = gh[6]
    pkt_num = 0
    offset = 24
    while offset + 16 <= data.bytesize
      ph = data.unpack(endian == :little ? 'VVVV' : 'NNNN', offset: offset)
      _ts_sec, _ts_usec, incl_len, _orig_len = ph
      offset += 16
      break if offset + incl_len > data.bytesize
      pkt_data = data[offset, incl_len]
      offset += incl_len
      pkt_num += 1
      raw = case linktype
            when 1 then pkt_data[14..]
            when 0 then pkt_data[4..]
            when 113 then pkt_data[16..]
            else pkt_data
            end
      next if raw.nil? || raw.bytesize < 28
      ihl = (raw.getbyte(0) & 0x0F) * 4
      next unless raw.getbyte(9) == 17
      next if raw.bytesize < ihl + 8
      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      yield(pkt_num, udp_data)
    end
  end
end

def save_fixture(name, udp_data, description)
  path = File.join(FIXTURE_DIR, "#{name}.bin")
  File.binwrite(path, udp_data)
  # Also save a text description
  desc_path = File.join(FIXTURE_DIR, "#{name}.txt")
  File.write(desc_path, description)
  puts "  Saved #{name}.bin (#{udp_data.bytesize} bytes)"
end

puts "Extracting fixtures from pcap..."

types_found = Hash.new(0)

PcapReader.new('factorio_capture.pcap').each_packet do |pkt_num, udp_data|
  parsed = FactorioProtocol.parse_udp_payload(udp_data)
  next unless parsed
  hdr = parsed[:header]

  # Collect stats on what we find
  types_found[hdr[:msg_name]] += 1
  next unless (hb = parsed[:heartbeat])

  hb[:tick_closures]&.each do |tc|
    tc[:actions]&.each do |act|
      collected = false

      # Deconstruct with area (expect 16 bytes)
      if act[:name] == 'deconstruct' && act[:data]&.bytesize.to_i >= 16 && !collected
        x1 = act[:data].unpack1('i', offset: 0)
        y1 = act[:data].unpack1('i', offset: 4)
        x2 = act[:data].unpack1('i', offset: 8)
        y2 = act[:data].unpack1('i', offset: 12)
        desc = <<~DESC.chomp
          Deconstruct area selection (type 131)
          Player: #{act[:game_player]} (delta #{act[:delta]})
          Area: (#{format('%.3f', x1 / 256.0)}, #{format('%.3f', y1 / 256.0)})-
                (#{format('%.3f', x2 / 256.0)}, #{format('%.3f', y2 / 256.0)})
          Source packet: #{pkt_num}
        DESC
        save_fixture('deconstruct_area', udp_data, desc)
        collected = true
      end

      # Build with position
      if act[:name] == 'build' && act[:data]&.bytesize.to_i >= 9 && !collected
        bx = act[:data].unpack1('i', offset: 0)
        by = act[:data].unpack1('i', offset: 4)
        dir = act[:data].getbyte(8)
        desc = <<~DESC.chomp
          Build entity (type 68)
          Player: #{act[:game_player]}
          Pos: (#{format('%.3f', bx / 256.0)}, #{format('%.3f', by / 256.0)}) dir=#{dir}
          Source packet: #{pkt_num}
        DESC
        save_fixture('build_action', udp_data, desc)
        collected = true
      end

      # Chat message (write_to_console)
      if act[:name] == 'write_to_console' && act[:data]&.bytesize.to_i >= 3 && !collected
        d = act[:data]
        marker_names = { 0x05 => 'segment', 0x3d => 'server_echo_3d',
                         0x01 => 'server_echo_01', 0x04 => 'non_segment' }
        marker = marker_names[d.getbyte(0)] || 'raw'
        # Truncate very long messages
        text_preview = d.bytesize > 50 ? "#{d[2..51].inspect}..." : d[2..-1].inspect
        desc = <<~DESC.chomp
          Chat: write_to_console (type 106) format=#{marker}
          Player: #{act[:game_player]}
          Data preview: #{text_preview}
          Source packet: #{pkt_num}
        DESC
        name = "chat_#{marker}"
        # Only save one of each chat format
        unless File.exist?(File.join(FIXTURE_DIR, "#{name}.bin"))
          save_fixture(name, udp_data, desc)
        end
        collected = true
      end

      # Server heartbeat with multiple actions (to test metadata filtering)
      if tc[:actions]&.size.to_i >= 2 && !collected
        names = tc[:actions].map { |a| a[:name] }
        # Prefer deconstruct as first action, but any multi-action is useful
        if names[0] == 'deconstruct'
          desc = <<~DESC.chomp
            Multi-action server heartbeat (first=#{names[0]})
            Actions: #{names.join(', ')}
            Players: #{tc[:actions].map { |a| a[:game_player] }.join(', ')}
            Source packet: #{pkt_num}
          DESC
          save_fixture('multi_action_server_tc', udp_data, desc)
          collected = true
        end
      end

      break if collected  # stop scanning after we have enough
    end
  end
end

puts "\nMessage type distribution:"
types_found.sort_by { |_, v| -v }.each { |k, v| puts "  #{k}: #{v}" }
puts "\nFixtures saved to #{FIXTURE_DIR}/"
Dir[File.join(FIXTURE_DIR, '*.bin')].each do |f|
  size = File.size(f)
  puts "  #{File.basename(f)} (#{size} bytes)"
end
