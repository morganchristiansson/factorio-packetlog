#!/usr/bin/env ruby
# Census of unidentified protocol content across capture sets.
#
#   ruby tools/identify_unknowns.rb PCAP... [PCAP...]
#
# For every input action the decoder cannot name or cannot length, prints the
# type with its count, example payload sizes and example ticks, so the same
# wire type can be found by tick in the /toggle-action-logging log and named.
# Also reports heartbeats that failed to parse. Defaults to the project's own
# capture corpus (observer sessions, the C→S server captures, handshake arcs).
require_relative '../lib/factorio_protocol'
require_relative '../lib/pcap'
require 'set'

FILES = if ARGV.empty?
          Dir['../captures/server-34197-*.pcap.gz'] + Dir['../handshake*.pcap']
        else
          ARGV.dup
        end

actions = Hash.new { |h, k| h[k] = { count: 0, bytes: {}, ticks: [], files: Set.new } }
hb_fail = Hash.new { |h, k| h[k] = { count: 0, files: Set.new } }

FILES.each do |path|
  next unless File.exist?(path)
  begin
    PcapReader.new(path).each_packet do |_n, _ts, _src, _dst, sport, _dport, data, _f|
      hdr = FactorioProtocol.parse_network_header(data)
      next unless hdr
      t = hdr[:msg_type]
      next unless t == 6 || t == 7
      parsed = (FactorioProtocol.parse_udp_payload(data) rescue nil)
      hb = parsed && parsed[:heartbeat]
      unless hb && hb[:tick_closures]
        hb_fail[t][:count] += 1
        hb_fail[t][:files] << File.basename(path)
        next
      end
      hb[:tick_closures].each do |tc|
        (tc[:actions] || []).each do |a|
          next unless a[:hit_unknown] || a[:name].to_s =~ /Unknown/
          key = a[:name] || "Unknown(#{a[:type]})"
          e = actions[key]
          e[:count] += 1
          e[:bytes][a[:data]&.bytesize] ||= a[:data]&.bytes&.map { |b| '%02x' % b }&.join
          e[:ticks] << tc[:tick] if e[:ticks].size < 4
          e[:files] << File.basename(path)
        end
      end
    end
  rescue => ex
    warn "#{path}: #{ex.class} #{ex.message[0, 60]}"
  end
end

puts '== unknown/undecoded actions (name = live /toggle-action-logging correlation) =='
actions.sort_by { |_, v| -v[:count] }.each do |name, e|
  puts format('%-32s x%-6d payloads=%s example_ticks=%s in=%s',
              name, e[:count], e[:bytes].keys.compact.sort.inspect,
              e[:ticks].inspect, e[:files].to_a.first(2))
end
puts '== heartbeats that failed to parse =='
hb_fail.each { |t, e| puts "msg#{t} x#{e[:count]} in=#{e[:files].to_a.first(3)}" }