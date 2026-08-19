#!/usr/bin/env ruby
# frozen_string_literal: true

# tools/chat_extract.rb — extract ALL in-game chat (write_to_console) from
# server-mode pcap captures into a readable transcript.
#
# One-off utility written to seed Hivemind's long-term memories from
# historical captures. Reuses the sniffer's own decoding pipeline:
#   PcapReader → FactorioProtocol.parse_udp_payload → segment reassembly
#   (identical logic to FactorioSniffer#chat_action_data) → decode_chat.
#
# Handles:
#   * segmented chat: split messages arrive as separate input-action
#     segments (seg_no/total_segs), often across separate packets —
#     buffered per (player, total_segs) and merged in seg_no order when
#     complete (15s window, like the sniffer).
#   * protocol versions: auto-detects 2.0 vs 2.1 by counting which
#     segment type decodes as write_to_console (104 vs 106) on a sample;
#     --protocol-version overrides.
#   * player names: msg-4 username + first C→S heartbeat index binding
#     (same as server mode), falling back to players.json, then
#     Player_<index>.
#
# Usage:
#   ruby tools/chat_extract.rb factorio-20260816-*.pcap factorio.pcap > transcript.txt
#   ruby tools/chat_extract.rb --protocol-version 2.1 captures/server-*.pcap
#
# Output: one line per chat message: [HH:MM:SS] name: message, with
# `== file ==` headers in capture order (files are chronological).

require_relative '../lib/pcap'
require_relative '../lib/factorio_protocol'
require_relative '../lib/player_db'

# ── CLI ─────────────────────────────────────────────────────────────

files = []
proto = nil
args = ARGV.dup
while (a = args.shift)
  case a
  when '--protocol-version'
    proto = args.shift
  when '-h', '--help'
    puts File.read(__FILE__).split(/^# Usage:\n/)[1].to_s.split("\n").first(2).join("\n")
    exit 0
  else
    files << a
  end
end
if files.empty?
  warn 'usage: ruby tools/chat_extract.rb PCAP... [--protocol-version 2.0|2.1]'
  exit 1
end
files.sort!

# ── Protocol version detection ──────────────────────────────────────

# 2.0 and 2.1 number input-action SEGMENT types differently (chat segment
# 104 vs 106). Pick the table that decodes more write_to_console actions
# on a sample of packets.
def detect_version(path)
  FactorioProtocol.reset_version
  hits = { '2.0' => 0, '2.1' => 0 }
  sampled = 0
  PcapReader.new(path).each_packet do |_n, _ts, _s, _d, _sp, _dp, udp|
    break if sampled > 5000
    sampled += 1
    next unless (udp.getbyte(0) & 0x1F) == 6
    %w[2.0 2.1].each do |v|
      FactorioProtocol.select_version(v)
      parsed = FactorioProtocol.parse_udp_payload(udp)
      next unless parsed && parsed[:heartbeat]
      parsed[:heartbeat][:tick_closures]&.each do |tc|
        hits[v] += tc[:actions].count { |a| a[:name] == 'write_to_console' }
      end
    end
  end
  hits.sort_by { |_k, v| -v }.first.first
rescue StandardError => e
  warn "version detection failed (#{e.class}: #{e.message}); defaulting to 2.0"
  '2.0'
end

proto ||= detect_version(files.first)
FactorioProtocol.select_version(proto)
puts "# chat protocol version: #{proto} (#{FactorioProtocol.actions.equal?(FactorioProtocol::ACTIONS_20) ? '2.0 table' : '2.1 table'})"
puts "# files: #{files.join(', ')}"

# ── Name resolution ─────────────────────────────────────────────────

# Player index (0-indexed game index +1 → players.json key) → name.
# pcap-derived bindings (msg-4 username + first C→S heartbeat index) win
# over players.json (which may be stale / missing recent joiners).
db = PlayerDatabase.new(File.join(__dir__, '..', 'players.json'))
index_name = {}
ip_index = {}   # src_ip → 0-indexed game index (bound by first real action)
ip_name = {}    # src_ip → username (from msg 4 ConnectionRequestReplyConfirm)

def player_name(idx0, db, index_name)
  return '?' if idx0.nil?
  index_name[idx0] || db.lookup(idx0 + 1)
end

# ── Segment reassembly (mirrors FactorioSniffer#chat_action_data) ────

chat_segments = {}

def reassemble_chat(chat_segments, act, pname, ts)
  total = act[:total_segs]
  data = act[:data]
  return data unless total && total > 1

  key = [pname, total]
  group = (chat_segments[key] ||= {})
  group[:ts] = ts
  group[act[:seg_no]] = data

  chat_segments.delete_if { |_k, g| g[:ts] && (ts - g[:ts]) > 15 }
  return nil unless (0...total).all? { |n| group.key?(n) }
  merged = (0...total).map { |n| group[n] }.join
  chat_segments.delete(key)
  merged
end

# ── Main pass ───────────────────────────────────────────────────────

total_msgs = 0
files.each do |f|
  file_msgs = 0
  puts "== #{File.basename(f)} =="
  begin
    PcapReader.new(f).each_packet do |_n, ts, src_ip, _dst, _sp, _dp, udp|
      mt = udp.getbyte(0) & 0x1F
      case mt
      when 4
        # ConnectionRequestReplyConfirm — the connecting client's username.
        parsed = FactorioProtocol.parse_udp_payload(udp)
        if parsed && parsed[:connection_confirm] && parsed[:connection_confirm][:username]
          ip_name[src_ip] = parsed[:connection_confirm][:username]
        end
        next
      when 6
        parsed = FactorioProtocol.parse_udp_payload(udp)
        next unless parsed && parsed[:heartbeat]
        hb = parsed[:heartbeat]
        # Bind src_ip → game index from the first real action in a C→S
        # closure (same heuristic as the sniffer's server mode).
        unless ip_index[src_ip]
          hb[:tick_closures]&.each do |tc|
            real = tc[:actions]&.find { |a| a[:type] != 0 && a[:type] != 84 }
            if real
              ip_index[src_ip] = real[:player]
              # msg-4 username + first-heartbeat index = authoritative
              # name→index (same as server mode's confirm path).
              if ip_name[src_ip]
                index_name[real[:player]] ||= ip_name[src_ip]
              end
              break
            end
          end
        end
        hb[:tick_closures]&.each do |tc|
          tc[:actions]&.each do |act|
            next unless act[:name] == 'write_to_console'
            pname = player_name(act[:player], db, index_name)
            data = reassemble_chat(chat_segments, act, pname, ts)
            next unless data
            msg = FactorioProtocol.decode_chat(data)
            next if msg.nil? || msg.empty?
            ts_str = Time.at(ts).strftime('%H:%M:%S')
            puts "#{ts_str}  #{pname}: #{msg}"
            total_msgs += 1
            file_msgs += 1
          end
        end
      end
    end
  rescue StandardError => e
    warn "#{f}: #{e.class}: #{e.message}"
  end
  warn "#{f}: #{file_msgs} messages" if file_msgs.zero?
end
warn "total chat messages: #{total_msgs}"
