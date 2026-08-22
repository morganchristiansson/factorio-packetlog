#!/usr/bin/env ruby
# Generate a test packet with NewPeerInfo sync action for use as fixture.
# Run: ruby -Ilib test/fixtures/gen_join_packet.rb

require 'fileutils'
require_relative '../../lib/factorio_protocol'

FIXTURE_DIR = File.join(__dir__)

def build_s2c_heartbeat_with_sync(sync_actions)
  # Server-to-client heartbeat with tick closures and sync actions
  # Flags: has_sync=true (0x10), has_tc=true (0x02), single_tc=true (0x04) => 0x16
  hb_flags = 0x16
  seq = [12345].pack('V')
  
  # Empty tick closure: all_tick_closures_are_empty=false, is_empty=false
  # Tick (8 bytes) + count_flagged (1 byte = 0 = 0 actions)
  tick = [0, 0, 0, 0, 0, 0, 0, 0].pack('C*')
  count_flagged = [0].pack('C')
  tc = tick + count_flagged
  
  # Sync actions count
  sync_data = String.new
  sync_actions.each do |sa|
    type_byte = [sa[:type]].pack('C')
    payload = sa[:payload] || String.new
    peer_id = [sa[:peer_id] || 0].pack('v')
    sync_data << type_byte << payload << peer_id
  end
  
  sync_count_byte = sync_data.bytesize < 0xFF ? [sync_data.bytesize > 0 ? 1 : 0].pack('C') : ([0xFF].pack('C') + [1].pack('V'))
  # Actually, sync count is the number of actions, not bytes
  sync_count_enc = [sync_actions.size].pack('C')  # assume small count < 255
  
  # Net header: 0x07 = S2C, no random
  net_hdr = [0x07].pack('C')
  
  net_hdr + [hb_flags].pack('C') + seq + tc + sync_count_enc + sync_data
end

# Generate NewPeerInfo action
# Format: [type=0x02][username_uint32v][peer_id(2)]
username = "hellwarr"
u_len = username.bytesize
username_bytes = [u_len].pack('C') + username
peer_id = 42  # example peer ID

new_peer_info = {
  type: 0x02,
  payload: username_bytes,
  peer_id: peer_id
}

# Generate a second sync action (GameEnd) after it
game_end = {
  type: 0x00,
  payload: String.new,
  peer_id: 1
}

packet = build_s2c_heartbeat_with_sync([new_peer_info, game_end])

path = File.join(FIXTURE_DIR, 'player_join.bin')
File.binwrite(path, packet)
puts "Created #{path} (#{packet.bytesize} bytes)"

# Verify it parses correctly
parsed = FactorioProtocol.parse_udp_payload(packet)
if parsed && parsed[:heartbeat]
  hb = parsed[:heartbeat]
  puts "Sync actions: #{hb[:sync_actions]&.size || 0}"
  hb[:sync_actions]&.each do |sa|
    puts "  #{sa[:name]} peer_id=#{sa[:peer_id]} username=#{sa[:username].inspect}"
  end
end
