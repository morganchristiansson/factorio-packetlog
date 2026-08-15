# frozen_string_literal: true

require_relative 'factorio_packet'

module FactorioProtocol
  # ClientToServerHeartbeat (6) / ServerToClientHeartbeat (7).
  #
  # Everything about the heartbeat message lives here: the heartbeat flags +
  # sequence number framing, tick closures (which carry the input actions),
  # synchronizer actions, and heartbeat requests. The tick-closure/action
  # parsers are private to this class because no other message type uses
  # them — "all heartbeat knowledge in one place".
  class HeartbeatPacket < FactorioPacket
    attr_reader :heartbeat

    private

    def parse_body
      _, @heartbeat = parse_heartbeat(@data, 1, is_server: @header[:msg_type] == 7)
      @result[:heartbeat] = @heartbeat
    end

    # ── Heartbeat ──────────────────────────────────────────────────

    def parse_heartbeat(data, offset, is_server: false)
      return [offset, nil] if offset >= data.bytesize

      hb = {
        flags: data.getbyte(offset),
        has_heartbeat_requests: false,
        has_tick_closures: false,
        has_single_tick_closure: false,
        all_tick_closures_are_empty: false,
        has_synchronizer_action: false,
        seq: nil,
        tick_closures: [],
        sync_actions: [],
        heartbeat_requests: [],
        hit_unknown: false,
      }

      f = hb[:flags]
      hb[:has_heartbeat_requests]       = (f & 0x01) != 0
      hb[:has_tick_closures]            = (f & 0x02) != 0
      hb[:has_single_tick_closure]      = (f & 0x04) != 0
      hb[:all_tick_closures_are_empty]  = (f & 0x08) != 0
      hb[:has_synchronizer_action]      = (f & 0x10) != 0
      offset += 1

      return [offset, hb] if offset + 4 > data.bytesize
      hb[:seq] = data.unpack1('V', offset: offset)
      offset += 4

      # Tick closures
      if hb[:has_tick_closures]
        count = hb[:has_single_tick_closure] ? 1 : data.getbyte(offset)
        offset += 1 unless hb[:has_single_tick_closure]
        tc_count = count.to_i

        tc_count.times do |i|
          break if offset >= data.bytesize || hb[:hit_unknown]
          # The C→S [tick][pad] trailer comes once per HEARTBEAT, after the
          # LAST closure — so only the final closure may hand its last action
          # the +8 trailer. Earlier closures end right after their actions;
          # consuming 8 bytes there swallows the next closure's 8-byte tick
          # (multi-closure heartbeat: phantom drag_train_wait_condition
          # Player_63 from a 266 in a non-final closure).
          is_last_closure = (i == tc_count - 1)
          offset, tc = parse_tick_closure(data, offset, hb[:all_tick_closures_are_empty],
                                          is_server: is_server, is_last_closure: is_last_closure)
          hb[:tick_closures] << tc if tc
          hb[:hit_unknown] = tc[:hit_unknown] if tc
        end
      end

      # Client-only: nextToReceiveServerTickClosure (8 bytes)
      if !is_server && !hb[:hit_unknown] && offset + 8 <= data.bytesize
        hb[:next_receive] = data.unpack1('Q<', offset: offset)
        offset += 8
      end

      # Synchronizer actions
      if hb[:has_synchronizer_action] && !hb[:hit_unknown]
        sync_start = offset
        offset, count = decode_uint32v(data, offset)
        # Sanity check: each sync action needs at least 3 bytes for server (1 type + 2 peer_id)
        # or 1 byte for client (1 type). If count is impossibly large, skip.
        min_per_sync = is_server ? 3 : 1
        if count && count > 0 && offset + (count * min_per_sync) > data.bytesize
          # Sync count is implausible — likely due to TC action length mismatch
          offset = sync_start  # reset to try other parsing paths
        else
          count.to_i.times do
            break if offset >= data.bytesize
            offset, sa = parse_synchronizer_action(data, offset, is_server)
            break unless sa
            hb[:sync_actions] << sa
            break if sa[:hit_unknown]
          end
        end
      end

      # Heartbeat requests
      if hb[:has_heartbeat_requests] && !hb[:hit_unknown] && offset < data.bytesize
        req_count = data.getbyte(offset)
        offset += 1
        req_count.times do
          break if offset + 4 > data.bytesize
          hb[:heartbeat_requests] << data.unpack1('V', offset: offset)
          offset += 4
        end
      end

      [offset, hb]
    end

    # ── Tick Closure ───────────────────────────────────────────────

    def parse_tick_closure(data, offset, is_empty, is_server: false, is_last_closure: true)
      return [offset, nil] if offset + 8 > data.bytesize
      tc = { tick: data.unpack1('Q<', offset: offset), actions: [], hit_unknown: false }
      offset += 8
      return [offset, tc] if is_empty

      # Action count with segment flag
      offset, count_flagged = decode_uint32v(data, offset)
      return [offset, tc] if count_flagged.nil?

      count = count_flagged >> 1
      has_segments = (count_flagged & 1) == 1
      tc[:action_count] = count

      # In drag-mode, the tick has more than 1 action and the first build action
      # has 11 bytes instead of 9 (includes position+dir+2 byte drag marker)
      is_drag = (count > 1)

      last_index = 0xFFFF
      count.times do |i|
        break if offset >= data.bytesize || tc[:hit_unknown]
        # The C→S [tick][pad] closure trailer sits after the LAST action of
        # the LAST closure in the heartbeat (or after the segments when
        # present). Only that action may consume it — see parse_action.
        # Without this, the parser would eat the next action's header (or the
        # next closure's tick) as trailer bytes and invent phantom actions
        # with bogus player deltas (Player_192 swap_tile_slots,
        # Player_63 drag_train_wait_condition).
        is_last = is_last_closure && (i == count - 1) && !has_segments
        offset, act = parse_action(data, offset, last_index,
                                   is_drag: is_drag, is_server: is_server, is_last: is_last)
        break unless act
        tc[:actions] << act
        last_index = act[:player]
        tc[:hit_unknown] = true if act[:hit_unknown]
      end

      # Server-to-client heartbeats: [server_tick_info][real action][metadata...]
      # or [real action][metadata...]. Keep the server_tick_info wrapper (needed
      # for player delta decoding; it is filtered at display) plus the FIRST real
      # action, then drop trailing metadata entries.
      if is_server && tc[:actions].size > 1
        wrapper = tc[:actions].take_while { |a| a[:name] == 'server_tick_info' }
        real = tc[:actions].find { |a| a[:name] != 'server_tick_info' && a[:type] != 0 }
        tc[:actions] = real ? wrapper + [real] : [tc[:actions].first]
        # Metadata actions may have set hit_unknown; reset so segment parsing proceeds
        tc[:hit_unknown] = false
      end

      # Parse segments — they contain action payloads (also adds actions not in input list)
      if has_segments && offset < data.bytesize && !tc[:hit_unknown]
        seg_count = data.getbyte(offset)
        offset += 1
        # Collect raw segments first: split chat messages span MULTIPLE
        # input-action segments (seg_no/total_segs), often across separate
        # packets. Same-closure segments are merged here (ordered by
        # seg_no); cross-packet groups carry seg_no/total_segs on the
        # action for the sniffer to reassemble (see
        # FactorioSniffer#chat_action_data).
        segs = []
        seg_count.times do
          break if offset >= data.bytesize
          seg_type = data.getbyte(offset); offset += 1
          seg_blue = data.unpack1('V', offset: offset) rescue 0; offset += 4
          v_off, seg_green = decode_uint16v(data, offset); offset = v_off
          v_off, total_len = decode_uint32v(data, offset); offset = v_off
          v_off, seg_number = decode_uint32v(data, offset); offset = v_off
          # Payload: uint32v length + data
          v_off, pay_len = decode_uint32v(data, offset); offset = v_off
          next unless pay_len && pay_len > 0 && offset + pay_len <= data.bytesize
          segs << { type: seg_type, green: seg_green, total: total_len,
                    no: seg_number, payload: data[offset, pay_len] }
          offset += pay_len
        end
        segs.group_by { |s| s[:type] }.each do |seg_type, parts|
          parts.sort_by! { |s| s[:no] }
          payload = parts.map { |s| s[:payload] }.join
          total_segs = parts.first[:total]
          seg_no = parts.first[:no]
          existing = tc[:actions]&.find { |a| a[:type] == seg_type }
          if existing
            existing[:data] = payload
            existing[:total_segs] = total_segs if total_segs
            existing[:seg_no] = seg_no
          else
            # Add new action from segment. Segment types follow the
            # server version's defines.input_action (see
            # FactorioProtocol.segment_types) — NOT the version-stable
            # main-action table. 2.0.77: chat arrives as a segment with
            # type 104 (write_to_console); 2.1: type 106.
            seg_name = FactorioProtocol.segment_action_name(seg_type)
            tc[:actions] << {
              type: seg_type, name: seg_name,
              player: parts.first[:green], game_player: parts.first[:green] + 1,
              delta: 0, data: payload, hit_unknown: false,
              total_segs: total_segs, seg_no: seg_no
            }
          end
        end
      end

      [offset, tc]
    end

    # ── Input Action ───────────────────────────────────────────────

    def parse_action(data, offset, last_index, is_drag: false, is_server: false, is_last: false)
      type_offset = offset
      offset, type = decode_uint16v(data, offset)
      return [offset, nil] if type.nil?
      delta_offset = offset
      offset, delta = decode_uint16v(data, offset)
      return [offset, nil] if delta.nil?

      raw_player = (last_index + delta) & 0xFFFF
      game_player = raw_player + 1
      data_start = offset
      # Version-dependent table (ACTIONS_20 for 2.0, ACTIONS for 2.1) —
      # names AND data lengths come from the selected map.
      entry = FactorioProtocol.actions[type]
      name = entry ? entry[0] : "Unknown(#{type})"
      alen = entry ? entry[1] : nil

      # Build: 9 bytes base (x+y+dir), 10 with ghost flag, 11 in drag mode.
      # C→S drag build carries the position INSIDE the action data: 21 bytes =
      # 9B pos + 01 01 drag marker + 10B headerless drag position (x+y+dir+flag).
      # Reading only 11 bytes used to leave the 10B position to be re-parsed as a
      # phantom action (e.g. zoom_around_point Player_252 from the position's
      # x-byte 0x80). S→C echoes send the position as a separate counted action
      # (11B build + 10B position), so it is only folded in for client packets.
      # Version-agnostic: matched by NAME (2.0: build=66, 2.1: 68).
      if name == 'build'
        if is_drag && !is_server && offset + 21 <= data.bytesize &&
           data.getbyte(offset + 9) == 0x01 && data.getbyte(offset + 10) == 0x01
          alen = 21
        elsif is_drag && offset + 11 <= data.bytesize
          alen = 11  # drag: 01 01 marker
        elsif offset + 10 <= data.bytesize && data.getbyte(offset + 9) == 0x00 && offset + 10 < data.bytesize
          alen = 10  # ghost: trailing 0x00 byte
        end
      end

      # open_gui: variable length, depends on direction.
      #   Client → server: 8 bytes [gui_type(1)][flags(1)][tick(4)][pad(2)].
      #     The tick is the local game tick when the click happened (hb tick - 3
      #     in captures). Reading 2 bytes here used to leave the 6-byte tail to
      #     be misparsed as phantom actions (e.g. add_decider_combinator_condition
      #     with a bogus player delta).
      #   Server echo: 14 bytes when it appends entity ref + token + tick,
      #     else the bare 2-byte form [gui_type][flags] (no entity info).
      if name == 'open_gui'
        alen = if is_server
          (offset + 14 <= data.bytesize) ? 14 : 2
        else
          8
        end
      end

      # open_character_gui (2.0: 6 / 2.1: 61) / open_blueprint_library_gui
      # (2.0: 63 / 2.1: 64): direction-dependent like open_gui. C→S carries
      # only the 1-byte GUI type; the S→C echo appends 14 bytes of metadata
      # (15 total). Reading 15 bytes for C→S swallowed the following
      # hover/266 actions and re-parsed their headers as phantom actions
      # (e.g. gui_inventory_bar_changed Player_267, alt_select_blueprint_entities).
      if name == 'open_character_gui' || name == 'open_blueprint_library_gui'
        alen = is_server ? 15 : 1
      end

      # selected_entity_cleared (2.0/2.1 both 9): the 8 bytes ACTIONS lists are
      # the C→S closure [tick][pad] trailer — the game sends the action with NO
      # data of its own, and the closure trailer follows the LAST action (hb
      # tick - 8 in captures). Intermediate actions carry no bytes; consuming 8
      # here used to eat the next action's header (phantom Player_192/etc.).
      # S→C echo: [ref(4)][token(4)] = 8 bytes (tail follows separately).
      if name == 'selected_entity_cleared'
        alen = is_server ? 8 : (is_last ? 8 : 0)
      end

      # Hover/selection/zoom family (2.0/2.1 IDs differ; matched by name): the
      # ACTIONS len is the C→S payload only. C→S tick closures carry ONE
      # 8-byte [tick(4)][pad(4)] trailer after the LAST action (hb tick - 3
      # in captures); intermediate actions carry no trailer. Adding +8 to
      # every action used to swallow the next action's header and re-parse
      # payload bytes as phantom actions (zoom→swap_tile_slots Player_192,
      # selected_entity_changed→drag_train_wait_condition Player_64).
      # S→C echoes append [ref(4)][token(4)][tick-1(4)][pad(4)] = +16.
      if alen && %w[close_gui zoom_around_point move_on_pan close_remote_view
                    change_picking_state selected_entity_changed_very_close
                    selected_entity_changed_very_close_precise
                    selected_entity_changed_relative render_mode_changed].include?(name)
        alen = if is_server
          alen + 16
        else
          is_last ? alen + 8 : alen
        end
      end

      adata = nil
      hit_unknown = false

      if alen && alen > 0 && offset + alen <= data.bytesize
        adata = data[offset, alen]
        offset += alen
      elsif alen == 0
        adata = ''.b
      elsif alen.nil?
        case name
        when 'remote_view_surface' # read 4 bytes for surface ID, then stop
          if offset + 4 <= data.bytesize
            adata = data[offset, 4]
            offset += 4
          end
          hit_unknown = true  # stop parsing further actions in this tick
        when 'write_to_console'
          s_off, s_len = decode_uint32v(data, offset)
          if s_len && s_off + s_len <= data.bytesize
            adata = data[offset, s_off - offset + s_len]
            offset = s_off + s_len
          else
            adata = nil
            hit_unknown = true
          end
        else
          adata = nil
          hit_unknown = true
        end
      else
        # alen > 0 but not enough data available
        adata = nil
        hit_unknown = true
      end

      [offset, {
        type: type, name: name, player: raw_player, game_player: game_player,
        delta: delta, data: adata, hit_unknown: hit_unknown,
        type_offset: type_offset, data_offset: data_start,
      }]
    end

    # ── Synchronizer Action ────────────────────────────────────────

    def parse_synchronizer_action(data, offset, is_server)
      return [offset, nil] if offset >= data.bytesize
      type = data.getbyte(offset)
      offset += 1
      info = SYNCHRONIZER_ACTIONS[type] || "Unknown(0x#{type.to_s(16)})"

      sa = { type: type, name: info, data: nil, hit_unknown: false }

      case type
      when 0x01 # PeerDisconnect — 1 byte reason
        if offset < data.bytesize
          sa[:reason] = data.getbyte(offset)
          offset += 1
        end
      when 0x02 # NewPeerInfo — username string (uint32v-prefixed)
        s_off, s_len = decode_uint32v(data, offset)
        if s_len && s_off + s_len <= data.bytesize
          sa[:username] = data[s_off, s_len]
          offset = s_off + s_len
        else
          sa[:hit_unknown] = true
        end
      when 0x03 # ClientChangedState
        if !is_server && offset < data.bytesize
          sa[:state] = data.getbyte(offset)
          offset += 1
        end
      when 0x04 # ClientShouldStartSendingTickClosures
        if offset + 8 <= data.bytesize
          sa[:data] = data[offset, 8]
          offset += 8
        end
      else
        # Use known lengths from SYNC_ACTION_LENS, or stop processing
        slen = SYNC_ACTION_LENS[type]
        if slen && offset + slen <= data.bytesize
          sa[:data] = data[offset, slen] if slen > 0
          offset += slen
        else
          sa[:hit_unknown] = true
        end
      end

      # Server-to-client messages append a 2-byte sender peer_id after action data
      if is_server && offset + 2 <= data.bytesize
        sa[:peer_id] = data.unpack1('v', offset: offset)
        offset += 2
      end

      [offset, sa]
    end
  end
end
