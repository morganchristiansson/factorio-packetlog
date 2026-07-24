# frozen_string_literal: true

# Factorio UDP protocol parser.
# Based on Hornwitser's Wireshark dissector (reverse-engineered from factorio.pdb).
module FactorioProtocol
  # ── Message Types ──────────────────────────────────────────────────
  MESSAGE_TYPES = {
    0 => 'Ping', 1 => 'PingReply',
    2 => 'ConnectionRequest', 3 => 'ConnectionRequestReply',
    4 => 'ConnectionRequestReplyConfirm', 5 => 'ConnectionAcceptOrDeny',
    6 => 'ClientToServerHeartbeat', 7 => 'ServerToClientHeartbeat',
    8 => 'GetOwnAddress', 9 => 'GetOwnAddressReply',
    10 => 'NatPunchRequest', 11 => 'NatPunch',
    12 => 'TransferBlockRequest', 13 => 'TransferBlock',
    14 => 'RequestForHeartbeatWhenDisconnecting',
    15 => 'LANBroadcast', 16 => 'GameInformationRequest',
    17 => 'GameInformationRequestReply', 18 => 'Empty',
  }.freeze

  SYNCHRONIZER_ACTIONS = {
    0x00 => 'GameEnd', 0x01 => 'PeerDisconnect', 0x02 => 'NewPeerInfo',
    0x03 => 'ClientChangedState', 0x04 => 'ClientShouldStartSendingTickClosures',
    0x05 => 'MapReadyForDownload', 0x06 => 'MapLoadingProgressUpdate',
    0x07 => 'MapSavingProgressUpdate', 0x08 => 'SavingForUpdate',
    0x09 => 'MapDownloadingProgressUpdate', 0x0a => 'CatchingUpProgressUpdate',
    0x0b => 'PeerDroppingProgressUpdate', 0x0c => 'PlayerDesynced',
    0x0d => 'BeginPause', 0x0e => 'EndPause',
    0x0f => 'SkippedTickClosure', 0x10 => 'SkippedTickClosureConfirm',
    0x11 => 'ChangeLatency', 0x12 => 'IncreasedLatencyConfirm',
    0x13 => 'SavingCountDown', 0x14 => 'AuxiliaryDataReadyForDownload',
    0x15 => 'AuxiliaryDataDownloadFinished',
  }.freeze

  # ── Input Actions (from Hornwitser/factorio_dissector Lua plugin) ──
  # [action_id] => [name, data_len]
  #   data_len: 0 = no data, N = fixed N bytes, nil = variable/complex
ACTIONS = {
  0=>["nothing",0],
  1=>["stop_walking",0],
  2=>["begin_mining",0],
  3=>["stop_mining",0],
  4=>["toggle_driving",0],
  5=>["open_gui",6],
  6=>["open_current_vehicle_gui",0],
  7=>["connect_rolling_stock",0],
  8=>["disconnect_rolling_stock",0],
  9=>nil,
  10=>["clear_cursor",0],
  11=>["reset_assembling_machine",0],
  12=>nil,
  13=>["cancel_new_blueprint",0],
  14=>nil,
  15=>["copy_entity_settings",0],
  16=>["paste_entity_settings",0],
  17=>["destroy_opened_item",0],
  18=>["copy_opened_item",0],
  19=>["copy_large_opened_item",0],
  20=>nil,
  21=>nil,
  22=>nil,
  23=>["open_bonus_gui",0],
  24=>["open_achievements_gui",0],
  25=>["cycle_blueprint_book_forwards",0],
  26=>["cycle_blueprint_book_backwards",0],
  27=>["cycle_quality_up",0],
  28=>["cycle_quality_down",0],
  29=>nil,
  30=>nil,
  31=>nil,
  32=>["toggle_enable_vehicle_logistics_while_moving",0],
  33=>["toggle_deconstruction_item_entity_filter_mode",0],
  34=>["toggle_deconstruction_item_tile_filter_mode",0],
  35=>["select_next_valid_gun",0],
  36=>["toggle_map_editor",0],
  37=>["delete_blueprint_library",0],
  38=>nil,
  39=>["activate_paste",0],
  40=>["undo",0],
  41=>["redo",0],
  42=>["toggle_personal_roboport",0],
  43=>["toggle_equipment_movement_bonus",0],
  44=>["toggle_personal_logistic_requests",0],
  45=>["toggle_entity_logistic_requests",0],
  46=>["toggle_artillery_auto_targeting",0],
  47=>["toggle_tall_entity_visibility",0],
  48=>["stop_drag_build",0],
  49=>["flush_opened_entity_fluid",0],
  50=>nil,
  51=>["add_logistic_section",0],
  52=>nil,
  53=>["open_opened_entity_grid",0],
  54=>nil,
  55=>nil,
  56=>["open_new_platform_button_from_rocket_silo",0],
  57=>["toggle_selected_entity",0],
  58=>["cheat",0],
  59=>["toggle_blueprint_snap_to_grid",0],
  60=>nil,
  61=>["open_character_gui",0],
  62=>["open_production_gui",0],
  63=>["open_logistics_gui",0],
  64=>["open_blueprint_library_gui",2],
  65=>["toggle_show_entity_info",0],
  66=>nil,
  67=>["drop_item",8],
  68=>["build",9],
  69=>["start_walking",16],
  70=>["begin_mining_terrain",8],
  71=>["change_riding_state",2],
  72=>["change_heading_riding_state",2],
  73=>["open_item",5],
  74=>["open_parent_of_opened_item",2],
  75=>["destroy_item",8],
  76=>["open_mod_item",6],
  77=>["open_equipment",nil],
  78=>["cursor_transfer",9],
  79=>["cursor_split",5],
  80=>["stack_transfer",5],
  81=>["send_stack_to_trash",0],
  82=>["send_stacks_to_trash",0],
  83=>["inventory_transfer",5],
  84=>nil,
  85=>["craft",5],
  86=>["wire_dragging",8],
  87=>["change_shooting_state",9],
  88=>["setup_assembling_machine",2],
  89=>nil,
  90=>["pipette",9],
  91=>["stack_split",2],
  92=>["inventory_split",8],
  93=>["cancel_craft",0],
  94=>["set_filter",nil],
  95=>["set_spoil_priority",nil],
  96=>nil,
  97=>["set_circuit_condition",nil],
  98=>["set_signal",nil],
  99=>["start_research",0],
  100=>["set_cheat_mode_quality",0],
  101=>["set_logistic_filter_item",nil],
  102=>["swap_logistic_filter_items",1],
  103=>["set_circuit_mode_of_operation",12],
  104=>["gui_click",nil],
  105=>["gui_confirmed",nil],
  106=>["write_to_console",nil],
  107=>["market_offer",9],
  108=>["change_train_stop_station",0],
  109=>["change_active_item_group_for_crafting",25],
  110=>["change_active_item_group_for_filters",5],
  111=>["change_active_character_tab",1],
  112=>["gui_text_changed",nil],
  113=>["gui_checked_state_changed",nil],
  114=>["gui_selection_state_changed",nil],
  115=>["gui_selected_tab_changed",nil],
  116=>["gui_value_changed",nil],
  117=>["gui_switch_state_changed",nil],
  118=>["gui_location_changed",nil],
  119=>["gui_inventory_bar_changed",nil],
  120=>["gui_inventory_filter_changed",nil],
  121=>["gui_inventory_action",nil],
  122=>["place_equipment",0],
  123=>["take_equipment",0],
  124=>["use_item",8],
  125=>["send_spidertron",0],
  126=>["set_inventory_bar",6],
  127=>nil,
  128=>nil,
  129=>nil,
  130=>["start_repair",8],
  131=>["deconstruct",8],
  132=>["upgrade",0],
  133=>["copy",0],
  134=>["alternative_copy",0],
  135=>["select_blueprint_entities",0],
  136=>["alt_select_blueprint_entities",0],
  137=>["setup_blueprint",0],
  138=>["setup_single_blueprint_record",0],
  139=>["copy_opened_blueprint",0],
  140=>["copy_large_opened_blueprint",0],
  141=>["reassign_blueprint",0],
  142=>["open_blueprint_record",0],
  143=>["grab_blueprint_record",nil],
  144=>["drop_blueprint_record",0],
  145=>["delete_blueprint_record",0],
  146=>["upgrade_opened_blueprint_by_record",0],
  147=>["upgrade_opened_blueprint_by_item",0],
  148=>["spawn_item",0],
  149=>["set_ghost_cursor",0],
  150=>nil,
  151=>nil,
  152=>nil,
  153=>["edit_blueprint_tool_preview",nil],
  154=>["remove_cables",8],
  155=>["export_blueprint",nil],
  156=>["import_blueprint",16],
  157=>["import_blueprints_filtered",6],
  158=>nil,
  159=>nil,
  160=>["cancel_deconstruct",0],
  161=>["cancel_upgrade",5],
  162=>["change_arithmetic_combinator_parameters",0],
  163=>["drag_decider_combinator_condition",0],
  164=>["add_decider_combinator_condition",0],
  165=>["modify_decider_combinator_condition",nil],
  166=>["remove_decider_combinator_condition",0],
  167=>["drag_decider_combinator_output",0],
  168=>["add_decider_combinator_output",0],
  169=>["modify_decider_combinator_output",0],
  170=>["remove_decider_combinator_output",0],
  171=>["drag_decider_combinator_else_output",0],
  172=>["add_decider_combinator_else_output",0],
  173=>["modify_decider_combinator_else_output",0],
  174=>["remove_decider_combinator_else_output",0],
  175=>["change_selector_combinator_parameters",0],
  176=>["change_programmable_speaker_parameters",0],
  177=>["change_programmable_speaker_alert_parameters",0],
  178=>["change_programmable_speaker_circuit_parameters",0],
  179=>["set_vehicle_automatic_targeting_parameters",0],
  180=>["build_terrain",0],
  181=>["change_research_condition",0],
  182=>["drag_research_condition",0],
  183=>["change_train_wait_condition",0],
  184=>["change_train_wait_condition_data",0],
  185=>["remove_train_station",0],
  186=>["remove_train_interrupt",0],
  187=>["add_train_station",0],
  188=>["change_train_station",0],
  189=>["add_train_interrupt",0],
  190=>["activate_interrupt",0],
  191=>["edit_interrupt",0],
  192=>["rename_interrupt",0],
  193=>["go_to_train_station",0],
  194=>["set_train_stopped",0],
  195=>["set_schedule_record_allow_unloading",0],
  196=>["custom_input",nil],
  197=>["change_item_label",0],
  198=>["change_entity_label",0],
  199=>["change_train_name",0],
  200=>["change_logistic_point_group",0],
  201=>["launch_rocket",0],
  202=>["delete_logistic_group",0],
  203=>["set_logistic_network_name",0],
  204=>["build_rail",0],
  205=>["cancel_research",12],
  206=>["move_research",0],
  207=>["select_area",0],
  208=>["alt_select_area",0],
  209=>["reverse_select_area",0],
  210=>["alt_reverse_select_area",0],
  211=>nil,
  212=>["set_infinity_container_filter_item",0],
  213=>["set_infinity_container_logistic_mode",0],
  214=>["swap_infinity_container_filter_items",0],
  215=>["set_infinity_pipe_filter",8],
  216=>["mod_settings_changed",7],
  217=>["set_entity_energy_property",4],
  218=>["set_equipment_energy_property",0],
  219=>["edit_custom_tag",2],
  220=>["edit_permission_group",1],
  221=>["import_blueprint_string",0],
  222=>["import_permissions_string",0],
  223=>nil,
  224=>nil,
  225=>["gui_elem_changed",nil],
  226=>nil,
  227=>["drag_train_schedule",1],
  228=>["drag_train_schedule_interrupt",0],
  229=>["drag_train_wait_condition",2],
  230=>["select_item_filter",0],
  231=>["swap_item_filters",0],
  232=>["select_entity_slot",4],
  233=>["swap_entity_slots",0],
  234=>["select_entity_filter_slot",0],
  235=>["swap_entity_filter_slots",0],
  236=>["select_asteroid_chunk_slot",0],
  237=>["swap_asteroid_chunk_slots",0],
  238=>["select_tile_slot",0],
  239=>["swap_tile_slots",0],
  240=>["select_mapper_slot_from",0],
  241=>["select_mapper_slot_to",0],
  242=>["swap_mappers",0],
  243=>nil,
  244=>["quick_bar_set_slot",9],
  245=>["quick_bar_pick_slot",2],
  246=>["quick_bar_set_selected_page",0],
  247=>nil,
  248=>["map_editor_action",1],
  249=>nil,
  250=>nil,
  251=>["change_multiplayer_config",1],
  252=>["admin_action",0],
  253=>["lua_shortcut",0],
  254=>nil,
  255=>["create_space_platform",0],
  256=>["delete_space_platform",0],
  257=>["cancel_delete_space_platform",0],
  258=>["rename_space_platform",0],
  259=>["remote_view_surface",nil],
  260=>["remote_view_entity",0],
  261=>nil,
  262=>["instantly_create_space_platform",nil],
  263=>["flush_opened_entity_specific_fluid",nil],
  264=>["change_picking_state",1],
  265=>nil,
  266=>nil,
  267=>nil,
  268=>nil,
  269=>["set_combinator_description",nil],
  270=>["switch_constant_combinator_state",1],
  271=>["switch_power_switch_state",1],
  272=>["switch_inserter_filter_mode_state",1],
  273=>["set_use_inserter_filters",0],
  274=>["switch_loader_filter_mode",0],
  275=>["switch_mining_drill_filter_mode_state",0],
  276=>["switch_connect_to_logistic_network",1],
  277=>["set_behavior_mode",1],
  278=>["fast_entity_transfer",1],
  279=>["rotate_entity",1],
  280=>["flip_entity",nil],
  281=>["fast_entity_split",1],
  282=>["request_missing_construction_materials",nil],
  283=>["providing_to_other_platforms",0],
  284=>["trash_not_requested_items",0],
  285=>nil,
  286=>["set_research_finished_stops_game",1],
  287=>["set_inserter_max_stack_size",1],
  288=>["set_loader_belt_stack_size_override",0],
  289=>["open_train_gui",4],
  290=>["open_trains_gui",nil],
  291=>["set_entity_color",4],
  292=>["set_copy_color_from_train_stop",0],
  293=>["set_deconstruction_item_trees_and_rocks_only",1],
  294=>["set_deconstruction_item_tile_selection_mode",1],
  295=>["delete_custom_tag",4],
  296=>["delete_permission_group",4],
  297=>["add_permission_group",4],
  298=>["set_infinity_container_remove_unfiltered_items",1],
  299=>["set_car_weapons_control",1],
  300=>["set_request_from_buffers",1],
  301=>["change_active_quick_bar",1],
  302=>nil,
  303=>nil,
  304=>["set_splitter_priority",1],
  305=>nil,
  306=>["set_heat_interface_temperature",8],
  307=>["set_heat_interface_mode",1],
  308=>["open_train_station_gui",4],
  309=>nil,
  310=>nil,
  311=>["set_player_color",4],
  312=>nil,
  313=>["set_trains_limit",4],
  314=>nil,
  315=>["set_linked_container_link_i_d",4],
  316=>["set_turret_ignore_unlisted",0],
  317=>["set_lamp_always_on",0],
  318=>["open_global_electric_network_gui",0],
  319=>["set_pump_fluid_filter",0],
  320=>nil,
  321=>["remove_logistic_section",0],
  322=>["edit_display_panel",0],
  323=>["edit_display_panel_always_show",0],
  324=>["edit_display_panel_show_in_chart",0],
  325=>["edit_display_panel_icon",0],
  326=>["edit_display_panel_parameters",0],
  327=>["edit_display_panel_single_entry",0],
  328=>["reorder_logistic_section",0],
  329=>["set_logistic_section_active",0],
  330=>["add_pin",0],
  331=>["pin_search_result",0],
  332=>["pin_alert_group",0],
  333=>["pin_custom_alert",0],
  334=>["edit_pin",0],
  335=>["remove_pin",0],
  336=>["move_pin",0],
  337=>["send_train_to_pin_target",0],
  338=>["gui_hover",nil],
  339=>["gui_leave",nil],
  340=>nil,
  341=>["spectator_change_surface",0],
  342=>["adjust_blueprint_snapping",0],
  343=>["set_train_stop_priority",0],
  344=>nil,
  345=>["land_at_planet",0],
  346=>nil,
  347=>nil,
  348=>["parametrise_blueprint",0],
  349=>nil,
  350=>["set_rocket_silo_send_to_orbit_automated_mode",0],
  351=>nil,
  352=>nil,
  353=>nil,
  354=>["set_control_behavior_input_networks",0],
  355=>["set_control_behavior_output_networks",0],
}.freeze

  NOISE_ACTIONS = %w[wire_dragging nothing].freeze
  GRIEF_ACTIONS = %w[
    Cheat SetAllowCommands DestroyItem PlayerAdminChange
    ServerCommand MapEditorAction PutSpecialItemInMap
    ChangeMultiplayerConfig DeleteCustomTag EditPermissionGroup
    DeletePermissionGroup AddPermissionGroup
  ].freeze

  # ── Variable-Length Integer Decoding ───────────────────────────────

  def self.decode_uint16v(data, offset)
    return [offset + 1, nil] if offset >= data.bytesize
    val = data.getbyte(offset)
    if val == 0xFF
      return [offset + 1, nil] if offset + 3 > data.bytesize
      return [offset + 3, data.unpack1('v', offset: offset + 1)]
    end
    [offset + 1, val]
  end

  def self.decode_uint32v(data, offset)
    return [offset + 1, nil] if offset >= data.bytesize
    val = data.getbyte(offset)
    if val == 0xFF
      return [offset + 1, nil] if offset + 5 > data.bytesize
      return [offset + 5, data.unpack1('V', offset: offset + 1)]
    end
    [offset + 1, val]
  end

  # ── Action Name / Length Lookup ────────────────────────────────────

  def self.action_name(type)
    entry = ACTIONS[type]
    entry ? entry[0] : "Unknown(#{type})"
  end

  def self.action_len(type)
    entry = ACTIONS[type]
    entry ? entry[1] : nil
  end

  # ── Network Header ─────────────────────────────────────────────────

  def self.parse_network_header(data)
    return nil if data.bytesize < 1
    flags = data.getbyte(0)
    {
      flags: flags,
      msg_type: flags & 0x1F,
      msg_name: MESSAGE_TYPES[flags & 0x1F] || "Unknown(#{flags & 0x1F})",
      has_random: (flags & 0x20) != 0,
      fragmented: (flags & 0x40) != 0,
      last_frag: (flags & 0x80) != 0,
    }
  end

  # ── Heartbeat ──────────────────────────────────────────────────────

  def self.parse_heartbeat(data, offset, is_server: false)
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

      count.times do
        break if offset >= data.bytesize || hb[:hit_unknown]
        offset, tc = parse_tick_closure(data, offset, hb[:all_tick_closures_are_empty])
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
      offset, count = decode_uint32v(data, offset)
      count.to_i.times do
        break if offset >= data.bytesize
        offset, sa = parse_synchronizer_action(data, offset, is_server)
        hb[:sync_actions] << sa if sa
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

  # ── Tick Closure ───────────────────────────────────────────────────

  def self.parse_tick_closure(data, offset, is_empty)
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
    count.times do
      break if offset >= data.bytesize || tc[:hit_unknown]
      offset, act = parse_action(data, offset, last_index, is_drag: is_drag)
      break unless act
      tc[:actions] << act
      last_index = act[:player]
      tc[:hit_unknown] = true if act[:hit_unknown]
    end

    # Parse segments — they contain action payloads (also adds actions not in input list)
    if has_segments && offset < data.bytesize
      seg_count = data.getbyte(offset)
      offset += 1
      seg_count.times do
        break if offset >= data.bytesize
        seg_type = data.getbyte(offset); offset += 1
        seg_blue = data.unpack1('V', offset: offset) rescue 0; offset += 4
        v_off, seg_green = decode_uint16v(data, offset); offset = v_off
        v_off, total_len = decode_uint32v(data, offset); offset = v_off
        v_off, seg_number = decode_uint32v(data, offset); offset = v_off
        # Payload: uint32v length + data
        v_off, pay_len = decode_uint32v(data, offset); offset = v_off
        if pay_len && pay_len > 0 && offset + pay_len <= data.bytesize
          payload = data[offset, pay_len]
          # Find existing action of same type or add new one
          existing = tc[:actions]&.find { |a| a[:type] == seg_type }
          if existing
            existing[:data] = payload
          else
            # Add new action from segment
            seg_name = action_name(seg_type)
            tc[:actions] << {
              type: seg_type, name: seg_name,
              player: seg_green, game_player: seg_green + 1,
              delta: 0, data: payload, hit_unknown: false
            }
          end
          offset += pay_len
        end
      end
    end

    [offset, tc]
  end

  # ── Input Action ───────────────────────────────────────────────────

  def self.parse_action(data, offset, last_index, is_drag: false)
    offset, type = decode_uint16v(data, offset)
    return [offset, nil] if type.nil?
    offset, delta = decode_uint16v(data, offset)
    return [offset, nil] if delta.nil?

    raw_player = (last_index + delta) & 0xFFFF
    game_player = raw_player + 1
    entry = ACTIONS[type]
    name = entry ? entry[0] : "Unknown(#{type})"
    alen = entry ? entry[1] : nil

    # Build: 9 bytes base (x+y+dir), 10 with ghost flag, 11 in drag mode
    if type == 68
      if is_drag && offset + 11 <= data.bytesize
        alen = 11  # drag: 01 01 marker
      elsif offset + 10 <= data.bytesize && data.getbyte(offset + 9) == 0x00 && offset + 10 < data.bytesize
        alen = 10  # ghost: trailing 0x00 byte
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
      case type
      when 259 # remote_view_surface — read 4 bytes for surface ID, then stop
        if offset + 4 <= data.bytesize
          adata = data[offset, 4]
          offset += 4
        end
        hit_unknown = true  # stop parsing further actions in this tick
      when 106 # write_to_console
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
    end

    [offset, {
      type: type, name: name, player: raw_player, game_player: game_player,
      delta: delta, data: adata, hit_unknown: hit_unknown,
    }]
  end

  # ── Synchronizer Action ────────────────────────────────────────────

  def self.parse_synchronizer_action(data, offset, is_server)
    return [offset, nil] if offset >= data.bytesize
    type = data.getbyte(offset)
    offset += 1
    info = SYNCHRONIZER_ACTIONS[type] || "Unknown(0x#{type.to_s(16)})"

    sa = { type: type, name: info, data: nil }
    rest = data[offset..]

    case type
    when 0x02 # NewPeerInfo — contains username!
      if rest.bytesize > 0
        s_off, s_len = decode_uint32v(rest, 0)
        if s_len && s_off + s_len <= rest.bytesize
          sa[:username] = rest[s_off, s_len]
          offset += s_off + s_len
        end
      end
    when 0x03 # ClientChangedState
      if !is_server && rest.bytesize >= 1
        sa[:state] = rest.getbyte(0)
        offset += 1
      end
    when 0x04 # ClientShouldStartSendingTickClosures (8 bytes)
      if rest.bytesize >= 8
        sa[:data] = rest[0, 8]
        offset += 8
      end
    end

    [offset, sa]
  end

  # ── Connection Request Reply Confirm (username!) ───────────────────

  def self.parse_connection_confirm(data, offset)
    return nil if data.bytesize < offset + 12
    offset += 12  # clientID(4) + serverID(4) + instanceID(4)
    off, len = decode_uint32v(data, offset)
    return nil if len.nil? || off + len > data.bytesize
    username = data[off, len]
    { username: username }
  end

  # ── Connection Request (version info) ──────────────────────────────

  def self.parse_connection_request(data, offset)
    return nil if data.bytesize < offset + 9
    maj = data.getbyte(offset)
    min = data.getbyte(offset + 1)
    patch = data.getbyte(offset + 2)
    build = data.unpack1('V', offset: offset + 3) & 0xFFFF
    cid   = data.unpack1('V', offset: offset + 5)
    { version: "#{maj}.#{min}.#{patch} (build #{build})", client_id: cid }
  end

  # ── Full UDP Payload Parse ─────────────────────────────────────────

  def self.parse_udp_payload(data)
    hdr = parse_network_header(data)
    return nil unless hdr

    result = { header: hdr }
    case hdr[:msg_type]
    when 6, 7
      _, hb = parse_heartbeat(data, 1, is_server: hdr[:msg_type] == 7)
      result[:heartbeat] = hb
    when 2
      result[:connection_request] = parse_connection_request(data, 1)
    when 4
      result[:connection_confirm] = parse_connection_confirm(data, 1)
    end
    result
  end
end
