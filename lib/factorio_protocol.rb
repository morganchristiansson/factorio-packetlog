# frozen_string_literal: true

# Factorio UDP protocol parser.
# Based on Hornwitser's Wireshark dissector (reverse-engineered from factorio.pdb).
module FactorioProtocol
  require_relative 'factorio_protocol/packets/heartbeat_packet'
  require_relative 'factorio_protocol/packets/connection_packets'
  require_relative 'input_actions_20'

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

  # Data lengths for synchronizer action types (bytes after type byte, before peer_id).
  # nil = variable-length (handled by parse_synchronizer_action case logic).
  SYNC_ACTION_LENS = {
    0x00 => 0, 0x01 => 1, 0x02 => nil, 0x03 => nil, 0x04 => 8,
    0x05 => nil, 0x06 => 1, 0x07 => 1, 0x08 => 0,
    0x09 => 1, 0x0a => 1, 0x0b => 1, 0x0c => 0,
    0x0d => 0, 0x0e => 0, 0x0f => nil, 0x10 => nil,
    0x11 => 1, 0x12 => 5, 0x13 => 8, 0x14 => 8, 0x15 => 0,
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
  5=>["open_gui",14],
  6=>["open_current_vehicle_gui",0],
  7=>["connect_rolling_stock",4],
  8=>["disconnect_rolling_stock",4],
  9=>["selected_entity_cleared",8],
  10=>["clear_cursor",0],
  11=>["reset_assembling_machine",0],
  13=>["cancel_new_blueprint",0],
  15=>["copy_entity_settings",0],
  16=>["paste_entity_settings",0],
  17=>["destroy_opened_item",0],
  18=>["copy_opened_item",0],
  19=>["copy_large_opened_item",0],
  23=>["open_bonus_gui",0],
  24=>["open_achievements_gui",0],
  25=>["cycle_blueprint_book_forwards",0],
  26=>["cycle_blueprint_book_backwards",0],
  27=>["cycle_quality_up",1],
  28=>["cycle_quality_down",0],
  32=>["toggle_enable_vehicle_logistics_while_moving",0],
  33=>["toggle_deconstruction_item_entity_filter_mode",0],
  34=>["toggle_deconstruction_item_tile_filter_mode",0],
  35=>["select_next_valid_gun",0],
  36=>["toggle_map_editor",0],
  37=>["delete_blueprint_library",0],
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
  51=>["add_logistic_section",0],
  53=>["open_opened_entity_grid",0],
  56=>["open_new_platform_button_from_rocket_silo",0],
  57=>["toggle_selected_entity",0],
  58=>["cheat",0],
  59=>["toggle_blueprint_snap_to_grid",0],
  60=>["close_gui",2],
  61=>["open_character_gui",15],
  62=>["open_production_gui",0],
  63=>["open_logistics_gui",0],
  64=>["open_blueprint_library_gui",15],
  65=>["toggle_show_entity_info",1],
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
  84=>["server_tick_info",12],
  85=>["craft",7],
  86=>["wire_dragging",8],
  87=>["change_shooting_state",9],
  88=>["setup_assembling_machine",2],
  90=>["pipette",9],
  91=>["stack_split",2],
  92=>["inventory_split",8],
  93=>["cancel_craft",0],
  94=>["set_filter",nil],
  95=>["set_spoil_priority",nil],
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
  107=>["market_offer",nil],
  108=>["change_train_stop_station",0],
  109=>["change_active_item_group_for_crafting",2],
  110=>["change_active_item_group_for_filters",15],
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
  128=>["zoom_around_point",24],
  129=>["move_on_pan",17],
  130=>["start_repair",8],
  131=>["deconstruct",16],
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
  153=>["edit_blueprint_tool_preview",nil],
  154=>["remove_cables",8],
  155=>["export_blueprint",nil],
  156=>["import_blueprint",16],
  157=>["import_blueprints_filtered",6],
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
  209=>["super_forced_select_area",0],
  210=>["reverse_select_area",0],
  211=>["alt_reverse_select_area",nil],
  212=>["set_infinity_container_filter_item",0],
  213=>["set_infinity_container_filter_item",0],
  214=>["set_infinity_container_logistic_mode",0],
  215=>["swap_infinity_container_filter_items",8],
  216=>["set_infinity_pipe_filter",7],
  217=>["mod_settings_changed",4],
  218=>["set_entity_energy_property",0],
  219=>["set_equipment_energy_property",2],
  220=>["edit_custom_tag",1],
  221=>["edit_permission_group",0],
  222=>["import_blueprint_string",0],
  223=>["import_permissions_string",nil],
  225=>["gui_elem_changed",nil],
  226=>["gui_elem_changed",nil],
  227=>["drag_train_schedule",1],
  228=>["drag_train_schedule",0],
  229=>["drag_train_schedule_interrupt",2],
  230=>["drag_train_wait_condition",0],
  231=>["select_item_filter",0],
  232=>["swap_item_filters",4],
  233=>["select_entity_slot",0],
  234=>["swap_entity_slots",0],
  235=>["select_entity_filter_slot",0],
  236=>["swap_entity_filter_slots",0],
  237=>["select_asteroid_chunk_slot",0],
  238=>["swap_asteroid_chunk_slots",0],
  239=>["select_tile_slot",0],
  240=>["swap_tile_slots",0],
  241=>["select_mapper_slot_from",0],
  242=>["select_mapper_slot_to",0],
  243=>["swap_mappers",nil],
  244=>["quick_bar_set_slot",9],
  245=>["quick_bar_set_slot",2],
  246=>["quick_bar_pick_slot",0],
  247=>["quick_bar_set_selected_page",nil],
  248=>["map_editor_action",1],
  249=>["map_editor_action",nil],
  251=>["change_multiplayer_config",1],
  252=>["change_multiplayer_config",0],
  253=>["admin_action",0],
  254=>["lua_shortcut",nil],
  255=>["create_space_platform",0],
  256=>["create_space_platform",0],
  257=>["delete_space_platform",0],
  258=>["cancel_delete_space_platform",0],
  259=>["rename_space_platform",nil],
  260=>["remote_view_surface",0],
  261=>["remote_view_entity",nil],
  262=>["close_remote_view",2],
  263=>["instantly_create_space_platform",nil],
  264=>["flush_opened_entity_specific_fluid",1],
  265=>["change_picking_state",1],
  266=>["selected_entity_changed_very_close",1],
  267=>["selected_entity_changed_very_close_precise",2],
  268=>["selected_entity_changed_relative",4],
  269=>["set_combinator_description",nil],
  270=>["set_combinator_description",1],
  271=>["switch_constant_combinator_state",1],
  272=>["switch_power_switch_state",1],
  273=>["switch_inserter_filter_mode_state",0],
  274=>["set_use_inserter_filters",0],
  275=>["switch_loader_filter_mode",0],
  276=>["switch_mining_drill_filter_mode_state",1],
  277=>["switch_connect_to_logistic_network",1],
  278=>["set_behavior_mode",1],
  279=>["fast_entity_transfer",1],
  280=>["rotate_entity",1],
  281=>["flip_entity",1],
  282=>["fast_entity_split",nil],
  283=>["request_missing_construction_materials",0],
  284=>["providing_to_other_platforms",0],
  285=>["trash_not_requested_items",nil],
  286=>["set_research_finished_stops_game",1],
  287=>["set_research_finished_stops_game",1],
  288=>["set_inserter_max_stack_size",0],
  289=>["set_loader_belt_stack_size_override",4],
  290=>["open_train_gui",nil],
  291=>["open_trains_gui",4],
  292=>["set_entity_color",0],
  293=>["set_copy_color_from_train_stop",1],
  294=>["set_deconstruction_item_trees_and_rocks_only",1],
  295=>["set_deconstruction_item_tile_selection_mode",4],
  296=>["delete_custom_tag",4],
  297=>["delete_permission_group",4],
  298=>["add_permission_group",1],
  299=>["set_infinity_container_remove_unfiltered_items",1],
  300=>["set_car_weapons_control",1],
  301=>["set_request_from_buffers",1],
  302=>["change_active_quick_bar",nil],
  304=>["set_splitter_priority",1],
  305=>["set_splitter_priority",nil],
  306=>["set_heat_interface_temperature",8],
  307=>["set_heat_interface_temperature",1],
  308=>["set_heat_interface_mode",4],
  309=>["open_train_station_gui",nil],
  310=>["render_mode_changed",1],
  311=>["set_player_color",4],
  312=>["set_player_color",nil],
  313=>["set_trains_limit",4],
  314=>["set_trains_limit",nil],
  315=>["set_linked_container_link_i_d",4],
  316=>["set_linked_container_link_i_d",0],
  317=>["set_turret_ignore_unlisted",0],
  318=>["set_lamp_always_on",0],
  319=>["open_global_electric_network_gui",0],
  320=>["set_pump_fluid_filter",nil],
  321=>["remove_logistic_section",0],
  322=>["remove_logistic_section",0],
  323=>["edit_display_panel",0],
  324=>["edit_display_panel_always_show",0],
  325=>["edit_display_panel_show_in_chart",0],
  326=>["edit_display_panel_icon",0],
  327=>["edit_display_panel_parameters",0],
  328=>["edit_display_panel_single_entry",0],
  329=>["reorder_logistic_section",0],
  330=>["set_logistic_section_active",0],
  331=>["add_pin",0],
  332=>["pin_search_result",0],
  333=>["pin_alert_group",0],
  334=>["pin_custom_alert",0],
  335=>["edit_pin",0],
  336=>["remove_pin",0],
  337=>["move_pin",0],
  338=>["send_train_to_pin_target",nil],
  339=>["gui_hover",nil],
  340=>["gui_leave",nil],
  341=>["spectator_change_surface",0],
  342=>["spectator_change_surface",0],
  343=>["adjust_blueprint_snapping",0],
  344=>["set_train_stop_priority",nil],
  345=>["land_at_planet",0],
  346=>["land_at_planet",nil],
  348=>["parametrise_blueprint",0],
  349=>["parametrise_blueprint",nil],
  350=>["set_rocket_silo_send_to_orbit_automated_mode",0],
  351=>["set_rocket_silo_send_to_orbit_automated_mode",nil],
  354=>["set_control_behavior_input_networks",0],
  355=>["set_control_behavior_input_networks",0],
}.freeze

  NOISE_ACTIONS = %w[wire_dragging nothing].freeze
  GRIEF_ACTIONS = %w[
    Cheat SetAllowCommands DestroyItem PlayerAdminChange
    ServerCommand MapEditorAction PutSpecialItemInMap
    ChangeMultiplayerConfig DeleteCustomTag EditPermissionGroup
    DeletePermissionGroup AddPermissionGroup
  ].freeze

  # ── Variable-Length Integer Decoding ───────────────────────────────
  # Shared primitives live in WireDecode (mixed into packet classes too);
  # the module extends it so `FactorioProtocol.decode_uint16v` etc. still
  # work for legacy callers and specs.
  extend WireDecode

  # ── Action Name / Length Lookup ────────────────────────────────────

  def self.action_name(type)
    entry = actions[type]
    entry ? entry[0] : "Unknown(#{type})"
  end

  def self.action_len(type)
    entry = actions[type]
    entry ? entry[1] : nil
  end

  # ── Version-dependent tables (2.0 vs 2.1) ───────────────────────

  # The wire numbering of input actions is version-dependent: 2.0 and 2.1
  # use different defines.input_action values (verified on a live 2.0.77
  # session — start_walking=67, write_to_console=104 — vs the 2.1 table's
  # 69 / 106). ACTIONS (below) is the 2.1 mapping; ACTIONS_20 is 2.0.
  #
  # Main action types and input-action SEGMENT types BOTH follow the
  # server version's enum. select_version picks both maps; defaults to 2.1
  # (ACTIONS). Survives hot reloads via SnifferState + #select_version.
  class << self
    attr_accessor :actions, :segment_types
  end
  self.actions = ACTIONS
  self.segment_types = ACTIONS

  # Name for an input-action segment type under the selected protocol
  # version. Values in SEGMENT_TYPES_20 are bare strings; ACTIONS entries
  # are [name, data_len] pairs.
  def self.segment_action_name(type)
    entry = segment_types[type]
    name = entry.is_a?(Array) ? entry[0] : entry
    name || "Unknown(#{type})"
  end

  # Pick the main-action + segment-type mapping for a server version
  # string ("2.0.77", "2.1", or a bare "2.0"). Anything 2.0.x uses the
  # defines dump; 2.1+ (and unknown) keep the main ACTIONS table. Returns
  # the chosen label ("2.0" / "2.1+") for logging.
  def self.select_version(version)
    if version.to_s.match?(/\A2\.0(\.|\z)/)
      self.actions = ACTIONS_20
      self.segment_types = SEGMENT_TYPES_20
      '2.0'
    else
      self.actions = ACTIONS
      self.segment_types = ACTIONS
      '2.1+'
    end
  end

  # ── Network Header ─────────────────────────────────────────────────

  # Message types that always carry a 2-byte message_id after the flags
  # byte, even without the fragmented flag (per factorio_dissector).
  ALWAYS_HAS_MESSAGE_ID_TYPES = [2, 4].freeze

  def self.parse_network_header(data)
    return nil if data.bytesize < 1
    flags = data.getbyte(0)
    msg_type = flags & 0x1F
    hdr = {
      flags: flags,
      msg_type: msg_type,
      msg_name: MESSAGE_TYPES[msg_type] || "Unknown(#{msg_type})",
      has_random: (flags & 0x20) != 0,
      fragmented: (flags & 0x40) != 0,
      last_frag: (flags & 0x80) != 0,
      header_size: 1,
    }

    # Variable-length header: flags(1), then when fragmented or the type
    # always carries it: message_id(2, bit15=confirm) + frag_number(1 if
    # fragmented) + confirm_count(1) + count*4 confirm items.
    # Verified: ConnectionAcceptOrDeny pkt header = 9 bytes
    # (0xc5 2f 85 00 01 01 00 00 00: flags + msg_id(0x852f, confirm) +
    #  frag_number + confirm_count(1) + confirm_item(0x00000001)).
    if hdr[:fragmented] || ALWAYS_HAS_MESSAGE_ID_TYPES.include?(msg_type)
      return hdr if data.bytesize < 3
      msg_id = data.unpack1('v', offset: 1)
      hdr[:message_id] = msg_id
      hdr[:confirm] = (msg_id & 0x8000) != 0
      hdr[:header_size] = 3
      if hdr[:fragmented]
        hdr[:frag_number] = data.getbyte(3)
        hdr[:header_size] = 4
      end
      if hdr[:confirm] && data.bytesize > hdr[:header_size]
        count = data.getbyte(hdr[:header_size])
        hdr[:confirm_count] = count
        hdr[:header_size] += 1
        hdr[:confirm_items] = []
        count.to_i.times do
          break if hdr[:header_size] + 4 > data.bytesize
          hdr[:confirm_items] << data.unpack1('V', offset: hdr[:header_size])
          hdr[:header_size] += 4
        end
      end
    end
    hdr
  end

  # ── Length-Prefixed String ─────────────────────────────────────────

  # [uint32v len][bytes] — returns [next_offset, string] or [nil, nil]

  # ── Full UDP Payload Parse ─────────────────────────────────────────

  def self.parse_udp_payload(data)
    hdr = parse_network_header(data)
    return nil unless hdr

    case hdr[:msg_type]
    when 6, 7
      # Heartbeat payload always starts at byte 1. The random flag (0x20) is
      # header metadata only — it does NOT add bytes before the heartbeat
      # (verified against factorio_dissector and live captures; treating it
      # as a 4-byte offset silently dropped ~half of all heartbeat actions).
      return nil if hdr[:fragmented]  # fragment payload is not a full message
      HeartbeatPacket.parse(data).result
    when 2
      ConnectionRequestPacket.parse(data).result
    when 4
      ConnectionConfirmPacket.parse(data).result
    when 5
      ConnectionAcceptPacket.parse(data).result
    else
      { header: hdr }
    end
  end

  # ── Chat Message Decoding (write_to_console) ─────────────────────

  # Decode a write_to_console message payload into a plain string.
  # Returns nil when the data is empty or not decodable.
  #
  # Observed payload formats (first byte is a message-type marker):
  #   [0x04][text...]                    non-segment message, text to end
  #   [0x05][meta(1)][text...]           segment message; meta = TOTAL message
  #                                      length across segments; text to end
  #   [0x0b][meta(1)][text...]           same layout as 0x05 (observed live)
  #   [0x00|0x3d|0x01][meta(1)][text...] server echoes, text to end
  #   localized string                   protobuf-like [key][mode][params...]
  #   [uint32v len][text]                main-action-list form
  #   raw text                           no prefix at all
  def self.decode_chat(data)
    return nil unless data && data.bytesize > 0
    d = data.dup.force_encoding('BINARY')

    # [0x04][text...] — non-segment format, text runs to end of payload
    if d.getbyte(0) == 0x04 && d.bytesize > 1
      return d[1..-1].force_encoding('UTF-8')
    end

    # [0x05|0x0b|0x24|0x29][meta(1)][text...] — meta byte is the TOTAL
    # message length (may span multiple segments). Text runs to end of payload,
    # NOT meta bytes — truncating to meta truncates long messages split across
    # segments (partials are returned for in-flight splits; the sniffer
    # reassembles them, see FactorioSniffer#chat_action_data).
    if [0x05, 0x0b, 0x24, 0x29].include?(d.getbyte(0)) && d.bytesize >= 2
      text = d[2..-1]
      return nil if text.empty?   # [type][meta] with no text = empty message
      return text.force_encoding('UTF-8')
    end

    # Live-observed chat tones [0x15|0x1f|0x2d|0x30][len][text] — same
    # layout. Stripped only when byte1 is a plausible length for the
    # remaining payload: 0x2d is '-' and 0x30 is '0', common first
    # characters of RAW text, so a length check avoids mangling those.
    # (Complete messages have len == bytesize - 2.)
    if [0x15, 0x1f, 0x2d, 0x30].include?(d.getbyte(0)) && d.bytesize >= 2
      len = d.getbyte(1)
      return nil if len == 0 && d.bytesize == 2   # empty message
      return d[2..-1].force_encoding('UTF-8') if len > 0 && len <= d.bytesize - 2
    end

    # Server echo formats: [0x00|0x3d|0x01][meta(1)][text...]
    if d.getbyte(0) == 0x00 && d.bytesize > 2
      return d[2..-1].force_encoding('UTF-8')
    end
    if d.getbyte(0) == 0x3d && d.bytesize > 2
      return d[2..-1].force_encoding('UTF-8')
    end
    if d.getbyte(0) == 0x01 && d.bytesize > 2
      return d[2..-1].force_encoding('UTF-8')
    end

    # Localized string format: [key_uint32v][mode(1)][params_count(1)][params...]
    # mode: 0=Empty, 1=Translation, 2=Literal, 3=LiteralTranslation
    msg = decode_localized_string(d)
    return msg if msg

    # Main action list format: [uint32v len][text]
    off, slen = decode_uint32v(d, 0)
    if slen && slen > 0 && off + slen <= d.bytesize
      return d[off, slen].force_encoding('UTF-8')
    end

    # Raw text (no prefix)
    d.force_encoding('UTF-8')
  end

  # Recursively decode a localized string (Factorio's protobuf-like format).
  # Format: [key_uint32v][mode(1)][params_count(1)][params...]
  # mode: 0=Empty, 1=Translation, 2=Literal, 3=LiteralTranslation
  def self.decode_localized_string(data, depth = 0)
    return nil if depth > 6 || data.bytesize < 4

    off, slen = decode_uint32v(data, 0)
    return nil unless slen && slen > 0 && off + slen + 2 <= data.bytesize

    key = data[off, slen].force_encoding('UTF-8')
    mode = data.getbyte(off + slen)
    pcount = data.getbyte(off + slen + 1)
    pos = off + slen + 2

    case mode
    when 0 then return ''                           # Empty
    when 2 then return key                          # Literal: key is the text
    when 3 then                                     # LiteralTranslation
      parts = [key]
      pcount.times do
        sub = decode_localized_string(data[pos..], depth + 1)
        break unless sub
        parts << sub
        pos = advance_ls(data, pos)
      end
      return parts.join('')
    when 1                                          # Translation
      parts = []
      pcount.times do
        sub = decode_localized_string(data[pos..], depth + 1)
        break unless sub
        parts << sub
        pos = advance_ls(data, pos)
      end
      return "[#{key}](#{parts.join(', ')})" if parts.any?
      return "[#{key}]"
    end
    nil
  end

  # Advance past one localized string, return next byte offset
  def self.advance_ls(data, offset)
    return data.bytesize if offset >= data.bytesize
    off, slen = decode_uint32v(data, offset)
    return data.bytesize unless slen
    off += slen
    return data.bytesize if off + 2 > data.bytesize
    pcount = data.getbyte(off + 1)
    off += 2
    pcount.to_i.times do
      off = advance_ls(data, off)
      break if off >= data.bytesize
    end
    off
  end
end
