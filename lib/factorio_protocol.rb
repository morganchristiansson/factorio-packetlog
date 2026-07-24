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

  # ── Input Actions ──────────────────────────────────────────────────
  # [action_id] => [name, data_len]  where data_len:
  #   0 = no data, N = fixed N bytes, nil = variable/complex
  ACTIONS = {
    0=>["Nothing",0], 1=>["StopWalking",0], 2=>["BeginMining",0],
    3=>["StopMining",0], 4=>["ToggleDriving",0], 5=>["OpenGui",0],
    6=>["OpenCharacterGui",0], 7=>["OpenCurrentVehicleGui",0],
    8=>["ConnectRollingStock",0], 9=>["DisconnectRollingStock",0],
    10=>["SelectedEntityCleared",0], 11=>["ClearCursor",0],
    12=>["ResetAssemblingMachine",0], 13=>["OpenProductionGui",0],
    14=>["StopRepair",0], 15=>["CancelNewBlueprint",0],
    16=>["CloseBlueprintRecord",0], 17=>["CopyEntitySettings",0],
    18=>["PasteEntitySettings",0], 19=>["DestroyOpenedItem",0],
    20=>["CopyOpenedItem",0], 21=>["CopyLargeOpenedItem",0],
    22=>["ToggleShowEntityInfo",0], 23=>["SingleplayerInit",0],
    24=>["MultiplayerInit",0], 25=>["DisconnectAllPlayers",0],
    26=>["OpenBonusGui",0], 27=>["OpenAchievementsGui",0],
    28=>["CycleBlueprintBookForwards",0], 29=>["CycleBlueprintBookBackwards",0],
    30=>["CycleQualityUp",0], 31=>["CycleQualityDown",0],
    32=>["CycleClipboardForwards",0], 33=>["CycleClipboardBackwards",0],
    34=>["StopMovementInTheNextTick",0], 35=>["ToggleEnableVehicleLogisticsWhileMoving",0],
    36=>["ToggleDeconstructionItemEntityFilterMode",0],
    37=>["ToggleDeconstructionItemTileFilterMode",0],
    38=>["SelectNextValidGun",0], 39=>["ToggleMapEditor",0],
    40=>["DeleteBlueprintLibrary",0], 41=>["GameCreatedFromScenario",0],
    42=>["ActivatePaste",0], 43=>["Undo",0], 44=>["Redo",0],
    45=>["TogglePersonalRoboport",0], 46=>["ToggleEquipmentMovementBonus",0],
    47=>["TogglePersonalLogisticRequests",0],
    48=>["ToggleEntityLogisticRequests",0],
    49=>["ToggleArtilleryAutoTargeting",0], 50=>["StopDragBuild",0],
    51=>["FlushOpenedEntityFluid",0], 52=>nil,
    53=>["AddLogisticSection",0], 54=>["AcknowledgeTechnology",0],
    55=>["OpenOpenedEntityGrid",0], 56=>["FinishedButContinuing",0],
    57=>["ContinueSinglePlayer",0],
    58=>["OpenNewPlatformButtonFromRocketSilo",0],
    59=>["ToggleSelectedEntity",0], 60=>["Cheat",0],
    61=>nil,62=>nil,
    63=>["OpenBlueprintLibraryGui",2],64=>["ChangeBlueprintLibraryTab",2],
    65=>["DropItem",8],66=>["Build",5],67=>["StartWalking",16],
    68=>["BeginMiningTerrain",8],69=>["ChangeRidingState",2],
    70=>["ChangeHeadingRidingState",2],71=>["OpenItem",5],
    72=>["OpenParentOfOpenedItem",2],73=>["DestroyItem",8],
    74=>["OpenModItem",6],75=>nil,
    76=>["CursorTransfer",9],77=>["CursorSplit",5],
    78=>["StackTransfer",5],79=>nil,80=>nil,
    81=>["InventoryTransfer",5],82=>["CheckCRCHeuristic",nil],
    83=>["Craft",5],84=>["WireDragging",8],
    85=>["ChangeShootingState",9],86=>nil,
    87=>["SelectedEntityChanged",8],88=>nil,
    89=>["StackSplit",2],90=>["InventorySplit",8],
    91=>nil,92=>nil,93=>nil,
    94=>["CheckCRC",9],95=>nil,96=>nil,97=>nil,98=>nil,99=>nil,
    100=>["SwapLogisticFilterItems",1],101=>["SetCircuitModeOfOperation",12],
    102=>nil,103=>nil,
    104=>["WriteToConsole",nil],105=>["MarketOffer",9],
    106=>["ChangeTrainStopStation",nil],
    107=>["ChangeActiveItemGroupForCrafting",25],
    108=>["ChangeActiveItemGroupForFilters",5],
    109=>["ChangeActiveCharacterTab",1],110=>nil,
    111=>["GuiCheckedStateChanged",8],112=>nil,113=>nil,
    114=>["GuiValueChanged",23],115=>nil,
    116=>["GuiLocationChanged",23],117=>nil,
    118=>["TakeEquipment",nil],119=>["UseItem",8],120=>nil,
    121=>["SetInventoryBar",6],122=>nil,123=>["ZoomAroundPoint",24],
    124=>nil,125=>["StartRepair",8],126=>["Deconstruct",8],
    127=>nil,128=>["Copy",2],
    129=>nil,130=>nil,131=>nil,132=>nil,133=>nil,
    134=>nil,135=>nil,136=>nil,137=>nil,
    138=>["GrabBlueprintRecord",nil],139=>nil,140=>nil,
    141=>nil,142=>nil,143=>nil,144=>nil,145=>nil,
    146=>["TransferBlueprint",13],147=>["TransferBlueprintImmediately",10],
    148=>nil,149=>["RemoveCables",8],150=>nil,
    151=>["ImportBlueprint",16],152=>["ImportBlueprintsFiltered",6],
    153=>["PlayerJoinGame",nil],154=>["PlayerAdminChange",1],
    155=>["CancelDeconstruct",nil],156=>["CancelUpgrade",5],
    157=>nil,158=>nil,159=>nil,160=>nil,161=>nil,162=>nil,
    163=>nil,164=>nil,165=>nil,166=>nil,167=>nil,168=>nil,
    169=>nil,170=>nil,171=>nil,
    172=>["ChangeTrainWaitCondition",nil],173=>nil,174=>nil,
    175=>nil,176=>nil,177=>nil,178=>nil,179=>nil,180=>nil,
    181=>nil,182=>nil,183=>nil,
    184=>["CustomInput",nil],185=>["ChangeItemLabel",nil],
    186=>["ChangeEntityLabel",nil],187=>nil,188=>nil,189=>nil,
    190=>nil,191=>nil,192=>nil,
    193=>["CancelResearch",12],194=>nil,195=>nil,196=>nil,
    197=>nil,198=>nil,
    199=>["ServerCommand",4],200=>nil,201=>nil,
    202=>["SetInfinityPipeFilter",8],203=>["ModSettingsChanged",7],
    204=>["SetEntityEnergyProperty",4],205=>["EditCustomTag",2],
    206=>["EditPermissionGroup",1],207=>nil,
    208=>["ImportPermissionsString",nil],209=>["ReloadScript",nil],
    210=>nil,211=>nil,
    212=>["BlueprintTransferQueueUpdate",1],213=>["DragTrainSchedule",1],
    214=>nil,215=>["DragTrainWaitCondition",2],216=>nil,217=>nil,
    218=>["SelectEntitySlot",4],219=>nil,220=>nil,221=>nil,
    222=>nil,223=>nil,224=>nil,225=>nil,226=>nil,227=>nil,
    228=>nil,229=>nil,230=>nil,231=>nil,232=>nil,
    233=>["PlayerLeaveGame",1],234=>["MapEditorAction",1],
    235=>["PutSpecialItemInMap",1],236=>["PutSpecialRecordInMap",1],
    237=>["ChangeMultiplayerConfig",1],238=>nil,239=>nil,
    240=>["TranslateString",nil],241=>nil,242=>nil,243=>nil,
    244=>nil,245=>nil,246=>nil,247=>nil,248=>nil,249=>nil,
    250=>["ChangePickingState",1],251=>["SelectedEntityChangedVeryClose",1],
    252=>["SelectedEntityChangedVeryClosePrecise",2],
    253=>["SelectedEntityChangedRelative",4],
    254=>["SelectedEntityChangedBasedOnUnitNumber",8],
    255=>nil,256=>["SwitchConstantCombinatorState",1],
    257=>["SwitchPowerSwitchState",1],
    258=>["SwitchInserterFilterModeState",1],259=>nil,260=>nil,
    261=>nil,262=>["SwitchConnectToLogisticNetwork",1],
    263=>["SetBehaviorMode",1],264=>["FastEntityTransfer",1],
    265=>["RotateEntity",1],266=>nil,267=>["FastEntitySplit",1],
    268=>nil,269=>nil,270=>["SetAllowCommands",1],
    271=>["SetResearchFinishedStopsGame",1],
    272=>["SetInserterMaxStackSize",1],273=>nil,
    274=>["OpenTrainGui",4],275=>nil,276=>["SetEntityColor",4],
    277=>nil,278=>["SetDeconstructionItemTreesAndRocksOnly",1],
    279=>["SetDeconstructionItemTileSelectionMode",1],
    280=>["DeleteCustomTag",4],281=>["DeletePermissionGroup",4],
    282=>["AddPermissionGroup",4],
    283=>["SetInfinityContainerRemoveUnfilteredItems",1],
    284=>["SetCarWeaponsControl",1],285=>["SetRequestFromBuffers",1],
    286=>["ChangeActiveQuickBar",1],287=>["OpenPermissionsGui",1],
    288=>["DisplayScaleChanged",8],289=>["SetSplitterPriority",1],
    290=>["GrabInternalBlueprintFromText",4],
    291=>["SetHeatInterfaceTemperature",8],
    292=>["SetHeatInterfaceMode",1],293=>["OpenTrainStationGui",4],
    294=>["RenderModeChanged",1],295=>["PlayerInputMethodChanged",1],
    296=>["SetPlayerColor",4],297=>nil,
    298=>["SetTrainsLimit",4],299=>nil,
    300=>["SetLinkedContainerLinkID",4],
  }.freeze

  # Actions that are noisy/low-value for logging
  NOISE_ACTIONS = %w[WireDragging Nothing].freeze

  # Actions that may indicate griefing
  GRIEF_ACTIONS = %w[
    Cheat SetAllowCommands DestroyItem PlayerAdminChange
    ServerCommand MapEditorAction PutSpecialItemInMap
    ChangeMultiplayerConfig DeleteCustomTag EditPermissionGroup
    DeletePermissionGroup AddPermissionGroup
  ].freeze

  # ── Decoders ───────────────────────────────────────────────────────

  def self.decode_uint16v(data, offset)
    return [offset + 1, nil] if offset >= data.bytesize
    val = data.getbyte(offset)
    if val == 0xFF
      return [offset + 1, nil] if offset + 2 > data.bytesize
      return [offset + 3, data.unpack1('v', offset: offset + 1)]
    end
    [offset + 1, val]
  end

  def self.decode_uint32v(data, offset)
    return [offset + 1, nil] if offset >= data.bytesize
    val = data.getbyte(offset)
    if val == 0xFF
      return [offset + 1, nil] if offset + 4 > data.bytesize
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

    hb = { flags: data.getbyte(offset), tick_closures: [], sync_actions: [] }
    f = hb[:flags]
    hb[:has_heartbeat_requests]    = (f & 0x01) != 0
    hb[:has_tick_closures]         = (f & 0x02) != 0
    hb[:has_single_tick_closure]   = (f & 0x04) != 0
    hb[:all_tick_closures_empty]   = (f & 0x08) != 0
    hb[:has_synchronizer_action]   = (f & 0x10) != 0
    offset += 1
    return [offset, hb] if offset + 4 > data.bytesize

    hb[:seq] = data.unpack1('V', offset: offset)
    offset += 4

    # Tick closures
    if hb[:has_tick_closures]
      count = hb[:has_single_tick_closure] ? 1 : data.getbyte(offset)
      offset += 1 unless hb[:has_single_tick_closure]
      count.times do
        break if offset >= data.bytesize
        off, tc = parse_tick_closure(data, offset, hb[:all_tick_closures_empty])
        hb[:tick_closures] << tc if tc
        offset = off
      end
    end

    # Client-only: nextToReceiveServerTickClosure (8 bytes)
    if !is_server && offset + 8 <= data.bytesize
      hb[:next_receive] = data.unpack1('Q<', offset: offset)
      offset += 8
    end

    # Synchronizer actions
    if hb[:has_synchronizer_action]
      off, count = decode_uint32v(data, offset)
      offset = off
      (count || 0).times do
        break if offset >= data.bytesize
        off, sa = parse_synchronizer_action(data, offset, is_server)
        hb[:sync_actions] << sa if sa
        offset = off
      end
    end

    # Heartbeat requests
    if hb[:has_heartbeat_requests] && offset < data.bytesize
      req_count = data.getbyte(offset)
      offset += 1
      req_count.times do
        break if offset + 4 > data.bytesize
        hb[:heartbeat_requests] ||= []
        hb[:heartbeat_requests] << data.unpack1('V', offset: offset)
        offset += 4
      end
    end

    [offset, hb]
  end

  # ── Tick Closure ───────────────────────────────────────────────────

  def self.parse_tick_closure(data, offset, is_empty)
    return [offset, nil] if offset + 8 > data.bytesize
    tc = { tick: data.unpack1('Q<', offset: offset), actions: [] }
    offset += 8
    return [offset, tc] if is_empty

    off, count_flagged = decode_uint32v(data, offset)
    return [offset, tc] if count_flagged.nil?
    offset = off

    count = count_flagged >> 1
    has_segments = (count_flagged & 1) == 1
    tc[:action_count] = count

    last_index = 0xFFFF
    count.times do
      break if offset >= data.bytesize
      off, act = parse_action(data, offset, last_index)
      break unless act
      tc[:actions] << act
      last_index = act[:player]
      offset = off
    end

    # Skip segments (rare, not fully decoded yet)
    if has_segments && offset < data.bytesize
      seg_count = data.getbyte(offset)
      offset += 1 + seg_count * 4
    end

    [offset, tc]
  end

  # ── Input Action ───────────────────────────────────────────────────

  def self.parse_action(data, offset, last_index)
    off, type = decode_uint16v(data, offset)
    return [off, nil] if type.nil?
    offset = off
    off, delta = decode_uint16v(data, offset)
    return [off, nil] if delta.nil?
    offset = off

    player = (last_index + delta) & 0xFFFF
    name = action_name(type)
    alen = action_len(type)

    adata = nil
    if alen && alen > 0 && offset + alen <= data.bytesize
      adata = data[offset, alen]
      offset += alen
    elsif alen == 0
      adata = ''.b
    elsif alen.nil? && offset < data.bytesize
      adata = data[offset..]  # remainder; may overlap next action
    end

    [offset, { type: type, name: name, player: player, delta: delta, data: adata }]
  end

  # ── Synchronizer Action ────────────────────────────────────────────

  def self.parse_synchronizer_action(data, offset, is_server)
    return [offset, nil] if offset >= data.bytesize
    type = data.getbyte(offset)
    offset += 1
    name = SYNCHRONIZER_ACTIONS[type] || "Unknown(0x#{type.to_s(16)})"
    sa = { type: type, name: name }

    case type
    when 0x02 # NewPeerInfo — contains username!
      rest = data[offset..]
      if rest.bytesize > 0
        off, s_len = decode_uint32v(rest, 0)
        if s_len && off + s_len <= rest.bytesize
          sa[:username] = rest[off, s_len]
          offset += off + s_len
        end
      end
    when 0x03 # ClientChangedState
      sa[:state] = data.getbyte(offset) unless is_server
      offset += 1 unless is_server
    when 0x04 # ClientShouldStartSendingTickClosures
      sa[:data] = data[offset, 8] if offset + 8 <= data.bytesize
      offset += 8
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
