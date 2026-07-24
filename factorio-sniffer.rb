#!/usr/bin/env ruby
# factorio-sniffer — live/offline Factorio player action logger
#
# Captures UDP traffic on the Factorio port, decodes the binary protocol,
# extracts player actions, and logs them with optional grief detection.
#
# Usage:
#   Live capture: sudo ruby factorio-sniffer.rb -i eth0 -p 34197
#   Pcap analysis: ruby factorio-sniffer.rb -r capture.pcap
#   With grief detection: ... --detect-grief
#   Save player db: ... --player-db players.json

require 'json'
require 'time'

# ─────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────
DEFAULT_PORT = 34_197
DEFAULT_PLAYER_DB = 'players.json'

# ─────────────────────────────────────────────────────────────────────
# Action Definitions (from Hornwitser's factorio_dissector)
# Maps action_type_id -> [name, data_len]
# data_len: nil = variable/dissect-only, 0 = no data, N = fixed length
# ─────────────────────────────────────────────────────────────────────
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
  # 301-335: mostly newer actions, unknown
}.freeze

# Actions that may indicate griefing
GRIEF_ACTIONS = %w[
  Cheat SetAllowCommands DestroyItem PlayerAdminChange
  ServerCommand MapEditorAction PutSpecialItemInMap
  ChangeMultiplayerConfig DeleteCustomTag EditPermissionGroup
  DeletePermissionGroup AddPermissionGroup
].freeze

# ─────────────────────────────────────────────────────────────────────
# Protocol Parsing Module
# ─────────────────────────────────────────────────────────────────────
module FactorioProtocol
  MESSAGE_TYPES = {
    0=>'Ping', 1=>'PingReply', 2=>'ConnectionRequest',
    3=>'ConnectionRequestReply', 4=>'ConnectionRequestReplyConfirm',
    5=>'ConnectionAcceptOrDeny', 6=>'ClientToServerHeartbeat',
    7=>'ServerToClientHeartbeat', 8=>'GetOwnAddress',
    9=>'GetOwnAddressReply', 10=>'NatPunchRequest', 11=>'NatPunch',
    12=>'TransferBlockRequest', 13=>'TransferBlock',
    14=>'RequestForHeartbeatWhenDisconnecting', 15=>'LANBroadcast',
    16=>'GameInformationRequest', 17=>'GameInformationRequestReply',
    18=>'Empty',
  }.freeze

  NOISE_ACTIONS = %w[WireDragging Nothing].freeze

  SYNCHRONIZER_ACTIONS = {
    0x00=>'GameEnd', 0x01=>'PeerDisconnect', 0x02=>'NewPeerInfo',
    0x03=>'ClientChangedState', 0x04=>'ClientShouldStartSendingTickClosures',
    0x05=>'MapReadyForDownload', 0x06=>'MapLoadingProgressUpdate',
    0x07=>'MapSavingProgressUpdate', 0x08=>'SavingForUpdate',
    0x09=>'MapDownloadingProgressUpdate', 0x0a=>'CatchingUpProgressUpdate',
    0x0b=>'PeerDroppingProgressUpdate', 0x0c=>'PlayerDesynced',
    0x0d=>'BeginPause', 0x0e=>'EndPause', 0x0f=>'SkippedTickClosure',
    0x10=>'SkippedTickClosureConfirm', 0x11=>'ChangeLatency',
    0x12=>'IncreasedLatencyConfirm', 0x13=>'SavingCountDown',
    0x14=>'AuxiliaryDataReadyForDownload', 0x15=>'AuxiliaryDataDownloadFinished',
  }.freeze

  # ── Variable-Length Integer Decoding ───────────────────────────────

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
    }

    f = hb[:flags]
    hb[:has_heartbeat_requests] = (f & 0x01) != 0
    hb[:has_tick_closures]      = (f & 0x02) != 0
    hb[:has_single_tick_closure] = (f & 0x04) != 0
    hb[:all_tick_closures_are_empty] = (f & 0x08) != 0
    hb[:has_synchronizer_action]     = (f & 0x10) != 0
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
        offset, tc = parse_tick_closure(data, offset, hb[:all_tick_closures_are_empty])
        hb[:tick_closures] << tc if tc
      end
    end

    # Client-only: nextToReceiveServerTickClosure (8 bytes)
    if !is_server && offset + 8 <= data.bytesize
      hb[:next_receive] = data.unpack1('Q<', offset: offset)
      offset += 8
    end

    # Synchronizer actions
    if hb[:has_synchronizer_action]
      offset, count = decode_uint32v(data, offset)
      count.to_i.times do
        break if offset >= data.bytesize
        offset, sa = parse_synchronizer_action(data, offset, is_server)
        hb[:sync_actions] << sa if sa
      end
    end

    # Heartbeat requests
    if hb[:has_heartbeat_requests] && offset < data.bytesize
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
    tc = { tick: data.unpack1('Q<', offset: offset), actions: [] }
    offset += 8
    return [offset, tc] if is_empty

    # Action count with segment flag
    offset, count_flagged = decode_uint32v(data, offset)
    return [offset, tc] if count_flagged.nil?

    count = count_flagged >> 1
    has_segments = (count_flagged & 1) == 1
    tc[:action_count] = count

    last_index = 0xFFFF
    count.times do |i|
      break if offset >= data.bytesize
      offset, act = parse_action(data, offset, last_index)
      break unless act
      tc[:actions] << act
      last_index = act[:player]
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
    offset, type = decode_uint16v(data, offset)
    return [offset, nil] if type.nil?
    offset, delta = decode_uint16v(data, offset)
    return [offset, nil] if delta.nil?

    player = (last_index + delta) & 0xFFFF
    entry = ACTIONS[type]
    name = entry ? entry[0] : "Unknown(#{type})"
    alen = entry ? entry[1] : nil

    # Decode data based on known length
    adata = nil
    if alen && alen > 0 && offset + alen <= data.bytesize
      adata = data[offset, alen]
      offset += alen
    elsif alen == 0
      adata = ''.b
    elsif alen.nil?
      # Variable length — try to infer from context or mark as raw
      # For now, grab remaining data (may overlap with next action)
      adata = data[offset..]
    end

    [offset, {
      type: type, name: name, player: player, delta: delta,
      data: adata,
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
      # Format: variable-length string (username)
      if rest.bytesize > 0
        s_off, s_len = decode_uint32v(rest, 0)
        if s_len && s_off + s_len <= rest.bytesize
          sa[:username] = rest[s_off, s_len]
          offset += s_off + s_len
        end
      end
    when 0x03 # ClientChangedState
      if is_server
        # Server doesn't have data for this
      elsif rest.bytesize >= 1
        sa[:state] = rest.getbyte(0)
        offset += 1
      end
    when 0x04 # ClientShouldStartSendingTickClosures (8 bytes)
      if rest.bytesize >= 8
        sa[:data] = rest[0, 8]
        offset += 8
      end
    else
      # Skip unknown / known-without-interest
    end

    [offset, sa]
  end

  # ── Connection Request Reply Confirm (username!) ───────────────────

  def self.parse_connection_confirm(data, offset)
    return nil if data.bytesize < offset + 12
    # Skip clientID(4) + serverID(4) + instanceID(4)
    offset += 12
    # Username: variable-length string
    off, len = decode_uint32v(data, offset)
    return nil if len.nil? || off + len > data.bytesize
    username = data[off, len]
    offset = off + len
    # Password hash: variable-length string
    off, len = decode_uint32v(data, offset)
    return nil if len.nil? || off + len > data.bytesize
    offset = off + len
    # Server key & timestamp (skip)
    { username: username }
  end

  # ── Connection Request (version info) ──────────────────────────────

  def self.parse_connection_request(data, offset)
    return nil if data.bytesize < offset + 9
    maj = data.getbyte(offset)
    min = data.getbyte(offset + 1)
    patch = data.getbyte(offset + 2)
    build = data.unpack1('V', offset: offset + 3) & 0xFFFF
    client_id = data.unpack1('V', offset: offset + 5)
    {
      version: "#{maj}.#{min}.#{patch} (build #{build})",
      client_id: client_id,
    }
  end

  # ── Full packet parse ──────────────────────────────────────────────

  def self.parse_udp_payload(data)
    hdr = parse_network_header(data)
    return nil unless hdr

    result = { header: hdr }
    case hdr[:msg_type]
    when 6, 7  # Heartbeat
      _, hb = parse_heartbeat(data, 1, is_server: hdr[:msg_type] == 7)
      result[:heartbeat] = hb
    when 2  # ConnectionRequest
      result[:connection_request] = parse_connection_request(data, 1)
    when 4  # ConnectionRequestReplyConfirm
      result[:connection_confirm] = parse_connection_confirm(data, 1)
    end

    result
  end
end

# ─────────────────────────────────────────────────────────────────────
# Player Database — persists ID <-> username mapping
# ─────────────────────────────────────────────────────────────────────
class PlayerDatabase
  attr_reader :players

  def initialize(path = nil)
    @path = path
    @players = {}  # id -> name
    @id_by_name = {}  # name -> id
    load if @path && File.exist?(@path)
  end

  def lookup(id)
    @players[id] || "Player_#{id}"
  end

  def add(id, name)
    return if name.nil? || name.empty?
    @players[id.to_i] = name
    @id_by_name[name] = id.to_i
  end

  def name_to_id(name)
    @id_by_name[name]
  end

  def save
    return unless @path
    File.write(@path, JSON.pretty_generate(@players))
  end

  private

  def load
    raw = JSON.parse(File.read(@path))
    @players = raw.each_with_object({}) { |(k, v), h| h[k.to_i] = v }
    @players.each { |id, name| @id_by_name[name] = id }
  rescue JSON::ParserError
    @players = {}
    @id_by_name = {}
  end
end

# ─────────────────────────────────────────────────────────────────────
# Grief Detector
# ─────────────────────────────────────────────────────────────────────
class GriefDetector
  def initialize(window: 60)
    @window = window
    @action_log = Hash.new { |h, k| h[k] = [] }  # "#{player}_#{action}" -> [timestamps]
    @alerts = []
  end

  def record(player_name, action_name, data, timestamp)
    key = "#{player_name}_#{action_name}"

    # Flag immediate grief actions
    if GRIEF_ACTIONS.include?(action_name)
      alert = { time: Time.at(timestamp).iso8601, player: player_name,
                action: action_name, severity: 'HIGH',
                message: "#{player_name} used #{action_name}!" }
      @alerts << alert
      return alert
    end

    # Rate-based detection
    @action_log[key] << timestamp
    cutoff = timestamp - @window
    recent = @action_log[key].select { |t| t >= cutoff }

    thresholds = { 'DestroyItem' => 15, 'Deconstruct' => 20,
                   'BeginMining' => 40, 'FastEntitySplit' => 30 }
    threshold = thresholds[action_name]
    if threshold && recent.size >= threshold
      alert = { time: Time.at(timestamp).iso8601, player: player_name,
                action: action_name, count: recent.size, severity: 'MEDIUM',
                message: "#{player_name} performed #{action_name} #{recent.size}x in #{@window}s" }
      @alerts << alert
      return alert
    end

    nil
  end

  def alerts_since(time = nil)
    return @alerts unless time
    @alerts.select { |a| a[:time] >= time }
  end

  def print_alerts
    @alerts.each do |a|
      puts "  \e[#{a[:severity] == 'HIGH' ? '31' : '33'}m🚨 #{a[:message]}\e[0m"
    end
  end
end

# ─────────────────────────────────────────────────────────────────────
# PCAP Reader
# ─────────────────────────────────────────────────────────────────────
class PcapReader
  def initialize(path)
    @path = path
  end

  def each_packet(&block)
    data = File.binread(@path)
    magic = data.unpack1('V')
    endian = (magic == 0xa1b2c3d4) ? :little : :big
    raise "Not a pcap file" unless [:little, :big].include?(endian)

    gh = data.unpack(endian == :little ? 'VvvVVVV' : 'NnnNNNN')
    linktype = gh[6]
    pkt_num = 0

    offset = 24
    while offset + 16 <= data.bytesize
      ph = data.unpack(endian == :little ? 'VVVV' : 'NNNN', offset: offset)
      ts_sec, ts_usec, incl_len, _ = ph
      offset += 16
      break if offset + incl_len > data.bytesize
      pkt_data = data[offset, incl_len]
      offset += incl_len
      pkt_num += 1

      # Strip link layer
      raw = case linktype
      when 1 then pkt_data[14..]
      when 0 then pkt_data[4..]
      when 113 then pkt_data[16..]
      else pkt_data
      end
      next if raw.nil? || raw.bytesize < 28

      # Parse IP + UDP
      ihl = (raw.getbyte(0) & 0x0F) * 4
      next unless raw.getbyte(9) == 17  # UDP only
      next if raw.bytesize < ihl + 8

      sport = raw.unpack1('n', offset: ihl)
      dport = raw.unpack1('n', offset: ihl + 2)
      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.bytesize < 1

      yield(pkt_num, ts_sec + ts_usec / 1_000_000.0,
            raw[12..15].bytes.join('.'), raw[16..19].bytes.join('.'),
            sport, dport, udp_data)
    end
  end
end

# ─────────────────────────────────────────────────────────────────────
# Live Capture (pcaprub)
# ─────────────────────────────────────────────────────────────────────
class LiveCapture
  def initialize(interface:, port:, bpf: nil)
    @interface = interface
    @port = port
    @bpf = bpf || (port ? "udp port #{port}" : 'udp')
  end

  def self.list_interfaces
    require 'socket'
    Socket.getifaddrs.select { |a| a.addr&.ip? }.map { |a| a.name }.uniq
  rescue => e
    puts "Failed to list interfaces: #{e}"
    ['(none found)']
  end

  def each_packet(&block)
    require 'pcaprub'

    cap = PCAPRUB::Pcap.open_live(@interface, 65535, true, 1000)
    cap.setfilter(@bpf)

    pkt_num = 0
    loop do
      pkt = cap.next
      unless pkt
        sleep 0.01
        next
      end

      # Parse Ethernet header
      next if pkt.bytesize < 14
      eth_type = pkt.unpack1('n', offset: 12)
      next unless eth_type == 0x0800  # IPv4 only for now

      raw = pkt[14..]
      next if raw.nil? || raw.bytesize < 20

      ihl = (raw.getbyte(0) & 0x0F) * 4
      next if raw.bytesize < ihl + 8 || raw.getbyte(9) != 17

      sport = raw.unpack1('n', offset: ihl)
      dport = raw.unpack1('n', offset: ihl + 2)
      next if @port && sport != @port && dport != @port

      udp_data = raw[ihl + 8, raw.bytesize - ihl - 8]
      next if udp_data.nil? || udp_data.bytesize < 1

      ts = Time.now.to_f
      pkt_num += 1
      yield(pkt_num, ts,
            raw[12..15].bytes.join('.'),
            raw[16..19].bytes.join('.'),
            sport, dport, udp_data)
    end
  rescue PCAPRUB::PCAPRUBError => e
    puts "Capture error: #{e}"
    puts "Available interfaces: #{self.class.list_interfaces.join(', ')}"
  rescue Interrupt
    # Graceful exit
  end
end

# ─────────────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────────────
class FactorioSniffer
  def initialize(options)
    @options = options
    @player_db = PlayerDatabase.new(options[:player_db])
    @grief = options[:detect_grief] ? GriefDetector.new : nil
    @stats = { packets: 0, factorio_packets: 0, actions: 0 }
  end

  def run
    if @options[:pcap]
      reader = PcapReader.new(@options[:pcap])
      reader.each_packet { |*args| process_packet(*args) }
    elsif @options[:interface]
      capturer = LiveCapture.new(
        interface: @options[:interface],
        port: @options[:port],
      )
      puts "Listening on #{@options[:interface]} port #{@options[:port]}..."
      puts "Press Ctrl+C to stop."
      capturer.each_packet { |*args| process_packet(*args) }
    end

    print_summary
    @player_db.save
  end

  private

  def process_packet(pkt_num, ts, src_ip, dst_ip, sport, dport, udp_data)
    @stats[:packets] += 1

    parsed = FactorioProtocol.parse_udp_payload(udp_data)
    return unless parsed

    @stats[:factorio_packets] += 1
    hdr = parsed[:header]

    if parsed[:connection_confirm]
      username = parsed[:connection_confirm][:username]
    end

    return unless (hb = parsed[:heartbeat])

    # synchronizer actions (NewPeerInfo can give usernames)
    hb[:sync_actions]&.each do |sa|
      if sa[:username]
        @player_db.add(0, sa[:username])
      end
    end

    # tick closures → player actions
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each do |act|
        @stats[:actions] += 1
        log_action(ts, act, hdr[:msg_type] == 7)
      end
    end
  end

  # Decode position/data from known action types
  POSITION_ACTIONS = {
    66  => { name: 'Build',          len: 5,  desc: 'tile pos + dir' },
    67  => { name: 'StartWalking',   len: 16, desc: 'path coords' },
    68  => { name: 'BeginMiningTerrain', len: 8, desc: 'tile pos' },
    73  => { name: 'DestroyItem',    len: 8,  desc: 'entity id' },
    87  => { name: 'SelectedEntityChanged', len: 8, desc: 'entity id + player?' },
    119 => { name: 'UseItem',        len: 8,  desc: 'entity id' },
    125 => { name: 'StartRepair',    len: 8,  desc: 'entity id' },
    126 => { name: 'Deconstruct',    len: 8,  desc: 'entity id' },
    265 => { name: 'RotateEntity',   len: 1,  desc: 'direction' },
    267 => { name: 'FastEntitySplit', len: 1, desc: 'entity slot' },
  }.freeze

  def decode_action_string(act)
    return nil unless act[:data] && act[:data].bytesize > 0
    off, slen = FactorioProtocol.decode_uint32v(act[:data], 0)
    return nil unless slen && off + slen <= act[:data].bytesize
    act[:data][off, slen]
  end

  def format_action_data(act)
    return '' unless act[:data] && act[:data].bytesize > 0
    d = act[:data]

    case act[:type]
    when 67  # StartWalking — 16 bytes: likely double x, double y + path
      if d.bytesize >= 16
        x = d.unpack1('E', offset: 0)
        y = d.unpack1('E', offset: 8)
        return " pos=(#{'%.1f' % x}, #{'%.1f' % y})"
      end
    when 68  # BeginMiningTerrain — 8 bytes: likely float x, float y
      if d.bytesize >= 8
        x = d.unpack1('e', offset: 0)
        y = d.unpack1('e', offset: 4)
        return " tile=(#{'%.1f' % x}, #{'%.1f' % y})"
      end
    when 73, 87, 119, 125, 126  # entity reference — first 4 bytes likely entity_id
      if d.bytesize >= 4
        eid = d.unpack1('V')
        return " entity=##{eid}"
      end
    when 66  # Build — 5 bytes: maybe uint16 x, uint16 y + direction
      if d.bytesize >= 4
        x = d.unpack1('v', offset: 0)
        y = d.unpack1('v', offset: 2)
        dir = d.bytesize >= 5 ? d.getbyte(4) : nil
        s = " tile=(#{x}, #{y})"
        s += " dir=#{dir}" if dir
        return s
      end
    when 265  # RotateEntity — 1 byte direction
      return " dir=#{d.getbyte(0)}"
    when 267  # FastEntitySplit — 1 byte slot
      return " slot=#{d.getbyte(0)}"
    when 69  # ChangeRidingState — 2 bytes: vehicle entity id?
      return " vehicle=#{d.unpack1('v')}" if d.bytesize >= 2
    when 83  # Craft — 5 bytes: recipe?
      return " recipe_id=#{d.unpack1('V')}" if d.bytesize >= 4
    when 78, 81  # StackTransfer/InventoryTransfer — 5 bytes
      return " slot=#{d.unpack1('V')}" if d.bytesize >= 4
    when 128  # Copy — 2 bytes
      return " flags=#{d.unpack1('v')}" if d.bytesize >= 2
    when 60  # Cheat — no data
      return ''
    end

    # Fallback: show first few bytes as hex
    return '' unless @options[:verbose]
    hex = d.bytes.first(8).map { |b| '%02x' % b }.join
    " [#{hex}#{d.bytesize > 8 ? '..' : ''}]"
  end

  def log_action(ts, act, is_server)
    pname = @player_db.lookup(act[:player])
    @grief&.record(pname, act[:name], act[:data], ts)

    ts_str = Time.at(ts).strftime('%H:%M:%S.%L')
    arrow = is_server ? '<-' : '->'

    # Chat messages
    if act[:name] == 'WriteToConsole'
      msg = decode_action_string(act)
      if msg
        puts "#{ts_str}  💬 #{pname}: #{msg}"
        return
      end
    end

    # Skip noise unless verbose
    return if !@options[:verbose] && FactorioProtocol::NOISE_ACTIONS.include?(act[:name])
    return if act[:name] == 'Unknown'

    # Format action data (position, entity refs, etc.)
    data_str = format_action_data(act)
    puts "#{ts_str}  #{arrow} #{pname.ljust(16)} #{act[:name].ljust(28)}#{data_str}"
  end

  def print_summary
    puts
    puts "── Summary ──"
    puts "Packets seen: #{@stats[:packets]}"
    puts "Factorio packets: #{@stats[:factorio_packets]}"
    puts "Player actions: #{@stats[:actions]}"
    puts "Known players: #{@player_db.players.size}"
    @player_db.players.each { |id, name| puts "  Player #{id}: #{name}" }

    if @grief
      puts
      puts "── Grief Alerts ──"
      @grief.print_alerts
    end
  end
end

# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────
if __FILE__ == $PROGRAM_NAME
  require 'optparse'

  options = { port: DEFAULT_PORT, player_db: DEFAULT_PLAYER_DB }

  op = OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
    opts.separator ''
    opts.separator 'Capture sources (specify one):'
    opts.on('-i', '--interface IFACE', 'Network interface for live capture') { |v| options[:interface] = v }
    opts.on('-r', '--read PCAP', 'Read from pcap file') { |v| options[:pcap] = v }
    opts.separator ''
    opts.on('-p', '--port PORT', Integer, "UDP port (default: #{DEFAULT_PORT})") { |v| options[:port] = v }
    opts.on('--player-db PATH', "Player database file (default: #{DEFAULT_PLAYER_DB})") { |v| options[:player_db] = v }
    opts.on('-v', '--verbose', 'Verbose: print every action') { |v| options[:verbose] = v }
    opts.on('--detect-grief', 'Enable grief detection heuristics') { |v| options[:detect_grief] = v }
    opts.on('--list-interfaces', 'List available network interfaces') { |v| options[:list_interfaces] = v }
    opts.on('--map-player ID:NAME', 'Map player ID to name (e.g. 1:dlbattle)') do |v|
      (options[:player_maps] ||= []) << v
    end
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end

  op.parse!

  if options[:list_interfaces]
    puts "Available interfaces: #{LiveCapture.list_interfaces.join(', ')}"
    exit 0
  end

  # Apply player mappings to the DB before starting
  db = PlayerDatabase.new(options[:player_db])
  (options[:player_maps] || []).each do |m|
    id, name = m.split(':', 2)
    db.add(id.to_i, name)
    puts "Mapped Player #{id} -> #{name}"
  end
  db.save

  unless options[:interface] || options[:pcap]
    puts op
    puts
    puts 'Error: specify --interface or --read'
    exit 1
  end

  unless Process.uid == 0 || options[:pcap]
    puts 'Warning: live capture requires root. Try: sudo ...'
  end

  FactorioSniffer.new(options).run
end
