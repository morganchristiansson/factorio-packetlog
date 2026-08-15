# frozen_string_literal: true

require 'json'
require 'rcon'
require_relative 'server_detect'

# RCON wrapper for the Factorio server, used to query the connected-player
# roster ({index, name} pairs) at startup.
#
# Getting data OUT of a Lua command over RCON: the console's `rcon` object
# sends its argument back through the RCON connection as the command
# response — the one clean channel:
#   /sc rcon.print(helpers.table_to_json(t))  →  body == a JSON string
#
# JSON (helpers.table_to_json) beats serpent.line + regex: serpent emits
# Lua table syntax with NO guaranteed key order (it sorts keys
# alphabetically, which silently broke an order-sensitive regex), and
# escapes must be hand-unescaped. JSON parses with stdlib JSON.parse.
#
# The built-in `/players` command also works over RCON but only lists NAMES
# (no player index), so it can't bind actions — which carry game player
# indexes — to names.
class RconClient
  # One-liner (keeps the reported Lua line number at 1) building
  # {index, name} pairs for connected players as JSON.
  ROSTER_LUA = 'local t={} for _,p in pairs(game.connected_players) do t[#t+1]={i=p.index,n=p.name} end rcon.print(helpers.table_to_json(t))'

  # One-liner returning player attributes for ALL known players (incl.
  # offline) — index, name, connected, admin, online_time (total ticks
  # across all sessions), afk_time (ticks since last action). Seeds
  # PlayerAttrs at startup; afterwards the sniffer maintains these from
  # the packet stream. Note the ~4KB rcon.print cap: very large rosters
  # may be truncated (players dropped from the tail — acceptable, attrs
  # are enrichment).
  PLAYER_ATTRS_LUA =
    'local t={} for _,p in pairs(game.players) do t[#t+1]={i=p.index,n=p.name,c=p.connected,a=p.admin,o=p.online_time,k=p.afk_time} end rcon.print(helpers.table_to_json(t))'

  # One-liner dumping ALL item + entity prototype names to script-output via
  # helpers.write_file (see docs/rcon-knowledge.md). The wire protocol's
  # 1-indexed ids ARE the `prototypes.<kind>` iteration order
  # (capture-verified: pipette refs, e.g. entity 87=stone-furnace,
  # item 87=nuclear-reactor). NOTE: game.item_prototypes does NOT exist at
  # runtime; `prototypes.<kind>` (console global) is the source. Must stay
  # one line — /sc only applies to the first line.
  DUMP_PROTOTYPES_LUA =
    'local function d(k,f) local n={} for x in pairs(prototypes[k]) do n[#n+1]=x end ' \
    'local o={} for i=1,#n do o[#o+1]=i.." = "..n[i] end helpers.write_file(f,table.concat(o,"\n")) end ' \
    'd("item","factorio-sniffer-items.txt") d("entity","factorio-sniffer-entities.txt")'

  # Build a client from ServerDetect.detect output, or nil when no RCON
  # endpoint was detected.
  def self.from_detected(detected)
    return nil unless detected && detected[:rcon_port]
    new(host: detected[:rcon_host] || 'localhost',
        port: detected[:rcon_port],
        password: detected[:rcon_password],
        script_output_dir: ServerDetect.script_output_dir(detected[:pid]))
  end

  # Parse a bare rcon.print roster payload into [{index:, name:}].
  # Returns [] for a valid empty roster, nil when the payload isn't a roster.
  # Parse a JSON roster payload (see ROSTER_LUA) into [{index:, name:}].
  # Returns [] for a valid empty roster, nil when the payload isn't JSON.
  # A truncated payload (rcon.print cap) parses as a partial list.
  def self.parse_roster(body)
    parsed = parse_json(body)
    return nil unless parsed.is_a?(Array)
    parsed.filter_map do |r|
      next unless r.is_a?(Hash) && r['i'] && r['n']
      { index: r['i'].to_i, name: r['n'].to_s }
    end
  end

  # Parse a player-attributes payload (see PLAYER_ATTRS_LUA) into
  # [{index:, name:, connected:, admin:, online_time:, afk_time:}]. Returns
  # nil when the payload isn't one. A truncated payload (rcon.print cap)
  # parses as a partial list.
  #
  # JSON (helpers.table_to_json) instead of serpent.line: serpent sorts
  # keys alphabetically (a, c, i, k, n, o), which silently broke an
  # order-sensitive regex — the attrs seed never populated.
  def self.parse_player_attrs(body)
    parsed = parse_json(body)
    return nil unless parsed.is_a?(Array)
    parsed.filter_map do |r|
      next unless r.is_a?(Hash) && r['i'] && r['n']
      { index: r['i'].to_i,
        name: r['n'].to_s,
        connected: r['c'] == true,
        admin: r['a'] == true,
        online_time: r['o'].to_i,
        afk_time: r['k'].to_i }
    end
  end

  # Parse the rcon.print body as JSON (helpers.table_to_json output).
  # Returns the parsed value, or nil for non-JSON payloads.
  def self.parse_json(body)
    return nil unless body && !body.strip.empty?
    JSON.parse(body.strip)
  rescue JSON::ParserError
    nil
  end

  def initialize(host:, port:, password:, script_output_dir: nil)
    @host, @port, @password = host, port, password
    @script_output_dir = script_output_dir
    @client = connect
    @mutex = Mutex.new
  end

  # <user-data>/script-output — where helpers.write_file output lands.
  attr_reader :script_output_dir

  # [{index:, name:}] for connected players, or nil if the query failed.
  def connected_players
    self.class.parse_roster(execute(ROSTER_LUA))
  end

  # [{index:, name:, connected:, admin:, online_time:}] for ALL known
  # players (incl. offline), or nil if the query failed.
  def player_attributes
    self.class.parse_player_attrs(execute(PLAYER_ATTRS_LUA))
  end

  # Write item + entity prototype name dumps to the server's script-output
  # dir (files factorio-sniffer-items.txt / factorio-sniffer-entities.txt)
  # via helpers.write_file. Returns true when the command ran; the caller
  # must read the files back (see ServerDetect.script_output_dir).
  def dump_prototype_files
    execute(DUMP_PROTOTYPES_LUA)
    true
  end

  # Send a chat message visible to all players (game.print via /sc). The
  # message is Lua-string-quoted, so arbitrary content (quotes, backslashes,
  # newlines) can't break out of the string or inject Lua. Used by the
  # HiveMind agent to reply to in-game chat.
  def say(text)
    return if text.nil? || text.empty?
    escaped = text.gsub('\\', '\\\\').gsub('"', '\\"').gsub(/[\r\n]+/, ' ')
    execute("game.print(\"#{escaped}\")")
  end

  # Server version string (e.g. "2.0.77") via the rcon.print data channel
  # (helpers.game_version — game.version doesn't exist), or nil on failure.
  # Used to pick the protocol's segment-type mapping
  # (FactorioProtocol.select_version).
  def server_version
    body = execute('rcon.print(helpers.game_version)').strip
    body.empty? ? nil : body
  end

  # Run an arbitrary RCON console command (raw, NO /sc Lua prefix) and
  # return its body. Used by the Hivemind agent's rcon_query tool — the
  # model passes full commands like "/players" or "/sc rcon.print(...)".
  # Reconnects once on failure, same as #execute.
  def command(cmd)
    body = nil
    @mutex.synchronize { body = @client.execute(cmd).body.to_s }
    body
  rescue => e
    begin
      @client = connect
      @mutex.synchronize { @client.execute(cmd).body.to_s }
    rescue => e2
      warn "RCON execute failed: #{e2.class}: #{e2.message}"
      ''
    end
  end

  private

  def connect
    c = Rcon::Client.new(host: @host, port: @port, password: @password)
    c.authenticate!(ignore_first_packet: false)  # Factorio sends ONE auth reply
    c
  end

  def execute(cmd)
    body = nil
    @mutex.synchronize { body = @client.execute("/sc #{cmd}").body.to_s }
    body
  rescue => e
    # Connection lost (server restart, network blip) — reconnect once.
    begin
      @client = connect
      @mutex.synchronize { @client.execute("/sc #{cmd}").body.to_s }
    rescue => e2
      warn "RCON execute failed: #{e2.class}: #{e2.message}"
      ''
    end
  end
end
