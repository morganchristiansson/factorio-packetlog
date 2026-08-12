# frozen_string_literal: true

require 'rcon'
require_relative 'server_detect'

# RCON wrapper for the Factorio server, used to query the connected-player
# roster ({index, name} pairs) at startup.
#
# Getting data OUT of a Lua command over RCON: the console's `rcon` object
# sends its argument back through the RCON connection as the command
# response — the one clean channel:
#   /sc rcon.print(serpent.line(t))  →  body == "{{i = 1, n = \"morganc\"}}\n"
#
# The built-in `/players` command also works over RCON but only lists NAMES
# (no player index), so it can't bind actions — which carry game player
# indexes — to names. serpent.line is available in the console environment.
class RconClient
  # One-liner (keeps the reported Lua line number at 1) building
  # {index, name} pairs for connected players.
  ROSTER_LUA = 'local t={} for _,p in pairs(game.connected_players) do t[#t+1]={i=p.index,n=p.name} end rcon.print(serpent.line(t))'

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
  def self.parse_roster(body)
    return nil unless body
    body = body.strip
    records = body.scan(/\{i = (\d+), n = "((?:[^"\\]|\\.)*)"\}/)
    return nil if records.empty? && !body.include?('{}')
    records.map { |i, n| { index: i.to_i, name: n.gsub(/\\(.)/, '\1') } }
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

  # Write item + entity prototype name dumps to the server's script-output
  # dir (files factorio-sniffer-items.txt / factorio-sniffer-entities.txt)
  # via helpers.write_file. Returns true when the command ran; the caller
  # must read the files back (see ServerDetect.script_output_dir).
  def dump_prototype_files
    execute(DUMP_PROTOTYPES_LUA)
    true
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
