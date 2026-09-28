# frozen_string_literal: true

require 'json'
require 'rcon'
require_relative 'player_db'

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
  # One-liner returning player attributes for ALL known players (incl.
  # offline) — index, name, connected, admin, online_time (total ticks
  # across all sessions), afk_time (ticks since last action), locale.
  # Seeds PlayerAttrs at startup; afterwards the sniffer maintains these from
  # the packet stream. Same write_file/print duality as the roster — at
  # ~80 B/player the attrs JSON exceeds the 4KB rcon.print cap beyond
  # ~50 players.
  PLAYER_ATTRS_FILENAME = 'factorio-packettools-attrs.json'
  PLAYER_ATTRS_WRITE_LUA =
    'local t={} for _,p in pairs(game.connected_players) do t[#t+1]={i=p.index,n=p.name,c=p.connected,a=p.admin,o=p.online_time,k=p.afk_time,l=p.locale} end helpers.write_file(' + PLAYER_ATTRS_FILENAME.inspect + ', helpers.table_to_json(t), false, 0)'
  PLAYER_ATTRS_PRINT_LUA =
    'local t={} for _,p in pairs(game.connected_players) do t[#t+1]={i=p.index,n=p.name,c=p.connected,a=p.admin,o=p.online_time,k=p.afk_time,l=p.locale} end rcon.print(helpers.table_to_json(t))'

  # One-liner dumping ALL item + entity prototype names to script-output via
  # helpers.write_file (see docs/rcon-knowledge.md). The wire protocol's
  # 1-indexed ids ARE the `prototypes.<kind>` iteration order
  # (capture-verified: pipette refs, e.g. entity 87=stone-furnace,
  # item 87=nuclear-reactor). NOTE: game.item_prototypes does NOT exist at
  # runtime; `prototypes.<kind>` (console global) is the source. Must stay
  # one line — /sc only applies to the first line.
  DUMP_PROTOTYPES_LUA =
    'local function d(k,f) local n={} for x in pairs(prototypes[k]) do n[#n+1]=x end ' \
    'local o={} for i=1,#n do o[#o+1]=i.." = "..n[i] end helpers.write_file(f,table.concat(o,"\n"), false, 0) end ' \
    'd("item","factorio-packettools-items.txt") d("entity","factorio-packettools-entities.txt")'

  # Parse a player-attributes payload into
  # [{index:, name:, connected:, admin:, online_time:, afk_time:, locale:,
  #   quickbar:}]. Returns nil when the payload isn't one. A truncated
  # payload (rcon.print cap) parses as a partial list. `quickbar` is only in
  # the join-time query's payload (see #player_attributes_for); nil for the
  # all-players dump.
  #
  # Both query shapes land here: the all-players dump is a JSON ARRAY of
  # records, the join-time one a single record OBJECT (live-verified — the
  # old parser demanded an Array, so that query could never parse).
  #
  # JSON (helpers.table_to_json) instead of serpent.line: serpent sorts
  # keys alphabetically (a, c, i, k, l, n, o), which silently broke an
  # order-sensitive regex — the attrs seed never populated.
  def self.parse_player_attrs(body)
    parsed = parse_json(body)
    return nil if parsed.nil?
    records = parsed.is_a?(Array) ? parsed : [parsed]
    records.filter_map do |r|
      next unless r.is_a?(Hash) && r['i'] && r['n']
      { index: r['i'].to_i,
        name: r['n'].to_s,
        connected: r['c'] == true,
        admin: r['a'] == true,
        online_time: r['o'].to_i,
        afk_time: r['k'].to_i,
        locale: r['l']&.to_s,
        quickbar: r.key?('q') ? (r['q'] == false ? :failed : PlayerDatabase.parse_quickbar(r['q'])) : nil }
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

  # [{index:, name:, connected:, admin:, online_time:, afk_time:, locale:}] for
  # the CONNECTED players, or nil if the query failed. Same write_file-first
  # path as the roster (attrs exceed 4KB beyond ~50 players). Connected-only:
  # every consumer filters on :connected or targets connected players, and a
  # game.players dump keeps growing with every player who ever joined.
  def player_attributes
    self.class.parse_player_attrs(json_query(PLAYER_ATTRS_FILENAME, PLAYER_ATTRS_WRITE_LUA, PLAYER_ATTRS_PRINT_LUA))
  end

  # Fetch one connected player's attributes for a join-time enrichment query.
  # This is deliberately targeted: the full dump belongs at startup only.
  # `player` is the game player INDEX (what the join path has) or a name.
  # One-line /sc command; returns a parsed LuaPlayer-attr hash (plus the
  # quickbar, see .player_attrs_for_lua) or nil.
  def player_attributes_for(player)
    records = self.class.parse_player_attrs(execute(player_attrs_for_lua(player)))
    return nil unless records
    # One record comes back (the player we asked for). Match by name only
    # when we queried BY name — an index lookup has no name to match.
    player.is_a?(Numeric) ? records.first : records.find { |p| p[:name] == player.to_s }
  end

  # The join-time one-liner: the usual attrs (index, name, connected, admin,
  # online_time, afk_time, locale) PLUS the player's whole quickbar, keyed by
  # the FLAT slot index 1..100 (`{"<flat index>": <item id>}`). The quickbar
  # rides along here rather than in a query of its own because the C→S
  # actions only ever report it as deltas — a join is the one moment the
  # whole bar is knowable.
  #
  # The read loop follows the server version (the same helpers.game_version
  # string select_version uses for the action tables) because the getter
  # changed in 2.1: 2.0 takes a flat index 1..100, 2.1 takes (page, slot).
  # Both branches normalise to the same flat key, so the page/slot fold lives
  # in one place (PlayerDatabase.parse_quickbar). The 2.1 branch assumes
  # 0-based page/slot, like the wire's quick_bar_set_selected_page byte.
  # An unknown version falls back to the 2.0 shape; the pcall below turns a
  # wrong guess, or a changed return type, into a visible "quickbar read
  # failed" — never a dead query, attrs included.
  #
  # Item PROTOTYPE IDS, not names, so the cache needs no item_db: the id map
  # is built right here in the same `prototypes.item` iteration order
  # DUMP_PROTOTYPES_LUA uses (that order IS the wire id).
  #
  # Everything else about this query is live-verified on 2.0.77 — the getter
  # arity, `.name`, the 1..100 bounds, the id map, game.players[...],
  # get_active_quick_bar_page being uncallable — and recorded in
  # docs/rcon-knowledge.md, which is the place to read before editing this.
  def player_attrs_for_lua(player)
    key = player.is_a?(Numeric) ? player.to_i.to_s : "\"#{lua_quote(player)}\""
    slots = PlayerDatabase::QUICKBAR_SLOTS
    version = server_version.to_s
    # 2.1+ takes (page, slot); 2.0 and an unknown version take the flat index
    loop_lua = if !version.empty? && !version.match?(/\A2\.0(\.|\z)/)
                "for pg=0,#{PlayerDatabase::QUICKBAR_PAGES - 1} do for sl=0,#{slots - 1} do " \
                  "put(pg*#{slots}+sl+1,p.get_quick_bar_slot(pg,sl)) end end"
              else
                "for i=1,#{PlayerDatabase::QUICKBAR_PAGES * slots} do put(i,p.get_quick_bar_slot(i)) end"
              end
    'do local p=game.players[' + key + '] local q={} ' \
      'local function read() local n={} for x in pairs(prototypes.item) do n[#n+1]=x end ' \
      'local ids={} for i=1,#n do ids[n[i]]=i end ' \
      'local function put(i,s) if s and s.name and ids[s.name] then q[tostring(i)]=ids[s.name] end end ' \
      "#{loop_lua} end " \
      'local okq=p and pcall(read) ' \
      'rcon.print(p and helpers.table_to_json({i=p.index,n=p.name,c=p.connected,a=p.admin,' \
      'o=p.online_time,k=p.afk_time,l=p.locale,q=okq and q or false}) or "nil") end'
  end

  # Set a player's quickbar cells: `cells` is {flat slot index => item id}
  # (the same shape #player_attrs_for_lua reads back). Ids become names in
  # Lua, from the same `prototypes.item` iteration order the wire uses.
  #
  # THE SETTER MATCHES THE GETTER, and it changed with it: 2.0 takes
  # (index, item), 2.1 takes (page, slot, filter). Each call is pcall'd and
  # the count of successes comes back, so a rejected write (a wrong 2.1
  # filter shape, say) is a number we report rather than a silent no-op.
  # One line, server-side, no response cap to worry about (a short count).
  def restore_quickbar(player, cells)
    return 0 if cells.nil? || cells.empty?
    version = server_version.to_s
    cells = cells.map { |i, id| "[#{i.to_i}]=#{id.to_i}" }.join(',')
    set = if !version.empty? && !version.match?(/\A2\.0(\.|\z)/)
            "local k=(i-1)//#{PlayerDatabase::QUICKBAR_SLOTS} local l=(i-1)%#{PlayerDatabase::QUICKBAR_SLOTS} " \
            'if pcall(p.set_quick_bar_slot,k,l,r[v]) then ok=ok+1 end'
          else
            'if pcall(p.set_quick_bar_slot,i,r[v]) then ok=ok+1 end'
          end
    lua = 'do local p=game.players["' + lua_quote(player) + '"] local ok=0 ' \
      'local r={} for x in pairs(prototypes.item) do r[#r+1]=x end ' \
      "if p then local s={#{cells}} for i,v in pairs(s) do #{set} end end " \
      'rcon.print(ok) end'
    execute(lua).to_s.strip.to_i
  end

  # Write item + entity prototype name dumps to the server's script-output
  # dir (files factorio-packettools-items.txt / factorio-packettools-entities.txt)
  # via helpers.write_file. Returns true when the command ran; the caller
  # must read the files back (see ServerDetect.script_output_dir).
  def dump_prototype_files
    execute(DUMP_PROTOTYPES_LUA)
    true
  end

  # Send a chat message visible to all players (game.print via /sc). The
  # message is Lua-string-quoted, so arbitrary content (quotes, backslashes,
  # newlines) can't break out of the string or inject Lua. Used by the
  # Hivemind agent to reply to in-game chat.
  def say(text)
    return if text.nil? || text.empty?
    execute("game.print(\"#{lua_quote(text)}\")")
  end

  # Set a player's overhead/chat tag (game.players[name].tag) — the ONLY
  # world-mutating RCON write the Hivemind agent may perform (dedicated
  # tool; everything else is read-only rcon_query). Name and tag are
  # Lua-string-quoted like #say so neither can inject Lua. Tags only
  # describe (shown next to the name in chat/overhead) — they never alter
  # mechanics. An empty tag clears it. Returns true when the player exists
  # (online or not — game.players covers everyone who ever joined) and the
  # tag was set, false when the player is unknown or the write failed.
  MAX_TAG_LEN = 64
  def set_player_tag(name, tag)
    player = name.to_s.strip
    return false if player.empty?
    text = tag.to_s.strip[0, MAX_TAG_LEN]
    body = execute(%(do local p = game.players["#{lua_quote(player)}"] rcon.print(p ~= nil) if p then p.tag = "#{lua_quote(text)}" end end)).to_s.strip
    body == 'true'
  rescue StandardError
    false
  end

  # Server version string (e.g. "2.0.77") via the rcon.print data channel
  # (helpers.game_version — game.version doesn't exist), or nil on failure.
  # Used to pick the protocol's segment-type mapping
  # (FactorioProtocol.select_version).
  # Memoised: a version never changes under a running server, and the
  # sniffer asks at startup anyway (select_protocol_version). Failures are
  # NOT memoised, so a server that was down at boot is retried.
  def server_version
    body = execute('rcon.print(helpers.game_version)').strip
    return nil if body.empty?
    @server_version = body
  end

  # Run an arbitrary RCON console command (raw, NO /sc Lua prefix) and
  # return its body. Used by the Hivemind agent's rcon_query tool — the
  # model passes full commands like "/players" or "/sc rcon.print(...)".
  # Reconnects once on failure, same as #execute.
  def command(cmd)
    run_command(cmd)
  end

  # Lua double-quoted string escaping shared by #say, #set_player_tag, and TranslationAgent:
  # every backslash and quote gets a literal backslash prefix so content
  # can't break out of the string or inject Lua; newlines collapse to
  # spaces (single-line contexts). Char loop on purpose: gsub with a
  # STRING replacement interprets backslashes (backreferences), which
  # silently un-doubles them — the exact hole this closes.
  def lua_quote(str)
    out = +''
    str.to_s.each_char do |ch|
      out << "\\" if ch == '"' || ch == "\\"
      out << ((ch == "\n" || ch == "\r") ? ' ' : ch)
    end
    out
  end

  private

  def connect
    c = Rcon::Client.new(host: @host, port: @port, password: @password)
    c.authenticate!(ignore_first_packet: false)  # Factorio sends ONE auth reply
    c
  end

  def execute(cmd)
    run_command("/sc #{cmd}")
  end

  def run_command(cmd)
    log_rcon_command(cmd)
    @mutex.synchronize { @client.execute(cmd).body.to_s }
  rescue
    # Connection lost (server restart, network blip) — reconnect once.
    begin
      @client = connect
      @mutex.synchronize { @client.execute(cmd).body.to_s }
    rescue => e
      warn "RCON execute failed: #{e.class}: #{e.message}"
      ''
    end
  end

  # Every outgoing RCON command (relay Lua, locale queries, hivemind replies,
  # tag writes, …) is echoed to the operator console so there is never a
  # question what ran. Response bodies still go to the caller as before.
  def log_rcon_command(cmd)
    ts = Time.now.strftime('%H:%M:%S')
    puts "#{ts}  [rcon]> #{cmd}"
  end
end
