# RCON Knowledge Base

Everything learned about querying the running Factorio server through RCON
(`/sc` Lua console). Read this before writing new RCON queries — most of it
was learned the hard way (timeouts, truncation, silent failures).

## Getting data OUT of the server

The RCON console has exactly ONE clean channel for returning data: the
`rcon` object in the console environment sends its argument back through the
RCON connection as the command response.

```lua
rcon.print("hello")                    -- response body == "hello\n"
rcon.print(helpers.table_to_json(t))   -- tables → JSON (preferred)
rcon.print(serpent.line(t))            -- fallback: Lua syntax, keys SORTED alphabetically
```

- **Prefer `helpers.table_to_json`**: JSON parses with stdlib `JSON.parse`
  (`RconClient.parse_json`). `serpent.line` emits Lua table syntax and
  sorts keys alphabetically (NOT insertion order) — an order-sensitive
  regex silently matched nothing and starved the agent's player stats.
- Without either, tables print as `table: 0x...`.
- Every command is executed with `/sc ` prefix (silent: nothing is shown to
  players) in `RconClient#execute`.
- **One-liner rule**: `/sc` only applies to the FIRST line of the command.
  Multi-line Lua sent over RCON silently fails on the lines after the first
  (they're parsed as separate, unknown console commands). Keep Lua one-liners
  (semicolons, inline `local function ... end`).
- Commands are also length-limited (~4096 chars) — keep them short.

## Response size cap (~4KB)

`rcon.print` responses are capped around 4KB and the tail is silently
truncated. A 100-name chunk of `{i = N, n = "name"}` records is ~4.4KB —
records at the end get dropped with no error. If you must print a list:

- keep chunks well under the cap (50 names ≈ 2KB is safe), or
- **prefer `helpers.write_file` for anything large** (see below).

## helpers.write_file — large dumps to disk

Official signature (Factorio Lua API):

```lua
helpers.write_file(filename, data, append?, for_player?)
```

- `filename :: string` — name/path relative to `script-output/`; a
  directory path (e.g. `"save/here/example.txt"`) creates the folder
  structure.
- `data :: LocalisedString` — the content to write.
- `append :: boolean?` — true appends; default false OVERWRITES any
  pre-existing file.
- `for_player :: uint32?` — **the trap**: if given, the file is only
  written for that player_index. **`0` writes to the server's output if
  present** (verified live on 2.0.77: `write_file(f, d, false, 0)` lands
  in `<user-data>/script-output/`); non-zero writes for THAT PLAYER
  (transferred to their client, never readable server-side). In the main
  chunk of the runtime stage (i.e. `/sc` console commands) a non-zero
  `for_player` is **always skipped** — the write silently does nothing.
  So via RCON: pass nothing (nil), or `0` — never a player index.

Writes land in `<user-data>/script-output/`. No size limit (unlike the
~4KB rcon.print cap). The user-data dir is the factorio process's
**working directory** (not the binary dir!) — find it via:

```bash
readlink /proc/<pid>/cwd        # → /home/factorio/factorio
ls /home/factorio/factorio/script-output/
```

**Server-side only by construction**: all sniffer calls pass only
`(filename, data)` — no `for_player`, so the write always goes to the
server's script-output. A `p.index` inside the data is just the player
index being serialized INTO the JSON, not the `for_player` arg. This is
how the roster / player-attrs queries (and the item/entity prototype
dumps) avoid the ~4KB rcon.print cap on 100+ player servers
(`RconClient#json_query` reads the file straight from script-output —
the sniffer runs on the server host).

In code: `ServerDetect.script_output_dir(pid)`.

Pattern: one `/sc` one-liner writes the whole dump to a file, then read the
file from `script-output/`. Used by `lib/rcon_client.rb#dump_prototype_files`
and `tools/item_db.rb` (items + entities, no chunking needed).

## helpers.game_version — server version (single value)

```lua
rcon.print(helpers.game_version)   -- → "2.0.77"
```

`helpers.game_version` exists on 2.0.x and 2.1.x (`game.version` does NOT
— `LuaGameScript` has no `version` key). Used by
`lib/rcon_client.rb#server_version` to pick the protocol's segment-type
mapping (`FactorioProtocol.select_version`; chat segment type is 104 on
2.0, 106 on 2.1 — see docs/protocol-notes.md).

## prototypes.* — wire prototype IDs

The wire protocol references items/entities by 1-indexed ID. Those IDs are
the **iteration order** of the console `prototypes` tables:

```lua
for name in pairs(prototypes.item) do ... end     -- item IDs (pipette src=0, cursor_transfer, ...)
for name in pairs(prototypes.entity) do ... end   -- entity IDs (pipette src=4)
```

- `prototypes.item` #1 = wooden-chest, #87 = nuclear-reactor, #149 = carbon.
- `prototypes.entity` #1 = wooden-chest, #87 = stone-furnace, #149 = iron-ore.
  The two lists start identically (~first 80 buildable items) then diverge —
  don't assume item order = entity order.
- **`game.item_prototypes` does NOT exist** — runtime `game` has no
  `item_prototypes` key ("LuaGameScript doesn't contain key..."). Use
  `prototypes.item`.
- `prototypes` is a console global (userdata table); `prototypes.entity` /
  `prototypes.item` are userdata too. All confirmed live.

## /players

Built-in command lists only player NAMES — no game index. Use
`game.connected_players` + `p.index`/`p.name` for the roster:

```lua
local t={} for _,p in pairs(game.connected_players) do t[#t+1]={i=p.index,n=p.name} end rcon.print(helpers.table_to_json(t))
```

Parsed by `RconClient.parse_roster` (JSON array of `{"i":N,"n":"name"}`).

## Connection details

- Factorio sends ONE packet in response to RCON auth (not two like SRCDS), so
  `authenticate!(ignore_first_packet: false)` or it times out.
- On connection loss `RconClient#execute` reconnects once, transparently.

## Gotchas checklist

- [ ] One-liner (multi-line `/sc` silently fails past line 1)
- [ ] `helpers.table_to_json` for any non-scalar value (serpent sorts keys!)
- [ ] Response ≤ ~4KB or use `helpers.write_file`
- [ ] `prototypes.<kind>`, never `game.<kind>_prototypes`
- [ ] Iteration order IS the wire ID order (both lists, 1-indexed)
