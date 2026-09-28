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
  written for that player_index. **`0` writes ONLY to the server's
  output, if the server is present** (verified live on 2.0.77:
  `write_file(f, d, false, 0)` lands in `<user-data>/script-output/`,
  identical to nil). "if present" is a condition on the write happening
  at all — the doc does NOT say it falls back to writing for all players
  when the server output is absent (that is speculation; the likely
  behavior there is a silent skip, like non-zero via `/sc`). non-zero
  writes for THAT PLAYER (transferred to their client, never readable
  server-side) and in the runtime stage (`/sc`) is **always skipped**.

  **Why we always pass `false, 0`**: mod/scenario Lua runs determin-
  istically on the server AND every client (lockstep prediction), so a
  bare `write_file(f, d)` would execute on all of them — `for_player=0`
  pins the write to the server's output explicitly. (RCON `/sc` itself
  executes server-only, so `nil` was already equivalent; `0` makes the
  intent unambiguous.) The sniffer guard (server_mode_test) checks every
  write_file call's last arg is `0` — never a player index.

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

Built-in `/players` lists only names, so the sniffer uses one RCON
`player_attributes` query instead. It returns JSON rows containing the
1-indexed game id, name, connection/admin flags, online/afk ticks, and
locale; `FactorioPacketTools` seeds `PlayerAttrs` and `PlayerDatabase` from that
single response. Later joins are learned from C→S packets, with one
targeted RCON lookup for a newly joined player's attributes
(`player_attributes_for`, by game index) — which also carries their **whole
quickbar** (`p.get_quick_bar_slot(i)` for the flat 1..100 slot space, pcall'd
once, keyed `{"<flat index>": <item id>}`; the Lua builds the name→id map from
`prototypes.item` so the ids are wire ids). One command per join covers both:
a full 100-cell bar is ~1.2KB, so `rcon.print` still fits under the cap.

### `LuaPlayer.get_quick_bar_slot` — the quickbar read

**The signature changed in 2.1, and the server version picks the call:**

| version | signature | index space |
|---------|-----------|-------------|
| 2.0 | `get_quick_bar_slot(index)` — one flat index | 1..100: "1 for the first slot of page one, 2 for slot two of page one, 11 for the first slot of page 2" |
| 2.1 | `get_quick_bar_slot(page_index, slot_index)` — two uint8s | 0-based page/slot (assumed, like the wire's `quick_bar_set_selected_page` byte — untested, no 2.1 server here) |

`RconClient#player_attrs_for_lua` builds the loop from
`RconClient#server_version` (memoised `helpers.game_version` — the same
version string `FactorioProtocol.select_version` uses for the action tables),
via `quickbar_page_args?`: 2.0.x → flat loop, anything else → the two-argument
loop, unknown → the verifiable 2.0 shape. Both normalise to the same flat key
in the payload, so the page/slot fold is one Ruby path
(`PlayerDatabase.parse_quickbar`). Passing the wrong arity RAISES
(`Expected 1 argument but 3 were given`), which is why the read is wrapped in
one `pcall`: a wrong guess or a changed return type costs the quickbar
(logged as a failed read) rather than the whole query, attrs included.

**Verified live on 2.0.77 (2026-09-27, RCON, single-player test game):**

- The 1-arg form is what that build has. `0`, `101` and negatives raise;
  every index 1..100 reads fine, so the flat loop needs no bounds guard.
  A float index is accepted (1.5 behaves as 1).
- Writes line up 1:1 — setting 1/7/23/100 read back at the same indices, so
  the space is contiguous, not per-row. `set_quick_bar_slot(i, nil)` clears.
- The returned filter has `.name`. 2.1 returns a `QuickBarSlot`/`ItemFilter`,
  so `.name` is a forward assumption (the pcall is what covers it).
- `get_active_quick_bar_page` is **not callable** on 2.0.77 (its argument
  counter demands one argument; passing self complains `real number expected
  got userdata`), so the active page stays packet-derived.

### `LuaPlayer.set_quick_bar_slot` — writing a bar back

Mirrors the getter, and changed with it: 2.0 takes `(index, item)`, 2.1 takes
`(page, slot, filter)`. `RconClient#restore_quickbar(name, {flat index => id})`
builds the right call from the memoised `server_version` (same branch as the
read), resolves the ids to names through the `prototypes.item` order, wraps
each call in a `pcall` and returns the COUNT of successes — so a rejected
write (a 2.1 filter shape we guessed wrong) is a number the caller reports,
not a silent no-op.

Used by the `quickbar_backup` plugin (`lib/quickbar_backup.rb`) to put a
player's saved quickbar back after a save change.

### Player lookup: by index OR name, and not `connected_players`

**Verified live on 2.0.77:**

- `game.players[1]` and `game.players["name"]` **both** work — use
  `game.players[...]` for both, and prefer the index: the join path has it,
  so no name ever has to be quoted into Lua.
- `game.connected_players["name"]` is **nil** even for a connected player —
  that table only iterates with `pairs`/`ipairs`. A lookup that uses it
  silently finds nobody.
- `game.get_player("name")` works, `game.get_player(lua_player)` does not.
- `game.get_players` does not exist.
- The join-time attrs payload is a single JSON **object**; the all-players
  dump is a JSON **array** of them. `parse_player_attrs` takes both.

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
