# level.dat — Internal Format

The decompressed `level.dat` (the game state) is Factorio's binary
serialization. This documents what we've reverse-engineered, verified against
live captures (Factorio 2.0.77 build 19003, 2026-09).

## Chunks

- `level.dat` is split into `level.dat0` … `level.datN` zip entries (stored,
  method 0).
- Each chunk is **independently zlib-compressed** (starts `78 01`) and
  decompresses to ~1 MiB.
- **Join chunks in NAME order** — the zip entry order is the random transfer
  order and must not be used.

## Serialization Conventions

Adapted from the community parsers (see References). Values use an **optim**
encoding:

- `read_optim(dtype)`: read 1 byte; if `< 0xFF` it is the value, else read
  the full `dtype` (u16/u32 LE).
- Strings: `optim-u32 length` + UTF-8 bytes (so short strings are just
  `[len][bytes]`).

## Header

Verified against our save (the 0.17+ layout), values from `_autosave14`:

```
version64         4 × u16 LE            (2, 0, 77, 0)  ← the save's game version
random byte       1 byte                (0.17+; purpose unknown)
campaign          optim-str             ("")
name              optim-str             ("Legendary Deathworld")
base_mod          optim-str             ("scenarios")
difficulty        u8                    (0=Normal, 1=Old School, 2=Hardcore, …)
finished          bool
player_won        bool
next_level        optim-str             ("")
can_continue      bool
finished_but_continuing  bool
saving_replay     bool
allow_non_admin_debug_options  bool      (0.16+)
loaded_from       3 × optim-u16         (2, 0, 77)
loaded_from_build u32                   (84539; u16 in pre-2.x)
allowed_commands  u8                    (2/3)
mod list          [count][len name][u16 version][u32 crc]*  — the same framing
                  as the client's mod list in msg 4 (see protocol-notes.md)
unknown           4 bytes               (00 00 a0 00 in our 2.0.77 save)
mods              [count: optim][name: optim-str][ver: 3×optim-u16][crc: u32]*
```

After the header: localized strings (victory messages), autoplace /
map-gen settings, then the game state.

## The stored game tick

`game.tick` at save time is stored as an IEEE 754 double (LE, 8 bytes) in
the decompressed `level.dat0`, past the header + prototype section.  The
tick is found by searching for an 8-byte signature that **always follows**
the tick f64 in saves from the same scenario:

```
tick f64 LE (8 bytes)     01 00 43 3a 03 00 00 00     ← TICK_SIGNATURE
```

Read the 8 bytes **before** `01 00 43 3a 03 00 00 00` as an f64 LE double
→ that is the game tick.  The signature appears exactly once per save from
a given scenario (verified on freeplay @ seed 42, base mod only, Factorio
2.0.77).

The stored value is typically **0–4 ticks ahead** of the `game.tick` an
RCON query returns at the same wall-clock moment: the save runs a few ticks
after the query that triggers it.  Confirmed via `game.server_save()` in a
single Lua command that captures both the tick and the save (lag = 0 on
fast saves, 4 after a `game.speed = 1000` burst):

| Save | RCON tick | Stored f64 | Lag |
|------|-----------|------------|-----|
| probe-d | 72040 | 72040.0 | 0 |
| probe-e | 72341 | 72341.0 | 0 |
| probe-h | 180105 | 180109.0 | 4 |
| probe-i | 223830 | 223834.0 | 4 |

`FactorioSave.tick_at(data)` implements the lookup; `FactorioSave::Roster`
uses it to set `save_tick` (falling back to the old max-last-online
approximation when the signature is not found — saves from a different
scenario, or streams too small to contain it).

## Section Map (mp-save-124, ~138 MB decompressed; offsets from the older
## 186 MB `_autosave14` are marked where they differ)

| Logical offset | Content |
|----------------|---------|
| 0 | Header + prototypes (items, tiles, collision layers) |
| ~28 MB | **Alert list** — LocalisedStrings with player names, no index |
| ~31 MB | Large float array (forces?), embedded strings |
| 40–116 MB | Blueprint libraries (author names — NOT players) |
| 40.67–52.91 MB | **Player roster** — 338 LuaPlayer records, index order (see below) |
| 122.7 MB | **Console buffer** (chat/events) — see below |
| 124–136 MB | Blueprint library (balancers etc.) |

## The Player Roster (verified — the whole roster, not just chatters)

The save carries the complete `game.players` list as an array of LuaPlayer
records **in game-index order**. In `_autosave14` (2.0.77, 186 MB
decompressed) it is the run at **40.67 MB … 52.91 MB** and holds all
**338** players — every player who ever joined the save, online or not, no
rolling-window limit like the console buffer.

Each record stores the name as a bare optim-string (no type tag):

```
… [u64 play ticks][u64 last-online tick][… floats … 1.0f]
  [len][name] [2.0 tags: [len][tag]…] …
```

- The field before the name is always the tail of a **1.0f**, i.e. the three
  bytes `00 80 3f` — a 24-bit signature over the whole stream. Outside the
  roster it only ever matches item/planet/recipe prototype names (`coal`,
  `Gleba`, `copper-ore`), never a player: Factorio rejects spaces and other
  punctuation in names, so `[A-Za-z0-9_.-]{3,32}` is a real filter (it drops
  the only two false positives in this save, chat/GUI strings with spaces).
- **The index is the record's position in the run**, so the run's absolute
  position is unknown — anchor it with players-cache.json: for every known
  name, `index - position` is a constant (269 for the first record here).
  That doubles as the self-check: a known name that disagrees means the save
  is from another world.
- The run is **not contiguous in the file**: the console buffer sits between
  records 337 and 338 here.
- **Index 0 has no record** in this save (the run starts at index 1), so
  `game.players[1]` is the first one.
- **`LuaPlayer.color` is in the record**: four f32 floats at `name − 33`
  (`r, g, b, a`, alpha 0.5). Recovered for **all 338** records, **337 exactly
  right** against the live `game.players` dump; the channels are ordinary
  floats from a fixed palette (~40 distinct colours on our server), not byte
  fractions, so there is no local tell for the one record whose layout differs
  — it lands on another player's grey. Alpha is 0.5 for all 338 (nobody has
  touched it); 39 distinct colours, 22 of them shared by 14-44 players and 17
  used by exactly one, which is what a swatch picker plus a few custom picks
  looks like. Colour is cosmetic, and the RCON value wins wherever both exist.
  **The colour is SAVE state, so it needs no backup/restore** — a new save
  carries every player's colour forward, exactly as it does the name. The
  quickbar is the opposite: it is NOT in the save, which is the entire reason
  `player_backup` restores it.
- The roster is found **without any cache**: a player record is a name that
  has the play-time/last-online pair below in front of it, and exactly the
  338 records have one (the ~280 prototype names and chat strings carrying
  the same name signature have none). Indexes start at 1 (verified on
  2.0.77) unless players-cache.json anchors the run, and a wrong start
  self-corrects on the first join seen on the wire. This is what makes
  client mode work: the map download is the server's save, so seeding
  players-cache.json from it gives the names of everyone already in the
  game (`docs/save-file-format.md`).
- The **locale** is in the record too — a bare optim-string `[len][bytes]`
  (`\x01\x00` in front, `00 00 00 00 ff ff ff` behind; the same string
  container the name and the tags use). Recovered for **290 of the 338**
  players with **zero wrong values** (checked against the live
  `game.players` dump); it can sit tens of KB behind the name, and the other
  48 records store it differently or not at all. `en` is a real string, not
  an implicit default.
- The two u64 slots in front of the name hold the player's play time and
  last-online tick. Both are u64-sized but carry a u32 value, so the layout
  is `[u32 ticks][00 00 00 00][u32 tick][00 00 00 00]` with play < last, and
  the values are **ticks (60/s)**, not seconds. Verified 338/338 against a
  live `game.players` dump: only the two players who had kept playing
  between the save and the dump differed.
  Their distance from the name is NOT fixed (-61 for 189 records, -67 for
  147 — two record layouts), and a play time under 2^24 ticks also forms a
  byte-shifted decoy pair out of the value's own zero padding, so read the
  offset most records agree on (see `stat_slots` in the tool).
- After the name come the 2.0 **player tags** (`07 Foundry 07 djimbro 07 Q`
  for morganc) — what `SetPlayerTag` writes — then the rest of the record
  (variable size: 8 KB … 2.4 MB, mostly the player's own mod storage).

`tools/extract_players_from_save.rb` implements exactly this and merges the
recovered names into players-cache.json (223 of the 338 were unknown from
packets alone here). For a LIVE server you don't need the save at all —
RCON `game.players` is authoritative — but an autosave recovers the whole
roster including everyone who left.

## Console Buffer → Player Index (verified)

Chat/event log near the end of the file. Each message:

```
02 [len]["name [planet=...]: message"] 00 [INDEX] 00 [4 color floats] [8-byte tick]
```

- `INDEX` = sender's **0-indexed game player index**.
- Verified: morganc's messages carry 27 == their C→S heartbeat index
  (game player #28, 1-indexed); Darkcry=0, ElNapo=5, star3Watcher=21,
  wampastompa09=43 all match their server-echoed action indexes.
- The buffer is a rolling window — only recent chatters appear (5 here),
  NOT the full roster.

## Offline Player Cache Records

Player-name records between the console messages, each:

```
[force refs (ff-runs)][v1: u64][v2: u64][8 floats][len][name][flags…]
```

The last two parts of that old line are WRONG — measured against a live
`game.players` dump (index, name, position, force, surface, admin,
online_time, whole quickbar for all 338 players):

- **position IS in the save — as two i32s at 1/256 tile units, at a
  VARIABLE offset inside the record.** Verified against a second, newer save
  (`_autosave20`, tick 125.5M, 343 players) and the frozen players between
  the two console dumps: 11 of 13 have the exact pair `(x*256, y*256)` as i32s
  inside their own record (offsets 2408 … 67452 — the record's variable tail,
  not a fixed field), and 2 do not. **Not extractable with confidence**:
  each record holds 2-3 look-alike pairs and nothing marks the right one, so
  a decoder would be guessing. Positions are also quantised (positions read
  from the console are exact multiples of 1/256, and `p.position` is 0,0 for a
  player whose surface is unloaded — 326 of 338 in one dump, so most players
  have nothing to compare). Packet-side position work is unaffected.

- `admin` is not in the save at all (it is `adminlist.json`, per server).

- 17 records found in mp-save-124 (looser signatures caught 3 more than the
  strict pattern: Phoenix_str, __Tortu__, alex8841).
- `v1` ≈ play time (~5K–62K ticks = 1.4–17 min, or seconds = 1.4–17 h),
  `v2` ≈ last-online tick (2.5M–22.8M, world ~110 h old).
- Contains only players **offline at save time** (online players absent —
  consistent with the save being a connect-time snapshot).
- The 8 floats repeat across players (preset color palette).
- These are the roster records described above — they are a SUBSET of the
  full roster, not a separate cache. The 17 records are just the ones that
  signature-matched in the OLD save; the roster itself holds everyone, so
  read the roster section, not this one, to get the player list.
- `v1`/`v2` are the play-time / last-online slots now identified above, and
  the trailing "locale" is the string we now read — the offline/online split
  here was an artifact of the old loose signature, not of the save.

## The differential-save method (what settles the rest)

Guessing encodings is exhausted; the way to find a field is to **change it and
diff two saves taken seconds apart**. The world barely moves between them, so
the differing byte ranges ARE the field — no naming, no encoding guesses:

```
/sc do game.server_save("probe-a") end
/sc do game.players[62].set_quick_bar_slot(1, "tesla-ammo") game.server_save("probe-b") end
```

Copy both zips here and the diff names the quickbar's bytes outright. The
same trick settles position (move a player between the two saves), force,
surface, and anything else settable from the console.

## Known Gaps / Open Questions

- The per-player record layout is only mapped as far as the name + tags +
  locale + the play-time pair (above): what the fields between them mean (the
  `00 00 <u16>` pair, the float pairs, the trailing tables) is unknown, and
  the roster array's own framing (its count / start marker) was never located
  — the run is found by the name signature instead.
- The other things `player_attributes_for` reads over RCON are NOT
  recoverable cheaply, and were measured, not guessed:
- `admin` is **not** in the save — it is server state (`adminlist.json`),
  which is why no byte, bit, bitset or index list for it exists in the file.
  `afk_time` is online-only and does not persist.
- The locale is **not on the wire**: no capture contains any multi-char
  locale code (zh-CN/pt-BR/es-ES/zh-TW/sv-SE — checked over all 380 MB), so
  a client never learns another player's language, and packet decode cannot
  recover it. The server knows it from its own account state at join; the
  save is the only copy that travels (see the roster section above), which
  is how a client-mode session gets the locale of players already in the
  game. The QUICKBAR is almost certainly in the record
  (per-player state of 8 KB … 2.4 MB), but it is unlocated: a quickbar is
  only findable by searching for known item ids, and we have none — no
  capture has quick_bar_set_slot actions and no backup file exists. Get
  ONE known bar (the `player_backup` plugin's file, or a capture with
  quickbar actions) and the search becomes concrete.
- Forces section boundaries not fully mapped (a large float array at
  ~31 MB contains an embedded "neutral" force record).

## References

- [gist: factorio save parser (0.13–0.16)](https://gist.github.com/mickael9/5dbdb926d3a800bc0b9badf0cc1d5a9f)
- [factorio-server-manager save.go (0.16/0.17+)](https://github.com/OpenFactorioServerManager/factorio-server-manager/blob/develop/src/factorio/save.go)
