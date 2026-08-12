# level.dat — Internal Format

The decompressed `level.dat` (the game state) is Factorio's binary
serialization. This documents what we've reverse-engineered, verified against
live captures (Factorio 2.1.14 build 87436, 2026-08-11).

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

Verified against our save (the 0.17+ layout):

```
version64         4 × u16 LE            (2, 1, 14, 1)
random byte       1 byte                (0.17+; purpose unknown)
campaign          optim-str             ("")
name              optim-str             ("freeplay")
base_mod          optim-str             ("base")
difficulty        u8                    (0=Normal, 1=Old School, 2=Hardcore, …)
finished          bool
player_won        bool
next_level        optim-str             ("")
can_continue      bool
finished_but_continuing  bool
saving_replay     bool
allow_non_admin_debug_options  bool      (0.16+)
loaded_from       3 × optim-u16         (2, 1, 14)
loaded_from_build u32                   (87436; u16 in pre-2.x)
allowed_commands  u8                    (2/3)
unknown           4 bytes               (00 00 a0 00 in 2.1.14)
mods              [count: optim][name: optim-str][ver: 3×optim-u16][crc: u32]*
```

After the header: localized strings (victory messages), autoplace /
map-gen settings, then the game state.

## Section Map (mp-save-124, ~138 MB decompressed)

| Logical offset | Content |
|----------------|---------|
| 0 | Header + prototypes (items, tiles, collision layers) |
| ~28 MB | **Alert list** — LocalisedStrings with player names, no index |
| ~31 MB | Large float array (forces?), embedded strings |
| 40–116 MB | Blueprint libraries (author names — NOT players) |
| 122.7 MB | **Console buffer** (chat/events) — see below |
| 122.75–124.2 MB | **Offline player cache** records — see below |
| 124–136 MB | Blueprint library (balancers etc.) |

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
[force refs (ff-runs)][v1: u64][v2: u64][8 floats][len][name][flags…][position doubles][locale]
```

- 17 records found in mp-save-124 (looser signatures caught 3 more than the
  strict pattern: Phoenix_str, __Tortu__, alex8841).
- `v1` ≈ play time (~5K–62K ticks = 1.4–17 min, or seconds = 1.4–17 h),
  `v2` ≈ last-online tick (2.5M–22.8M, world ~110 h old).
- Contains only players **offline at save time** (online players absent —
  consistent with the save being a connect-time snapshot).
- The 8 floats repeat across players (preset color palette).

## Known Gaps / Open Questions

- **The actual `game.players` roster records do not contain plain-text
  names** in this version — the online players' names appear only in the
  console buffer + alerts. Their roster entries are serialized without the
  name bytes (or in an unidentified section).
- Forces section boundaries not fully mapped (a large float array at
  ~31 MB contains an embedded "neutral" force record).
- The relationship between action indexes (0–43+) and the roster size
  (17 offline + 4 online?) is unresolved — verifying by loading the save in
  single player (`/c for i,p in pairs(game.players) do print(i,p.name) end`)
  would settle it.

## References

- [gist: factorio save parser (0.13–0.16)](https://gist.github.com/mickael9/5dbdb926d3a800bc0b9badf0cc1d5a9f)
- [factorio-server-manager save.go (0.16/0.17+)](https://github.com/OpenFactorioServerManager/factorio-server-manager/blob/develop/src/factorio/save.go)
