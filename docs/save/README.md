# Save / Map Download Format

How the server's map save is transmitted and structured. Verified against
live captures (2026-08-11, Factorio 2.1.14 build 87436).

## Transfer

- The map download = **TransferBlock** (msg 13) packets: `header(1) |
  block_number(4, LE) | data(503 bytes)`.
- Blocks arrive in order 0..N; concatenating reproduces the save archive.
- A second server connection reuses block numbers — split downloads by
  ConnectionRequest (msg 2) timestamps.
- Live capture can drop blocks at ~20k pps (kernel buffer overflow); use
  `tcpdump` for lossless capture (see `../save-file-format.md` for the full
  loss analysis and fixes).

## The Save Archive (mp-save-100.zip / mp-save-122/123/124.zip)

- A ZIP with data-descriptor flags (`flags & 0x08` → local header sizes are
  0; use the central directory).
- Entries: `control.lua`, `description.json`, `level-init.dat`,
  `locale/*/freeplay.cfg`, `level.dat0..N`, `level.datmetadata`,
  `script.dat`, `info.json`. **No player-data.json** — player data is inside
  `level.dat`.
- The final transfer block (after the zip's EOCD) is a small **server-info
  block**: game name, motd, server address, and alphabetical name lists
  (NOT index-ordered — verified via console-buffer indexes).

## Player Data Sources (in priority order)

| Source | Gives | Notes |
|--------|-------|-------|
| **Console buffer** in level.dat | name ↔ game index | verified; only for chatters |
| ConnectionAcceptOrDeny | online names + **peer ids** | peer id ≠ game index for returning players |
| NewPeerInfo | joiners' names + peer ids | same caveat |
| Your own C→S heartbeats | your game index | confirmed: morganc=28 (1-idx) |
| Offline player cache in level.dat | names + playtime/last-online | offline players only, no index |
| Alerts in level.dat | names only | LocalisedStrings, no index |
| RCON `game.players` | full roster | the clean endgame (needs server control) |

## Document Index

- [level.dat — Internal Format](level-dat.md) — chunks, header, optim
  encoding, console buffer, offline cache.
- [../save-file-format.md](../save-file-format.md) — transfer/zip details,
  packet-loss analysis and capture fixes, red herrings.

## Red Herrings (things that look like player data but aren't)

1. **Blueprint authors** (Montoyo, Guillaumeb810, MasterTaz, … at 40–116 MB)
   — imported blueprint book authors, not the roster.
2. **The post-zip name lists** — alphabetical, partial, no indexes.
3. **GUI layout names** (`top`, `horizontal_flow`, `empty_widget`, …) — GUI
   state around alerts/events.
4. **`"players"` strings** in level.dat — inside blueprint labels.
5. **Alerts** — reference players by name in LocalisedString params, carry
   NO index.
6. **`level.datmetadata`** — 8 bytes, a timestamp/counter, not player data.

## Tools

- `tools/extract_save_from_pcap.rb` — reconstruct a chosen download's save
  and decompress the intact level.dat chunks (fixed to inflate internally-
  zlib method-0 chunks).
- `tools/extract_players_from_save.rb` — parse the console buffer from a
  decompressed level.dat → 1-indexed name→index JSON.
