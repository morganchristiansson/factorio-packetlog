# Save / Map Download — Transfer & Capture

How the server's map save travels on the wire, and how to capture it
losslessly. For the decoded internals of `level.dat` (header, console
buffer, player data) see [docs/save/](save/README.md).

## Transfer Layer

- The map download is a stream of **TransferBlock** (msg type 13) packets:
  `network header(1) | block_number(4, LE) | data(503 bytes)`.
- The client requests blocks with **TransferBlockRequest** (msg type 12,
  just a block number).
- Blocks arrive in order `0, 1, 2, …, N`; concatenating reproduces the
  server's save file byte-for-byte (~40 MB here; 80–84k blocks over ~4 s).

### Multiple servers in one capture

A second server connection reuses block numbers from 0. Separate downloads
by ConnectionRequest (msg 2) timestamps (`tools/extract_save_from_pcap.rb`
does this; the download index counts connection requests).

## The Save Archive (mp-save-100.zip / mp-save-122/123/124.zip)

- A standard ZIP with **data-descriptor flags** (`flags & 0x08`) — local
  header `csize`/`usize` are 0; use the **central directory**.
- Entries: `control.lua`, `description.json`, `level-init.dat`,
  `locale/*/freeplay.cfg`, `level.dat0..N`, `level.datmetadata`,
  `script.dat`, `info.json` (which is `"null"` here).
  **No player-data.json** — player data lives inside `level.dat`
  (see [docs/save/level-dat.md](save/level-dat.md)).
- After the zip's EOCD, the final transfer block is a **server-info block**:
  game name, motd/description, server address, and **alphabetical** name
  lists (verified NOT index-ordered).

## Packet Loss & Capture Fixes

Two independent loss mechanisms were verified in the live captures:

1. **Capture drops (dominant)** — the map download bursts at ~20k pps
   (~10 MB/s). The old pcaprub loop (`cap.next` + `sleep 0.01`) overflowed
   the libpcap kernel buffer: the client received every block (it never
   re-requested them) but the pcap copy was dropped. Missing blocks were
   zero-padded in reconstruction, corrupting the zlib chunks they spanned.
2. **Network loss** — the client re-requested blocks it genuinely missed
   (3,719 in one session); retransmissions were byte-identical and captured.

**Fixes in `factorio-packettools.rb`:**
- pcaprub's blocking `each_data` (waits on the fd, no sleep-polling).
- **Transfer fast path**: msg-13 packets are detected with a one-byte peek
  and written straight to the pcap sink (measured ~5M pps vs 28k pps).
- **Buffered `PcapWriter`** with a background flush thread — disk I/O never
  blocks the capture loop.
- `cap.stats` drop reporting: `[capture] kernel buffer drops: N`.

**For lossless captures** use tcpdump:

```bash
sudo tcpdump -i eth0 -w session.pcap 'udp port 34197'
```

## Tooling

- `tools/extract_save_from_pcap.rb` — reconstruct a chosen download's save
  from the pcap and decompress intact level.dat chunks (handles internally-
  zlib method-0 chunks; outputs `level.dat`, per-chunk files, other entries).
  Requires the capture to include TransferBlocks: run the sniffer with
  `capture: save` in config.yaml (off by default since 2025 —
  TransferBlocks are ~12% of file size and contain no player actions).
- `tools/extract_players_from_save.rb` — recover the FULL roster from a save
  archive or a decompressed level.dat (index → name, play time, last-online
  tick, locale; all verified against a live `game.players` dump — the locale
  for 290 of 338 records, zero wrong), and optionally `--merge` the names
  (and any locale the cache lacks) into players-cache.json. Needs no cache —
  a player record is a name with a play-time pair in front of it — and when
  players-cache.json does have names it also validates them (refuses a save
  from another world). `admin` is server state (adminlist.json), not in the
  save.

## Client mode: seed the roster from the map download

Client mode has no RCON and only ever sees players who join *after* us, so
the names of everyone already in the game are unknown. The map download is
the fix: it is the server's own save, and it carries the whole roster.

**Live (the normal path).** Every msg 13 TransferBlock the client receives is
handed to `lib/map_download.rb` from the capture thread — a hash store under a
mutex, nothing else. A worker thread waits for the stream to go quiet (5 s),
concatenates blocks 0..N into `captures/map-download-<ts>.zip` and runs
`tools/extract_players_from_save.rb` on it with `--merge`, then reloads the
in-memory cache, so the running session knows the names. The archive is
deleted once the roster is out of it (the pcap keeps the blocks if you asked
for `capture: save`/`full`). A download with a hole in it (capture loss) is
reported and skipped — the zip's central directory lives at the end, so a
partial archive is not a usable save. No new config: it turns itself on in
client mode, because that is the only mode that needs it.

**Offline** (the same two steps by hand, e.g. after the fact):

```bash
ruby tools/extract_save_from_pcap.rb captures/client-<ip>-<ts>.pcap outdir
ruby tools/extract_players_from_save.rb outdir/save.zip players-cache.json --merge
```

An index that turns out to be off (the run is assumed to start at index 1)
self-corrects on the first join seen on the wire, via
`PlayerDatabase#remove_other_entries_for`. The save also carries each
player's **locale** (290 of 338 here, never wrong), so a client-mode session
gets the languages of players already in the game too — the one thing the
wire never carries (checked: no capture contains a single multi-char locale
code).

## Capture size note (verified on a 4.9M-packet / 444 MB client-mode capture)

Most of the file is NOT the input actions: ~64% is fixed per-packet framing
(16 B pcap record header + 14 B Ethernet + 20 B IP + 8 B UDP), and ~40% of
packets are **empty keepalive heartbeats** (msg 6/7 with no tick closures, no
sync actions, no requests — only ~0.4% carry a sync action). TransferBlocks
(one ~44 MB save download) are ~12%. The input actions themselves are ~2.6M
actions in ~86 MB of heartbeat payload across 4.9M tiny packets.

## Capture filtering / compression / retention (since 2025)

The sniffer's always-on capture filters and can compress/rotate:

- **TransferBlocks (msg 13)** are excluded by default (no player actions,
  ~12% of file size); `capture: save` keeps ONLY them for save
  extraction, `capture: full` records everything.
- **Keepalive-only heartbeats** (flags byte: no heartbeat requests 0x01, no
  synchronizer action 0x10, tick closures all-empty 0x08) are dropped —
  ~40% of packets in a typical session. This is a single-byte check, no
  parse cost.
- **Server mode** additionally captures only incoming (C→S) packets: the
  outgoing direction is the same actions broadcast to every client, and
  analysis never reads it. A 5h server capture dropped from ~460MB to
  ~20MB with the two filters combined.
- **Gzip**: name the capture path with a `.gz` suffix → the stream is
  written gzip-compressed (measured ~3.4x on a full capture; much better
  once keepalives are filtered). `PcapReader` auto-detects and gunzips,
  so `-r` analysis and `tools/extract_save_from_pcap.rb` work unchanged.
- **Rolling retention**: the capture rotates every hour AND when it
  exceeds 256 MB (timestamped files); rotated files are deleted once older
  than 72h (`keep`) or the rotated total passes 512 MB (`max_size`, oldest
  first). Change them in config.yaml when you need more history. Combine
  with `.gz` paths.

All of it is bypassed with `capture: full` (record every packet as-is).
