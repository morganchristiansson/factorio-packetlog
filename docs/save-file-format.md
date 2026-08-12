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

**Fixes in `factorio-sniffer.rb`:**
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
- `tools/extract_players_from_save.rb` — parse the console buffer from a
  decompressed level.dat → 1-indexed name→index JSON.
