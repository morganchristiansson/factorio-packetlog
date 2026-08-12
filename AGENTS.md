# Factorio Packet Sniffer — Agent Context

## Project Overview

Factorio multiplayer protocol reverse-engineering tool. Captures UDP traffic,
decodes the binary protocol, extracts player actions, and logs them. Runs
either on a client or on the game server host (server mode, with RCON).

## Key Files

- `factorio-sniffer.rb` — Entry point: CLI + hot-reload loop (thin)
- `lib/factorio_sniffer.rb` — Main sniffer class (`FactorioSniffer`),
  `SnifferState` (state carried across hot reloads)
- `lib/factorio_protocol.rb` — Protocol parser (ACTIONS table, parsing logic)
- `lib/server_detect.rb` — Auto-detects a running factorio server
  (game port, RCON endpoint, server IPs, dedicated-server detection)
- `lib/rcon_client.rb` — RCON roster query (`rcon.print` + `serpent.line`)
- `lib/player_db.rb` — Player ID→name mapping (`players.json`)
- `lib/pcap.rb` — PcapWriter / PcapReader
- `lib/live_capture.rb` — pcaprub live capture (msg-13 fast path)
- `tools/rcon.rb` — RCON CLI (status/players/exec/raw)
- `tools/item_db.rb` — regenerate item/entity prototype ID→name dumps from RCON (wire IDs = `prototypes.item` / `prototypes.entity` iteration order)
- `players.json` — 1-indexed player ID→name mapping
- `external/` — Game dumps (`input_actions_dump.txt`, `data-raw-dump.json`, `item_prototypes_runtime.txt`, `entity_prototypes_runtime.txt`, …)

## Docs (details live here, not in this file)

- `docs/README.md` — Protocol reference (network layer, packets, actions)
- `docs/protocol-notes.md` — Session-verified protocol findings, fixed
  issues, unknown types, chat formats, echo lengths
- `docs/server-mode.md` — Server mode, auto-detection, RCON, hot reload
- `docs/rcon-knowledge.md` — RCON knowledge base: rcon.print / serpent.line
  data channel, `helpers.write_file` dumps to script-output, `prototypes.*`
  iteration order (= wire IDs), response-size cap, gotchas. Read this
  before writing new RCON queries.
- `docs/player-mapping.md` — Peer IDs vs game indexes, save-file findings
- `docs/save/`, `docs/save-file-format.md` — Save/map-download internals

## Critical Invariants

- **Player IDs**: 0-indexed in protocol, 1-indexed in game and
  `players.json`. Add `+1` to decoded values. Network peer ids are NOT game
  indexes (see `docs/player-mapping.md`).
- **Server mode** (default when run on the server host): analyzes only
  incoming C→S packets (no broadcast duplicates), drops save-download
  TransferBlocks. `--local-ip` forces client mode. See `docs/server-mode.md`.
- **Hot reload**: Ctrl-C once reloads code (capture file, player DB, stats
  preserved); Ctrl-C again quits. Player names persist to `players.json`.
- **RCON data channel**: `rcon.print(data)` returns values through RCON;
  `serpent.line` for tables. `/players` lists names only (no index). See
  `docs/rcon-knowledge.md` for the full API knowledge base (incl.
  `helpers.write_file` for large dumps, `prototypes.*` ordering).

## Usage

```bash
# Server host, everything auto-detected (interface, port, IP, RCON):
sudo ruby factorio-sniffer.rb

# Client mode / pcap analysis:
sudo ruby factorio-sniffer.rb -i eth0 -p 34197 --local-ip 192.168.1.144
ruby factorio-sniffer.rb -r capture.pcap
ruby factorio-sniffer.rb -r capture.pcap --item-db external/item_prototypes_runtime.txt --entity-db external/entity_prototypes_runtime.txt

# RCON admin:
ruby tools/rcon.rb status          # version/players/admins/time/evolution
ruby tools/rcon.rb exec "/shout hi"  # or /sc for silent Lua

# Tests:
ruby -Ilib spec/server_mode_spec.rb       # server mode + ops
ruby -Ilib spec/packet_fixtures_spec.rb   # real captured packets
ruby -Ilib spec/factorio_protocol_spec.rb # protocol unit tests
```
