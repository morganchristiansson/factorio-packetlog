# Factorio Packet Sniffer — Agent Context

## Project Overview

Factorio multiplayer protocol reverse-engineering tool. Captures UDP traffic,
decodes the binary protocol, extracts player actions, and logs them. Runs
either on a client or on the game server host (server mode, with RCON).

## Key Files

- `factorio-sniffer.rb` — Entry point: CLI + hot-reload loop (thin)
- `lib/factorio_sniffer.rb` — Main sniffer class (`FactorioSniffer`),
  `SnifferState` (state carried across hot reloads)
- `lib/factorio_protocol.rb` — Protocol parser (ACTIONS table, parsing logic). Input-action IDs are version-dependent (2.0 vs 2.1): `FactorioProtocol.select_version` picks the main + segment maps (`lib/input_actions_20.rb`, auto-detected from RCON `helpers.game_version`; `--protocol-version` overrides). `tools/validate_actions.rb` validates IDs against `/toggle-action-logging` output. See `docs/protocol-notes.md`.
- `lib/server_detect.rb` — Auto-detects a running factorio server
  (game port, RCON endpoint, server IPs, dedicated-server detection)
- `lib/rcon_client.rb` — RCON roster query (`rcon.print` + `serpent.line`), `#say` for in-game chat (Lua-quoted `game.print`)
- `lib/player_db.rb` — Player ID→name mapping (`players.json`)
- `lib/ai_agent.rb` — Hivemind AI agent (`HiveMindAgent`): answers in-game chat containing "hivemind" (case-insensitive) via ruby_llm; replies through RCON `game.print` using the `HivemindSay` RubyLLM tool, and can run READ-ONLY RCON queries via `RconQuery`. Tools are re-registered before every ask, so Ctrl-C hot reloads pick up agent/tool code changes without restart. Chat input comes from packet-decoded `write_to_console` actions; context includes online players + play-time/admin stats. See `docs/ai-agent.md`.
- `lib/pcap.rb` — PcapWriter / PcapReader
- `lib/live_capture.rb` — pcaprub live capture (msg-13 fast path)
- `tools/rcon.rb` — RCON CLI (status/players/exec/raw)
- `tools/item_db.rb` — regenerate item/entity prototype ID→name dumps from RCON (wire IDs = `prototypes.item` / `prototypes.entity` iteration order)
- `tools/validate_actions.rb` — validate input-action wire IDs against `/toggle-action-logging` output (correlate `Action performed [tick player Name]` lines with packet captures by tick; flags OK/MISMATCH/NOT-IN-TABLE; `--suggest` prints a corrected table). Run: `sudo ruby tools/validate_actions.rb --capture 60 --toggle`
- `tools/dump_input_actions.rb` — regenerate `lib/input_actions_20.rb` (2.0 defines dump + validated internal wire actions)
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
- **Online tracking**: the sniffer keeps a live `name → index` map of
  players currently in-game (`FactorioSniffer#online_players`) — seeded
  from the RCON roster, updated on NewPeerInfo / PeerDisconnect, indexes
  bound by C→S heartbeats. Survives hot reloads. Fed to the Hivemind agent
  as context (`HiveMindAgent#online_provider`).
- **Server mode** (default when run on the server host): analyzes only
  incoming C→S packets (no broadcast duplicates), drops save-download
  TransferBlocks. `--local-ip` forces client mode. Captured pcaps
  (`--save-capture`) are filtered by default: TransferBlocks (msg 13),
  keepalive-only heartbeats, and (server mode) outgoing S→C broadcasts are
  excluded — a 5h server capture went from ~460MB to ~20MB. `--full-capture`
  records everything; `--save-transfer-blocks` keeps just the TransferBlocks
  (needed for `tools/extract_save_from_pcap.rb`). A `.gz` path compresses
  the pcap stream (~3-4x); `--keep HOURS` rolls hourly and prunes files
  older than HOURS. See `docs/server-mode.md`.
- **Hot reload**: Ctrl-C once reloads code (capture file, player DB, stats
  preserved); Ctrl-C again quits. Player names persist to `players.json`.
- **Interactive filter console**: type `/show NAME`, `/hide NAME`, `/actions`,
  `/noise`, `/chat`, `/quiet` at the sniffer's stdin to filter console
  output live (survives hot reloads). Chat is always printed. See
  `docs/server-mode.md`.
- **RCON data channel**: `rcon.print(data)` returns values through RCON;
  `serpent.line` for tables. `/players` lists names only (no index). See
  `docs/rcon-knowledge.md` for the full API knowledge base (incl.
  `helpers.write_file` for large dumps, `prototypes.*` ordering).

## Usage

```bash
# Server host, everything auto-detected (interface, port, IP, RCON):
sudo ruby factorio-sniffer.rb

# With the Hivemind AI agent (answers "hivemind" mentions in chat):
HIVE_API_KEY=... sudo ruby factorio-sniffer.rb --ai-agent
sudo ruby factorio-sniffer.rb --ai-agent --ai-api-key "$HIVE_API_KEY" --ai-model glm-5.3

# Pcap from a 2.0 server (segment-type map differs from 2.1):
ruby factorio-sniffer.rb -r capture.pcap --protocol-version 2.0

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
