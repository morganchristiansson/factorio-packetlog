# Factorio Protocol Documentation

This directory contains documentation for the Factorio multiplayer protocol,
reverse-engineered from packet captures and the
[Hornwitser/factorio_dissector](https://github.com/Hornwitser/factorio_dissector)
Wireshark plugin.

## Network Layer

Factorio uses UDP for multiplayer. Each packet starts with a **Network Header**
byte that identifies the message type.

### Network Header (1 byte)

```
Bit 0-4: Message Type ID (0-18)
Bit 5:    HasRandom (checksum perturbation flag)
Bit 6:    Fragmented
Bit 7:    LastFragment
```

### Message Types

| ID | Name | Direction | Payload summary |
|----|------|-----------|-----------------|
| 0 | Ping | Bidirectional | Header only; keepalive/latency probe |
| 1 | PingReply | Bidirectional | uint32 ping number |
| 2 | ConnectionRequest | Client→Server | major/minor/patch bytes, uint32 build, uint32 client id |
| 3 | ConnectionRequestReply | Server→Client | uint16 maximum packet size |
| 4 | ConnectionRequestReplyConfirm | Client→Server | client/server/instance ids, length-prefixed connection strings, uint64 timestamp |
| 5 | ConnectionAcceptOrDeny | Server→Client | connection status, game/host metadata, mods, and network peer list |
| 6 | ClientToServerHeartbeat | Client→Server | sequence, tick closures, synchronizer actions, requests, next-receive tick |
| 7 | ServerToClientHeartbeat | Server→Client | sequence, echoed tick closures, synchronizer actions, requests |
| 8 | GetOwnAddress | Client→Server | Header only; NAT address discovery |
| 9 | GetOwnAddressReply | Server→Client | IPv4 address + UDP port in network byte order |
| 10 | NatPunchRequest | Client→Server | Header only |
| 11 | NatPunch | Server→Client | Target IPv4 address + UDP port |
| 12 | TransferBlockRequest | Client→Server | Block id, offset, and requested size |
| 13 | TransferBlock | Server→Client | uint32 block number + raw archive bytes (normally 503-byte chunks) |
| 14 | RequestForHeartbeatWhenDisconnecting | Client→Server | Header only; final-heartbeat request fallback |
| 15 | LANBroadcast | Server→LAN | Human-readable server discovery data |
| 16 | GameInformationRequest | Client→Server | Header only |
| 17 | GameInformationRequestReply | Server→Client | Name, version/build, description, uptime, host, mods, tags, players |
| 18 | Empty | Bidirectional | Header only; filler/keepalive |

The decoder currently extracts full payloads for connection messages 2, 4,
and 5, heartbeats 6/7, and game-information reply 17. Other message types
retain their network header and are ignored by the analysis path.

## Heartbeat Layout

Messages 6 and 7 share this framing after the network header:

```text
flags(1) sequence(4)
[tick closures when flags bit 1 is set]
[next-receive tick(8), client heartbeats only]
[synchronizer actions when flags bit 4 is set]
[heartbeat requests when flags bit 0 is set]
```

Heartbeat flag bits are: 0 requests, 1 tick closures, 2 one tick closure,
3 all closures empty, and 4 synchronizer actions. Each tick closure starts
with a uint64 game tick. Its action count is a uint32v whose low bit says
whether input-action segments follow. Client heartbeat actions use two
uint16v fields (type and player delta); version- and direction-specific data
lengths and trailers are documented in `protocol-notes.md`.

A synchronizer action is a type byte plus type-specific data. The decoder
uses NewPeerInfo (type 2) to learn usernames and PeerDisconnect (type 1)
for clean leave events. Heartbeat requests are uint32 sequence numbers.

## Input Actions

Heartbeat packets (types 6 and 7) contain **Tick Closures** which in turn
contain **Input Actions**. These are the player actions that drive the game state.

Each input action starts with:
- **Action Type** (uint16v): The action ID
- **Player Delta** (uint16v): Delta-encoded player index
- **Action Data** (variable): Action-specific data

The player index is computed as: `player = (previous_player + delta) & 0xFFFF`
where `previous_player` starts at `0xFFFF` (65535) at the beginning of each
tick closure.

> **Version note**: input-action IDs are version-dependent (2.0 vs 2.1
> differ — start_walking 67 vs 69, write_to_console 104 vs 106, etc.).
> `FactorioProtocol.select_version` picks both the main and segment maps;
> the sniffer auto-detects via RCON `helpers.game_version` (or
> `--protocol-version`). Verified with `tools/validate_actions.rb`.
> See [protocol-notes.md](protocol-notes.md) and
> [lib/input_actions_20.rb](../lib/input_actions_20.rb).

### Variable-Length Integer Encoding

Factorio uses a variable-length encoding for integers:

- **uint16v**: If the first byte is < 0xFF, the value is the byte itself (1 byte).
  If the first byte is 0xFF, the next 2 bytes (little-endian uint16) contain the
  value (3 bytes total).

- **uint32v**: If the first byte is < 0xFF, the value is the byte itself (1 byte).
  If the first byte is 0xFF, the next 4 bytes (little-endian uint32) contain the
  value (5 bytes total).

## Map Download & Save Format

When a client joins, the server streams its entire save file as a sequence
of 503-byte TransferBlock packets (a ZIP containing scenario files and
`level.dat` chunks). See [Save / Map Download Format](save/README.md) for
an index, [level.dat internals](save/level-dat.md) for the decoded game
state (console-buffer player index mapping, offline player cache), and
[save-file-format.md](save/save-file-format.md) for the transfer layer, zip
structure and lossless-capture fixes.

## Player ID Conventions

- **Game player indexes** (heartbeat action `game_player` field) are
  1-indexed (Lua-style); the wire protocol is 0-indexed but the parser
  converts at decode time. `players-cache.json` uses 1-indexed values.
- **Network peer ids** (ConnectionAcceptOrDeny `clientPeerInfo`, NewPeerInfo
  sync peer_id) are a separate connection counter. They only equal game
  indexes for brand-new joiners.

## Action Types

See [actions.md](actions.md) for the complete list of input action types.

## Verified Packet Fixtures

Documentation must be grounded in real captured packets, not mirror the
implementation. Every documented format should cite a fixture in
[`test/fixtures/packets.rb`](../test/fixtures/packets.rb) (real packets from
live sessions, with expected parse output) or
[`test/fixtures/chat_variations.rb`](../test/fixtures/chat_variations.rb)
(synthetic variations of `write_to_console` payloads).

The fixture tests (`test/packet_fixtures_test.rb`) parse each real packet
through `FactorioProtocol.parse_udp_payload` and assert the exact actions,
so changing the decoder requires updating the fixtures — preventing
silent regressions (e.g. the repeated chat truncation bugs).

To add a fixture from a live capture:

1. Extract the raw UDP payload hex (e.g. from `factorio_capture.pcap`).
2. Verify the expected parse output manually.
3. Add it to `test/fixtures/packets.rb` with the expected actions.
4. Run `ruby -Ilib test/packet_fixtures_test.rb`.

Run the complete suite with `bundle exec ruby -Ilib test/*_test.rb test/fixture_tests.rb`;
add `--verbose` to show captured output for otherwise quiet successful files.

## Additional Notes

- [`protocol-notes.md`](protocol-notes.md) — session-verified findings:
  fixed parsing issues, unknown types, chat message formats, server echo
  metadata suppression, verified echo data lengths.
- [`player-mapping.md`](player-mapping.md) — peer IDs vs game player
  indexes, where player names live in the save, red herrings.
- [`grief-analysis.md`](grief-analysis.md) — investigating "who did X at
  position Y" from captures: which actions carry positions, mining's
  blind spot, the correlation workflow, and hard limits.
- [`server-mode.md`](server-mode.md) — running the sniffer on the game
  server host: server mode semantics, auto-detection, RCON roster, hot
  reload.
- Save/map-download internals: [`save-file-format.md`](save-file-format.md)
  and [`save/`](save/).
