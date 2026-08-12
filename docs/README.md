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

| ID | Name | Direction | Description |
|----|------|-----------|-------------|
| 0  | [Ping](packets/00-ping.md) | Bidirectional | Keepalive ping |
| 1  | [PingReply](packets/01-ping-reply.md) | Bidirectional | Ping response |
| 2  | [ConnectionRequest](packets/02-connection-request.md) | Client→Server | Initial connection request with version info |
| 3  | [ConnectionRequestReply](packets/03-connection-request-reply.md) | Server→Client | Server response to connection request |
| 4  | [ConnectionRequestReplyConfirm](packets/04-connection-request-reply-confirm.md) | Client→Server | Client confirms with username/password |
| 5  | [ConnectionAcceptOrDeny](packets/05-connection-accept-or-deny.md) | Server→Client | Server accepts or denies connection, assigns peer ID |
| 6  | [ClientToServerHeartbeat](packets/06-client-to-server-heartbeat.md) | Client→Server | Regular heartbeat with tick closures |
| 7  | [ServerToClientHeartbeat](packets/07-server-to-client-heartbeat.md) | Server→Client | Regular heartbeat with tick closures |
| 8  | [GetOwnAddress](packets/08-get-own-address.md) | Client→Server | NAT traversal: ask server for own public address |
| 9  | [GetOwnAddressReply](packets/09-get-own-address-reply.md) | Server→Client | NAT traversal: server replies with client's public address |
| 10 | [NatPunchRequest](packets/10-nat-punch-request.md) | Client→Server | NAT punch request |
| 11 | [NatPunch](packets/11-nat-punch.md) | Server→Client | NAT punch response |
| 12 | [TransferBlockRequest](packets/12-transfer-block-request.md) | Client→Server | Request a download block by number |
| 13 | [TransferBlock](packets/13-transfer-block.md) | Server→Client | 503-byte download block (map save chunks) |
| 14 | [RequestForHeartbeatWhenDisconnecting](packets/14-request-heartbeat-disconnect.md) | Client→Server | Request heartbeat before disconnect |
| 15 | [LANBroadcast](packets/15-lan-broadcast.md) | Server→LAN | LAN server discovery broadcast |
| 16 | [GameInformationRequest](packets/16-game-info-request.md) | Client→Server | Request game information |
| 17 | [GameInformationRequestReply](packets/17-game-info-reply.md) | Server→Client | Game information response |
| 18 | [Empty](packets/18-empty.md) | Bidirectional | Empty keepalive |

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

- **Game player indexes** (what heartbeat actions carry, 0-indexed in the
  protocol) are the index into `game.players`; `players.json` uses
  1-indexed values. Add +1 to decoded values.
- **Network peer ids** (ConnectionAcceptOrDeny `clientPeerInfo`, NewPeerInfo
  sync peer_id) are a separate connection counter. They only equal game
  indexes for brand-new joiners.

## Action Types

See [actions.md](actions.md) for the complete list of input action types.

## Verified Packet Fixtures

Documentation must be grounded in real captured packets, not mirror the
implementation. Every documented format should cite a fixture in
[`spec/fixtures/packets.rb`](../spec/fixtures/packets.rb) (real packets from
live sessions, with expected parse output) or
[`spec/fixtures/chat_variations.rb`](../spec/fixtures/chat_variations.rb)
(synthetic variations of `write_to_console` payloads).

The fixture specs (`spec/packet_fixtures_spec.rb`) parse each real packet
through `FactorioProtocol.parse_udp_payload` and assert the exact actions,
so changing the decoder requires updating the fixtures — preventing
silent regressions (e.g. the repeated chat truncation bugs).

To add a fixture from a live capture:

1. Extract the raw UDP payload hex (e.g. from `factorio_capture.pcap`).
2. Verify the expected parse output manually.
3. Add it to `spec/fixtures/packets.rb` with the expected actions.
4. Run `ruby -Ilib spec/packet_fixtures_spec.rb`.

## Additional Notes

- [`protocol-notes.md`](protocol-notes.md) — session-verified findings:
  fixed parsing issues, unknown types, chat message formats, server echo
  metadata suppression, verified echo data lengths.
- [`player-mapping.md`](player-mapping.md) — peer IDs vs game player
  indexes, where player names live in the save, red herrings.
- [`server-mode.md`](server-mode.md) — running the sniffer on the game
  server host: server mode semantics, auto-detection, RCON roster, hot
  reload.
- Save/map-download internals: [`save-file-format.md`](save-file-format.md)
  and [`save/`](save/).
