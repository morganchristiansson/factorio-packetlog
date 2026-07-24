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
| 12 | [TransferBlockRequest](packets/12-transfer-block-request.md) | Client→Server | Request data block transfer |
| 13 | [TransferBlock](packets/13-transfer-block.md) | Server→Client | Data block transfer |
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

## Action Types

See [actions.md](actions.md) for the complete list of input action types.
