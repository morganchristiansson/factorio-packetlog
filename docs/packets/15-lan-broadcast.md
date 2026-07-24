# LANBroadcast (Type 15)

Broadcast sent by servers on LAN for discovery. Clients listen for these to
find local servers without needing the server address.

## Direction

Server → LAN (broadcast)

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=15` |
| 1 | var | Server Name | String with game/server info |

The payload typically contains human-readable server information
including the game name, version, map, and player count.
