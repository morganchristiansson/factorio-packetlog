# PingReply (Type 1)

Reply to a Ping packet.

## Direction

- Server → Client
- Client → Server

## Structure

Contains a 4-byte ping number that echoes the sender's sequence number.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=1` |
| 1 | 4 | Ping Number | uint32 little-endian, echoes the ping number from the original Ping |

## See Also

- [Ping](00-ping.md)
