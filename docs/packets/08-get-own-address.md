# GetOwnAddress (Type 8)

Sent by client to determine their own public IP/port as seen by the server.
Used for NAT punchthrough.

## Direction

Client → Server

## Structure

Minimal packet, no additional payload beyond the network header.

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=8` |

## See Also

- [GetOwnAddressReply](09-get-own-address-reply.md)
