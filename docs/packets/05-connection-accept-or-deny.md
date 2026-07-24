# ConnectionAcceptOrDeny (Type 5)

Server accepts or denies the connection attempt.

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=5` |
| 1 | 2 | New Peer ID | uint16 little-endian, the peer ID assigned to the client (0 = denied) |
| 3 | var | ... | Additional data (accept reason, etc.) |

A `new_peer_id` of 0 indicates the connection was denied.

## See Also

- [ConnectionRequestReplyConfirm](04-connection-request-reply-confirm.md)
