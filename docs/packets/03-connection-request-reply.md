# ConnectionRequestReply (Type 3)

Server's response to a connection request, providing connection parameters.

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=3` |
| 1 | 2 | Max Packet Size | uint16 little-endian, maximum packet size for fragmentation |

## See Also

- [ConnectionRequest](02-connection-request.md)
- [ConnectionRequestReplyConfirm](04-connection-request-reply-confirm.md)
