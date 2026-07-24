# GetOwnAddressReply (Type 9)

Server replies with the client's public address as seen by the server.

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=9` |
| 1 | 4 | IP Address | uint32, IP address in network byte order |
| 5 | 2 | Port | uint16, UDP port in network byte order |

## See Also

- [GetOwnAddress](08-get-own-address.md)
