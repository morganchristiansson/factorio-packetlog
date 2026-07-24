# ConnectionRequest (Type 2)

Sent by the client to initiate a connection to the server.

## Direction

Client → Server

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=2` |
| 1 | 1 | Major Version | uint8 |
| 2 | 1 | Minor Version | uint8 |
| 3 | 1 | Patch Version | uint8 |
| 4 | 4 | Build | uint32 little-endian, contains version build number |
| 8 | 4 | Client ID | uint32 little-endian, random client identification |

## Example

```
Hex: 22 01 01 01 68 02 00 00 2D 00 00 00
     ^^ msg_type=2, HasRandom=true
        ^^ major=1
           ^^ minor=1
              ^^ patch=1
                 ^^ ^^ ^^ ^^ build=0x268=616
                                ^^ ^^ ^^ ^^ client_id=0x2D=45
```

## See Also

- [ConnectionRequestReply](03-connection-request-reply.md)
