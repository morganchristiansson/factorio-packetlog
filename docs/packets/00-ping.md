# Ping (Type 0)

Ping packet for keepalive and latency measurement.

## Direction

- Server → Client
- Client → Server

## Structure

No payload beyond the network header. The presence of the packet with `HasRandom`
flag serves as the ping signal.

## Fields

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=0`, typically with `HasRandom` flag |

## Example

```
Hex: 20
     ^^ msg_type=0, HasRandom=true
```

## See Also

- [PingReply](01-ping-reply.md)
