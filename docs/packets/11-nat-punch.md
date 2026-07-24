# NatPunch (Type 11)

NAT punchthrough response from server to client.

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=11` |
| 1 | 4 | Target IP | uint32, IP address of target peer |
| 5 | 2 | Target Port | uint16, UDP port of target peer |
