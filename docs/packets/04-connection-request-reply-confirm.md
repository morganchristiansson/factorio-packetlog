# ConnectionRequestReplyConfirm (Type 4)

Client confirms the connection request reply, providing authentication info.

## Direction

Client → Server

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=4` |
| 1 | 4 | Client ID | uint32 little-endian |
| 5 | 4 | Server ID | uint32 little-endian |
| 9 | 4 | Instance ID | uint32 little-endian |
| 13 | var | Username | uint32v length-prefixed string |
| + | var | Password Hash | uint32v length-prefixed string |
| + | var | Server Key | Additional key data (variable) |
| + | 8 | Timestamp | uint64 little-endian, timestamp |

## Fields

The username is a variable-length string prefixed with a uint32v length.
The password hash follows the same pattern.
