# TransferBlock (Type 13)

Data block transfer response. Contains actual data being transferred.

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=13` |
| 1 | 4 | Block ID | uint32 |
| 5 | 4 | Offset | uint32 |
| 9 | var | Data | Raw data bytes |

## See Also

- [TransferBlockRequest](12-transfer-block-request.md)
