# TransferBlockRequest (Type 12)

Request to transfer a block of data. Used for map downloads, mod transfers, etc.

## Direction

Client → Server

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=12` |
| 1 | 4 | Block ID | uint32, identifies the block being requested |
| 5 | 4 | Offset | uint32, offset within the block |
| 9 | 2 | Size | uint16, requested size |

## See Also

- [TransferBlock](13-transfer-block.md)
