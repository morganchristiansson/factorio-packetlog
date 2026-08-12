# TransferBlock (Type 13)

Data block transfer response. Contains the next chunk of a file download
(the map save during join).

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=13` |
| 1 | 4 | Block Number | uint32 little-endian, sequential per download |
| 5 | var | Data | Raw data bytes (503 bytes per block in practice) |

## Notes

- The client requests blocks with
  [TransferBlockRequest](12-transfer-block-request.md), which carries just
  the block number.
- Blocks arrive in order `0, 1, 2, …, N`; concatenating the data fields
  reproduces the transferred file byte-for-byte. The map download is the
  server's save archive (`mp-save-100.zip`).
- A second server connection in the same capture reuses block numbers from 0
  — separate downloads by ConnectionRequest (msg 2) timestamps.
- The final block is followed by an extra ~503-byte "player info" block
  after the zip's EOCD (see [Save format](../save-file-format.md)).

## See Also

- [TransferBlockRequest](12-transfer-block-request.md)
- [Save / Map Download Format](../save-file-format.md)
