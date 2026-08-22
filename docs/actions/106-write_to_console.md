# write_to_console (Type 106)

Send a chat message or console command.

## Data Length

Variable — see payload formats below.

## Payload Formats

The payload's first byte is a message-type marker:

| Marker | Format | Notes |
|--------|--------|-------|
| 0x04 | `[04][text...]` | Non-segment, text runs to end |
| 0x05 | `[05][meta(1)][text...]` | meta = TOTAL message length (may span segments); text runs to end |
| 0x0b | `[0b][meta(1)][text...]` | Same layout as 0x05 |
| 0x24 | `[24][meta(1)][text...]` | Same layout as 0x05 (observed live) |
| 0x29 | `[29][meta(1)][text...]` | Same layout as 0x05 (observed live) |
| 0x00 / 0x3d / 0x01 | `[marker][meta(1)][text...]` | Server echoes |
| other | — | Treated as uint32v-prefixed or raw text |

For the `[marker][meta][text...]` formats the text starts at byte 2 and runs
to the END of the payload — `meta` is the total message length across all
segments, NOT the current segment's length. Truncating to `meta` bytes loses
the rest of the message when it is split across segments.

Multi-segment messages: first segment carries `[marker][total_len][first_part]`,
subsequent segments carry raw `[continuation]` text (no marker).

A 2-byte `[marker][0x00]` payload is a zero-length message (empty chat
submission) — decodes to nil.

## Example (observed live, 2026-08-11)

Server echo of "molten supply not stable" inside a segment (packet header
0x27 — random flag set, payload starts at byte 1):

```
27 06 8781b300 e835b30000000000 | 03 | 54 01 [12B tick_info]
  | 01 6a 5e010000 05 0100 1a | 05 18 6d6f6c74656e20737570706c79206e6f7420737461626c65
                                  │   │
                                  │   └ meta 0x18 = 24 = text length
                                  └ marker 0x05
```

## Player Index

1-indexed game player.

## Fixtures

- `test/fixtures/packets.rb`: `client_chat_message_0x0b`, `server_chat_echo_segment`,
  `server_empty_chat_echo`, `server_chat_echo_random_flag_packet`
- `test/fixtures/chat_variations.rb`: all marker formats + edge cases
