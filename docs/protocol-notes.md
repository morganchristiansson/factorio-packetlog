# Protocol Notes (reverse-engineering findings)

Session-verified findings about the Factorio multiplayer protocol. The
authoritative reference docs are `docs/README.md` (network layer),
`docs/packets/` (per-message), `docs/actions/` (input actions). This file
holds the *verified-by-capture* notes, fixes, and open questions.

## ACTIONS Table (`lib/factorio_protocol.rb`)

Built from the `defines.input_action` dump (`external/input_actions_dump.txt`).
IDs from the dump may DIFFER from protocol IDs in some sessions. The mapping
includes:
- Core actions (build=68, wire_dragging=86, etc.)
- Internal-only actions (nothing=0, stop_walking=1, stop_mining=3)
- Session-verified protocol IDs for some types (wire_dragging at 84 vs 86)

## Key Protocol Findings

- **Player IDs**: 0-indexed in protocol, 1-indexed in game. `players.json`
  uses 1-indexed. Add `+1` to decoded values.
- **Ghost flag**: detected via `next_receive & 1` in client heartbeats. When
  bit 0 of the 8-byte client timeshift field is 1, ghost mode is active.
- **Build action lengths**:
  - Single build: 9 bytes (int32 x + int32 y + uint8 dir)
  - Ghost build: 10 bytes (9 + 0x00 flag)
  - Drag build (subsequent): 11 bytes (9 + 0x01 0x01 marker)
  - Server echoes use 11B for drag builds.
- **Input Action Segments**: some actions (like write_to_console) have data
  stored in input action segments, not in the standard action data field.
  Parsed after the main action list.
- **Direction naming**: 16 directions (north=0, northnortheast=1, …,
  northnorthwest=15).
- **Action IDs are stable** — the `defines.input_action` dump is reliable;
  IDs don't change between sessions.

## Unknown Types (old protocol IDs not in current dump)

| Type | Observed | Suspected |
|------|----------|-----------|
| 84 | 12 bytes S→C | wire_dragging (protocol ID, dump says 86) — see below |
| 265 | 17+ bytes S→C | cursor hover/selection — see below |
| 9 | 16+ bytes S→C | cursor/selection action — see below |
| 128 | 20+ bytes S→C | copy operation |
| 266 | 10+ bytes C→S | flip entity? |
| 267 | 20+ bytes S→C | fast entity split? |
| 268 | 16+ bytes C→S | unknown |
| 60 | observed | cheat? |
| 21, 31, 151 | observed | unknown |

## Fixed Issues (verified in live sessions)

1. ✅ **deconstruct (type 131) data length** — Was 8 bytes (entity ID),
   corrected to **16 bytes** (two tile positions for area selection:
   `x1,y1,x2,y2`, 4 × int32). Previously the second position was
   misinterpreted as a separate phantom action with a fake player ID.
   Fixed: `131=>["deconstruct",16]`.
   - Before: `<- Player_164  quick_bar_pick_slot  row=254 slot=255 [feff]`
   - After:  `<- Moon-O-Cronic deconstruct area=(-352.387, 430.109)-(-349.043, 463.797)`

2. ✅ **server_tick_info (type 84)** — Server-to-client wrapper action with
   12 bytes (4B hash + 8B tick). Was `nil` in ACTIONS, causing `hit_unknown`
   cascading into phantom segment parsing. Fixed: `84=>["server_tick_info",12]`.

3. ✅ **Segment parsing guard** — When `hit_unknown` triggers during main
   action parsing, segment parsing is skipped (offset unreliable).

4. ✅ **Truncated data guard** — Added missing `else` branch for
   `alen > 0` with insufficient data; sets `hit_unknown=true`.

5. ✅ **open_gui (type 5) length** — Was 9 bytes, corrected to **14 bytes**.
   First 6 bytes are header `30 00 54 ff ff ff` (GUI type + entity ref).

6. ✅ **open_character_gui (type 61) length** — Was 2 bytes, corrected to
   **15 bytes**. First 2 bytes `01 54` are GUI type, then 13B metadata.

7. ✅ **open_blueprint_library_gui (type 64) length** — Was 2 bytes,
   corrected to **15 bytes**. Same structure as open_character_gui.

8. ✅ **change_active_item_group_for_filters (type 110) length** — Was 5
   bytes, corrected to **15 bytes**.

9. ✅ **Chat echo parsing** — server echoes chat via a type-84 wrapper
   followed by a segment write_to_console. Fixed by mapping type 84.

10. ✅ **Server echo metadata suppression** — server heartbeats append
    metadata entries after each echoed player action. Fixed by passing
    `is_server` through to `parse_tick_closure` and discarding all actions
    after the first (see "Echo metadata" below).

11. ✅ **`nothing` (type 0) filtered** — `return if act[:type] == 0` guard
    in the sniffer display for server padding actions.

12. ✅ **Chat message decoding (write_to_console)** — `decode_action_string`
    handles multiple prefix formats (see "Chat message formats" below).

## Remaining Known Issues

1. **Server heartbeat action metadata filtering** — server heartbeats append
   metadata entries (server_tick_info, nothing, paste_entity_settings,
   Unknown(128), …) after each echoed action, with player IDs that may
   coincide with real ones. The parser discards all actions after the first
   per tick closure, which eliminates phantom players but also truncates
   legitimate multi-action server echoes (if any exist).
2. **Server heartbeat action lengths** — many server-echoed actions have
   different data lengths than their client counterparts. Compare with the
   ACTIONS table per type when debugging new phantom actions.

## Server Heartbeat Action Structure

Server-to-client heartbeats use a different action encoding from
client-to-server. Each server heartbeat typically contains a
`server_tick_info` (type 84) action with 12 bytes. When echoing player
actions the server wraps them with additional metadata bytes.

Packet-level pattern:
- Packet size = `15 + action_section`, `action_section = 2 + data_len + ((count-1) * 2)`
- count_flagged byte at offset 14: `count = flagged >> 1`, `has_segments = flagged & 1`
- Each action: `[type_uint8][delta_uint8][data...]` (uint8, NOT uint16v like client)

### Echo metadata suppression (varies by session/game version)

- Session A: `[real_action][metadata...]` — first action is genuine.
- Session B: `[server_tick_info(84)][real_action][metadata...]` — wrapper
  first (delta=1 → player 0), then the real echoed action (delta encodes
  player relative to the wrapper), then metadata.
- Parser rule: keep the server_tick_info wrapper(s) (needed for player delta
  decoding; filtered at display) plus the FIRST non-84/non-0 action; drop
  trailing metadata. Metadata may also trigger hit_unknown on
  unknown-length types (128, 266, …), which stops further parsing.

## Chat Message Formats (`write_to_console`, type 106)

Prefix formats (first byte is a message-type marker):
- `[0x05][meta(1)][text...]` — segment format (outgoing). `meta` = TOTAL
  message length (may span segments). Text runs from offset 2 to end of
  payload (NOT `meta` bytes — truncating to meta cuts long messages).
  Split messages: first segment `[0x05][total_len][first_part]`, subsequent
  segments raw `[continuation]` (no prefix).
- `[0x0b][meta(1)][text...]` — same layout as 0x05 (observed live:
  `[0x0b][0x2c]` + 44-byte message). Was truncated to 11 bytes before.
- `[0x24][meta(1)][text...]` — same layout as 0x05 (observed: `[0x24][0x18]`).
- `[0x29][meta(1)][text...]` — same layout as 0x05 (observed: `[0x29][0x30]`).
- `[0x3d][meta(1)][text...]` — server echo with `=` marker.
- `[0x01][meta(1)][text...]` — server echo alternate format.
- `[0x04][text...]` — non-segment format.
- `[0x00][meta(1)][text...]` — server echo format (legacy).
- `[0x05][0x00]` (2 bytes) — zero-length message (server echo of empty chat
  submission). Decodes to nil; not a truncation case.

## Network Header Random Flag

The 0x20 bit in the network header byte is header metadata only (checksum
perturbation flag); the heartbeat payload always starts at byte 1. Parsing
from byte 5 (treating the flag as a 4-byte offset) silently dropped ALL tick
closures from ~half of all heartbeats (every `0x26`/`0x27`-prefixed packet).
Verified against factorio_dissector and 97,656 affected packets. Fragmented
messages (0x40 bit) are skipped.

## open_gui (type 5) — 14 bytes

`[gui_type(1)][flags(1)][entity_tag(1)][entity_hi(1)][entity_lo(2)][token(4)][tick_minus_1(4)]`

- GUI type 0x30 = entity container/chest. Byte 1 flags: 0 = open.
- **Bytes 2-5: stable entity reference** (constant per entity). Tag `0x54` =
  container; the 3 payload bytes (hi+lo) uniquely identify the entity.
- **Bytes 6-9: per-call token** (changes every invocation, NOT the entity ID).
- **Bytes 10-13: tick - 1** (uint32) — game tick when the action was performed.
- The actual entity ID is NOT in this action; the client sends an empty
  open_gui and the server fills the ref from the player's cursor context.

## cursor_hover (type 265) — 8 bytes

`[flags(1)][tick(4)][padding(3)]` — sent when hovering over an entity.

## cursor_click_select (type 9) — 8 bytes

`[tick(4)][padding(4)]` — sent when clicking an entity. Tick matches the
open_gui tick (client direction only; server echoes are wrapped differently).

## Server Echo Action Data Lengths (Verified)

| Type | Name | Client Len | Server Echo Len | Notes |
|------|------|-----------|----------------|-------|
| 5 | open_gui | 9 | **14** | 6B header + 8B meta |
| 61 | open_character_gui | 2 | **15** | 2B+13B |
| 64 | open_blueprint_library_gui | 2 | **15** | Same as 61 |
| 84 | server_tick_info | nil | **12** | Server-only action |
| 110 | change_active_item_group_for_filters | 5 | **15** | 5B+10B |
| 131 | deconstruct | 8 | **16** | x1,y1,x2,y2 (4 × int32) |

Server echo data lengths are consistently larger than client lengths due to
additional metadata bytes appended by the server.
