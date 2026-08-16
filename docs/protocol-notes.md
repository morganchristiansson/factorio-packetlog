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
| 9 | 16+ bytes S→C | cursor/selection action — see below |
| 265 | 17+ bytes S→C | cursor hover/selection — see below |
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

5b. ✅ **open_gui (type 5) client length** — Client (C→S) open_gui is **8
   bytes** `[gui_type][flags][tick][pad]`, not 2. Was misparsed as 2 bytes,
   leaving the payload tail to be read as phantom actions with bogus player
   deltas (single-player game logged `add_decider_combinator_condition`
   Player_36 and `select_next_valid_gun` Player_59). Fixed: direction-aware
   length (client 8, server 14-if-fits-else-2). Fixtures
   `client_open_gui_8b{,_2,_3}`. (2026-08-12)

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
13. ✅ **C→S closure trailer is per-closure, not per-action** — the 8-byte
    `[tick][pad]` trailer belongs to the LAST action of a C→S closure.
    Adding +8 to every hover/zoom/pan action (or treating
    selected_entity_cleared as 8 bytes) with 2+ actions swallowed the next
    action's header and re-parsed payload bytes as phantoms
    (`Player_192 swap_tile_slots` from a zoom×2 closure,
    `Player_64 drag_train_wait_condition` from a 266+start_walking closure).
    See "Client action tick trailer" below.
14. ✅ **C→S drag build carries both positions (21B data)** — the headerless
    drag position rides inside the build action; reading 11B left it to be
    re-parsed as a phantom (`Player_252 zoom_around_point`).
15. ✅ **open_character_gui / open_blueprint_library_gui (61/64) C→S = 1B** —
    the 15-byte form is the S→C echo only; 15B C→S swallowed the following
    hover stream (`Player_267 gui_inventory_bar_changed` phantom).

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
3. **S→C echo segments** — server echoes of tooltip-carrying closures
   (hover over entities with descriptions) append segment sections whose
   payload bytes can be re-parsed as garbage actions after the S→C
   first-action filter (phantom set_cheat_mode_quality/gui_confirmed/etc.
   from tooltip text bytes). Not visible in server mode (C→S only).
4. **Unknown C→S actions** — a few exotic packets still derail: a drag-build
   with a `00 00` marker variant (paste_entity_settings phantom), a
   `[technology=…]` tooltip packet (Unknown(50)), and a rare hover-stream
   containing an unidentified action. ~74 actions in a multi-hour capture;
   each needs its own capture to pin down.

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

## Input-Action IDs Are Version-Dependent (2.0 vs 2.1)

The wire numbering of input actions is **version-dependent** — 2.0 and
2.1 use different `defines.input_action` values, and the internal wire
actions (not exposed in defines) differ too. Confirmed on a live 2.0.77
server with tools/validate_actions.rb (correlating
`/toggle-action-logging` output with packet captures by tick):

| action | 2.0 wire | 2.1 wire |
|--------|----------|----------|
| start_walking | 67 | 69 |
| build | 66 | 68 |
| drop_item | 65 | 67 |
| take_equipment | 118 | 123 |
| write_to_console | 104 | 106 |
| zoom_around_point | 123 | 128 |
| selected_entity_changed_very_close | 251 | 266 |
| selected_entity_cleared | 10 | 9 |
| render_mode_changed | 294 | 310 |
| change_multiplayer_config | 237 | 251 |
| clear_cursor | 11 | 10 |

Note this contradicts an earlier claim here that main actions were
version-stable — that conclusion came from misreading a stale capture;
the tick-correlated validation proves the IDs differ.

Selection: `FactorioProtocol.select_version` switches BOTH the main
`actions` table (ACTIONS for 2.1, ACTIONS_20 for 2.0) and `segment_types`.
ACTIONS_20 = the 2.0 `defines.input_action` dump + internal wire actions
verified by validation (nothing, stop_walking, zoom_around_point, the
selected_entity_changed family, close_gui, …; see lib/input_actions_20.rb,
regenerated by tools/dump_input_actions.rb). The sniffer auto-detects via
RCON `helpers.game_version` in server mode (`--protocol-version 2.0`
overrides, e.g. for pcap analysis).

### Validating IDs (tools/validate_actions.rb)

`/toggle-action-logging` makes the server log every action as
`Action performed [<tick> <player> <Name>]` (names only, no IDs).
Correlating those names with the packet capture's wire IDs by
(tick, player, position) yields a definitive ID→name map:

    sudo ruby tools/validate_actions.rb --capture 60 --toggle --table 20 --suggest

Flags OK (table matches), MISMATCH (different name for the ID), and
NOT IN TABLE entries.

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

## open_gui (type 5) — server echo 14 bytes / client 8 bytes

Server echo format:

`[gui_type(1)][flags(1)][entity_tag(1)][entity_hi(1)][entity_lo(2)][token(4)][tick_minus_1(4)]`

- GUI type 0x30 = entity container/chest. Byte 1 flags: 0 = open.
- **Bytes 2-5: stable entity reference** (constant per entity). Tag `0x54` =
  container; the 3 payload bytes (hi+lo) uniquely identify the entity.
- **Bytes 6-9: per-call token** (changes every invocation, NOT the entity ID).
- **Bytes 10-13: tick - 1** (uint32) — game tick when the action was performed.
- The actual entity ID is NOT in this action; the client sends a bare
  open_gui and the server fills the ref from the player's cursor context.

Client (C→S) format — 8 bytes:

`[gui_type(1)][flags(1)][tick(4)][pad(2)]` — tick is the local game tick when
  the click happened (hb tick - 3 in captures). **Regression (2026-08-12):**
  the parser read 2 bytes here, so the remaining 6 bytes of payload were
  misparsed as phantom actions with bogus player deltas (single-player game
  logged `add_decider_combinator_condition` Player_36 and
  `select_next_valid_gun` Player_59). Locked in by fixtures
  `client_open_gui_8b{,_2,_3}`. See `docs/actions/005-open_gui.md`.

## selected_entity_changed family (types 266-268) + selected_entity_cleared (9)

Hover/selection actions, **real names** — verified by correlating
`/toggle-action-logging` output with the capture by tick (log tick == packet
heartbeat tick):

| Type | Name | C→S payload |
|------|------|-------------|
| 9 | selected_entity_cleared | 0 (`[tick][pad]`) |
| 266 | selected_entity_changed_very_close | 1 |
| 267 | selected_entity_changed_very_close_precise | 2 |
| 268 | selected_entity_changed_relative | 4 |

**2.0 ONLY — type 254 `selected_entity_changed_based_on_unit_number`**
(verified live on 2.0.77, 2026-08-16): 8-byte C→S payload =
`[unit_number(4)][pad(4)]` + the usual C→S `[tick(4)][pad(4)]` trailer
(total 16). Carries the hovered entity's unit number — the cursor-state
signal that makes hand-mining locatable (see docs/grief-analysis.md:
64 hover→begin_mining pairs prove the hovered entity is the mining
target; resolve with RCON `game.get_entity_by_unit_number`). The 1-byte
`very_close` payload varies when the hovered entity changes (e.g. 0x85→
0x86 at a mining start) but is not an entity/item prototype id; the
4-byte `relative` payload is a cursor offset `[dx(2)][dy(2)]` i16 LE in
1/256 tiles from the player's character (verified against drag-build
lines: cursor −9,0 while placing a line 9 tiles west of the player's
path). REMOVED in 2.1 (the 2.1 ACTIONS table has no entry for 254).

C→S: `[payload][tick(4)][pad(4)]`; S→C: `[payload][ref(4)][token(4)][tick-1(4)][pad(4)]`.
The log tick equals the packet hb tick, and the data tick field = hb tick - 3.
`selected_entity_changed_based_on_unit_number` does not exist in 2.1.14
(removed); type 265 is `change_picking_state` (live defines).
`close_remote_view` (262) and `close_gui` (60) use the same wire shape.
See `docs/actions/266-selected_entity_changed_very_close.md`.

## zoom_around_point (128), move_on_pan (129), render_mode_changed (310)

Identified with the same tick-correlation: 128 = zoom_around_point (3 doubles
= position + zoom, field order unverified), 129 = move_on_pan (17B payload:
pos int32×2 in 1/256 tiles + int + float + byte, semantics unverified), 310 =
render_mode_changed (1-byte mode). Same `[payload][tick][pad]` C→S /
`[payload][ref][token][tick-1][pad]` S→C shapes.

**2026-08-16: zoom_around_point's doubles do NOT match player/camera
positions** (e.g. (−1, −47, −69) and (−1, −137, 90) while the player was
working around (558, 83); first double flips ±1.0). Possibly
[double][float][float] or a different space — field order/semantics remain
unverified; do not use as a position source until decoded.

## drop_item (2.0: 65 / 2.1: 67)

The 8-byte payload is a DIRECTION double (1.0, −1.0, ±√2/2, −0.0 observed
on the 2026-08-16 capture), not an x,y position. The old "drop_item =
player position" note (grief-analysis) was wrong; drop_item must be
excluded from position-bearing action lists.

## ACTIONS table alignment (2026-08-12)

The full ACTIONS table was rebuilt against the **live** `defines.input_action`
(via RCON, 2.1.14). The previous table and the Hornwitser dissector predate
`super_forced_select_area` being inserted at type 209 — everything ≥209 was
shifted by one (e.g. 279 was misnamed rotate_entity, 262 was misnamed
instantly_create_space_platform; those are fast_entity_transfer and
close_remote_view, and 263 = instantly_create_space_platform).

## Client action tick trailer (C→S heartbeats)

Client input actions are followed by an 8-byte trailer `[tick(4)][pad(4)]`
— the local game tick when the action occurred (hb tick - 3 in captures;
-8 for selected_entity_cleared). The server does NOT echo it (server echoes end
right after the action data). For actions with own data (start_walking,
pipette, …) the trailer appears after the data; for 0-byte actions
(stop_walking, stop_drag_build) it is currently left as unparsed trailing
bytes (harmless — those bytes are never misread as actions). open_gui is
special: its payload swallows the trailer (8-byte client form, see above).

**2026-08-12 correction — the trailer belongs to the CLOSURE, not per action.**
A C→S tick closure carries ONE `[tick][pad]` trailer, after the LAST action
(or after the segments when present). Multi-action closures make this
obvious: `[zoom][zoom][trailer]` — each zoom's data is its 24-byte payload
only; the first zoom must NOT consume a trailer, or it eats the second
zoom's header (`80 00`) and the tail of its payload (`f0 bf` = last two
bytes of the -1.0 double) is re-parsed as a phantom `swap_tile_slots` action
with a garbage delta → `Player_192`. Same for `[266][start_walking][trailer]`
(phantom `drag_train_wait_condition` `Player_64` from the middle of the
walk-direction double) and `[cleared][start_walking][trailer]`. Fix: only the
last action may consume the trailer (+8 for the hover/zoom family, 8 bytes
for selected_entity_cleared); intermediate actions use the raw payload
length. Locked in by fixtures `client_zoom_around_point_x2{,_alt}`,
`client_selected_changed_plus_start_walking`,
`client_selected_cleared_plus_start_walking`,
`client_selected_changed_stream`.

## C→S drag build (2026-08-12)

A drag-build closure's build action carries BOTH positions in its data:
`[x(4)][y(4)][dir(1)][01 01 marker][x2(4)][y2(4)][dir2(1)][flag(1)]` = 21
bytes. The second position is headerless and NOT counted in `count`. S→C
echoes instead send it as a separate counted action (11B build + 10B
position). Reading only 11B for C→S left the position to be re-parsed as a
phantom action — the position's x-byte `0x80` reads as type 128
(zoom_around_point) with the next byte as delta → `Player_252`. Locked in by
fixture `client_drag_build_with_position`.

## open_character_gui / open_blueprint_library_gui (61/64) — direction split

C→S carries only the 1-byte GUI type; the S→C echo appends 14 bytes of
metadata (15 total). Reading 15B for C→S swallowed following hover actions
(`Player_267 gui_inventory_bar_changed` phantom). Locked in by fixture
`client_open_character_gui_then_hover_stream`.

## Server Echo Action Data Lengths (Verified)

| Type | Name | Client Len | Server Echo Len | Notes |
|------|------|-----------|----------------|-------|
| 5 | open_gui | 8 | **14** (or 2 bare) | client: gui_type+flags+tick+pad |
| 61 | open_character_gui | 2 | **15** | 2B+13B |
| 64 | open_blueprint_library_gui | 2 | **15** | Same as 61 |
| 84 | server_tick_info | nil | **12** | Server-only action |
| 110 | change_active_item_group_for_filters | 5 | **15** | 5B+10B |
| 131 | deconstruct | 8 | **16** | x1,y1,x2,y2 (4 × int32) |

Server echo data lengths are consistently larger than client lengths due to
additional metadata bytes appended by the server.
