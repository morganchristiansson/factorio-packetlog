# Protocol Notes (reverse-engineering findings)

Session-verified findings about the Factorio multiplayer protocol. The
network-layer reference and compact payload table live in `docs/README.md`;
input actions are listed in `docs/actions.md`. This file holds the
*verified-by-capture* notes, fixes, and open questions.

## ACTIONS Table (`lib/factorio_protocol.rb`)

Built from the `defines.input_action` dump (`external/input_actions_dump.txt`).
IDs from the dump may DIFFER from protocol IDs in some sessions. The mapping
includes:
- Core actions (build=68, wire_dragging=86, etc.)
- Internal-only actions (nothing=0, stop_walking=1, stop_mining=3)
- Session-verified protocol IDs for some types (wire_dragging at 84 vs 86)

## Parsed Message Coverage

`FactorioProtocol.parse_udp_payload` fully decodes connection request (2),
connection confirm (4), connection accept (5), heartbeats (6/7), and game
information reply (17). Other types retain only their network header. The
README payload table is the single per-message reference; the sections
below contain the capture-verified details and regressions that are not
obvious from the table.

## Key Protocol Findings

- **Player IDs**: decoded as 1-indexed game player indexes (`game_player`
  field). Wire protocol is 0-indexed; the +1 translation happens in the
  parser, not in downstream code.
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
heartbeats (0x40 bit) are skipped (a fragment is not a full message).

## Fragmented msg-4 confirm carries the mod list (phantom joins)

A modded client's ConnectionRequestReplyConfirm carries its mod
list/settings blob (KBs, so every client runs the same deterministic
sim) and arrives as frags 0..N (~500B chunks, one message_id). Only
frag 0 holds the leading fields (username); frags 1+ are mid-blob
slices. Parsing them as whole messages decoded mod text (tech
prerequisites, research triggers, spawn weights) as phantom "usernames"
— one real "morganc connected" plus 4-5 phantom "X connected" lines in
the same millisecond, last-write-wins @ip_names, and the first heartbeat
bound a phantom as the game player (players-cache.json "1" = log-like text).
Fix: parse_udp_payload skips frag_number > 0 (header only); frag 0
parses as before. Proof: captures/server-34197-20260910-205559.pcap
pkts 34154-34159, saved as test/fixtures/frag_confirm_{0..5}.bin.

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
  `client_open_gui_8b{,_2,_3}`. See `docs/actions.md`.

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
See `docs/actions.md`.

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

## C→S action lengths are MEASURED, not derived (2026-09-25)

`ACTIONS_20`'s data lengths were inherited from the 2.1 table **by name**
("payload shapes are version-stable"). They are not: on a live 2.0 server a
wrong length desyncs the rest of the tick closure, every following action
decodes as garbage, and the packet lands in `captures/unknown.packets-*.pcap`.
In one such capture set (23k heartbeats) only **2.5%** of heartbeats parsed
to exactly the last byte, 86% hit an unknown action.

The lengths are measurable without the game log and without a running server:
**every C→S heartbeat ends with an 8-byte `[tick(4)][pad(4)]` block** (the
next-to-receive tick / closure trailer — its tick lands within a second of
the closure's own tick, verified on 23k packets), so a tick closure's action
bytes occupy a range whose END is known. In a closure holding a **single**
action, that action's payload is exactly the remaining budget: no other
length is assumed, so it is ground truth. `tools/measure_action_lens.rb`
does that and reports the result per wire ID (with the number of distinct
closures backing it); `C2S_LENS_20` is its `--emit` output and wins over the
table's guess for client→server. Effect on a 30 282-heartbeat capture set:
**2.6% → 84.7%** of heartbeats parse to exactly the last byte, 86% → **4.2%**
hit an unknown action. Replaying captures that consist *entirely* of flagged
packets (4 522 of them) through the sniffer now flags **none** of them.
Both 2.0-only parsers below are matched on the 2.0 wire ID as well as the
name — 2.1 has its own build_terrain (180) and its layout differs.

Careful with the override: it must only apply to IDs the map actually has
(`measured.key?(type)`). A plain `measured[type]` read returns nil for every
other ID, blanks the table's length and reports all 0-byte actions as
unknown — that bug alone accounted for 2 600 of the remaining flags.

### `0xFF` is both the escape marker and the literal type 255

`decode_uint16v` (here and in factorio_dissector) treats a leading `0xFF` as
"a u16 follows". But the wire also writes **type 255** — 2.0's
`set_combinator_description` — as a single `0xFF` byte, so the two are
ambiguous. A closure that ends with the two bytes `FF FF` is that action, not
a truncated escape; read as an escape it decodes to a type of 0xDBFF and the
rest of the closure is garbage. The tie-break is the defines dumps: the
largest real input-action ID in either version is 355, so an "escaped" value
above 400 is a misread. This one line removed 118 flagged packets on its own
and fixed every `render_mode_changed` closure that ended in it.

### The trailing closure bytes belong to the CLOSURE, not the action

Two related traps, both worth ~800 flagged packets together:

- A tick closure's last action is followed by bytes that are **not** its
  payload. `build_terrain`'s 3-byte zero tail is a closure terminator: taking
  it while another action follows eats that action's header (usually a
  `nothing`, `00 00`) and desyncs the rest. Only take it when the action *is*
  the last one — `parse_action` already receives that flag.
- The count byte can legitimately name one more action than the well-formed
  ones visible in the buffer: that last action is the `FF FF` case above.

### Content-defined actions: parse, don't table

Three actions have no fixed length, and for those a wrong constant silently
mis-parses the rest of the closure while a missing one stops cleanly. Two are
decoded and the third is measured as a majority:

- **build_terrain (2.0: 171)** — a LIST of 11-byte terrain records, each
  record after the first preceded by the 4-byte marker `00 00 AB 00`, then a
  2-byte `00 00` tail. Lengths 13/26/28 bytes observed. Walking the records
  lands exactly on the byte for 2 350 of the 2 934 closures that contain it;
  when the tail is absent the length stays unknown (clean stop). Biggest
  single win: 2 937 → 18 flagged packets.
- **translate_string (2.0: 240)** — `[u8 count]` then `count` localised
  strings: `[u8v key][01][00][u8v translation][9 bytes]`. The 9-byte tail is
  the argument block; it is 9 in 60 of 68 occurrences and longer when an
  entry carries a nested localised string as an argument (those 8 desync).
- **build (2.0: 66)** — 12 bytes (the by-name-inherited guess said 9). The
  rare drag-painting forms (30/35) stay mis-parsed rather than guessed.

Measured vs the inherited-by-name guess (2.0 IDs): close_gui 61 = 1 (table
said 2), move_on_pan 124 = 16 (17), selected_entity_changed 87 = 8 (nil),
gui_click 102 = 17 (nil), set_logistic_filter_item 99 = 23 (nil),
lua_shortcut 239 = 27 (nil), start_walking 67 = 16, use_item 119 = 1,
change_shooting_state 85 = 9, render_mode_changed 294 = 9, fast_entity_split
267 = 1, and six IDs the 2.0 table does not name at all (32, 33, 54, 64,
212, 331 — lengths 0, 0, 0, 2, 12, 2, enough to stop the stream desyncing;
names still unknown, to be identified with `/toggle-action-logging`).

Two things are deliberately NOT tabled:

- `custom_input` (184) and `translate_string` (240) are script/content
  defined (240 arrived with 66 distinct lengths across 68 closures — a
  localised-string list). A number in the table would be a lie; they need a
  real parser, and the tool reports them instead.
- Several types are content-dependent by exactly one byte (92: 8/9,
  99: 22/23, 87: 8/18, 14: 0/10, 102: 17/27). The majority value is
  tabled; the tool prints every value it saw.

**The closure action-count byte is fine** (`count = byte >> 1`, bit 0 =
"action segments follow"): the observed byte distribution is all even
(2: 16445, 4: 5396, 6: 883, 8: 179) and, for closures whose actions have
non-zero length, walking `cb>>1` actions lands exactly on the budget end
(`tools/measure_action_lens.rb` prints this per count byte). The trailing
`nothing` first-hits it looked like caused were a wrong length upstream in
the same closure, not a misread count.

**Types the tool deliberately will not measure.** The candidate search skips
any target whose table length is 0 — a 0 is a claim, and letting the search
near 0-length actions collects the 1-2 byte votes that shifted boundaries
produce (`nothing` "measured" 23 on 462 closures, which then poisons the
seed's own majority). That leaves a handful of types whose 0 guess is simply
wrong — 88 pipette, 127 upgrade, 128 copy, 144 set_ghost_cursor, 155
cancel_deconstruct, 254 — to be found one at a time, by enumerating candidate
lengths for that single type and keeping only those where the rest of the
closure parses exactly with at least one following action of non-zero length.
Those six are in `C2S_LENS_20` with their evidence; they are not derivable
from a corpus-wide statistic, and a per-type script is the honest tool for
them.

**The 7-byte entity reference.** Several 2.0 actions end their payload with
`00 00 | 01 80 00 00 | XX 00` — a u16 pad, a u32 **unit number** (`0x8001` is
the first player unit) and a u16 pad. It shows up identically in `127
upgrade` (23), `128 copy` (22) and `155 cancel_deconstruct` (23), each of which
is otherwise two 8-byte position records, and it is what `88 pipette` (10
bytes) carries: pipette is the cursor picking up a ghost item, so its payload
is the entity it picked up. Knowing the semantics is what settled it — the
per-closure candidate search gave 10 bytes on 69 closures against 1 for the
"measured" value, and `00 00 01 80 00 00 00 00` is exactly that unit number.

**build_terrain is fully decoded — verified, not assumed.** Splitting every
one of the 3 901 `build_terrain` payloads on the `00 00 00 AB 00` marker gives
7 694 gaps and **every one is exactly 10 bytes**, and `171` is never the last
action in a closure, so there is no tail at all: the payload is
`10 + 5×markers` (10, 25, 40 …). The parser reproduces that in 3 901 of 3 901
cases. The earlier 13/28/43-byte readings were the tool's own boundary
artifacts, not measurements.

**Test coverage for all of this.** Every fix above is pinned by a real
capture in `test/fixtures/packets.rb` (each description names the evidence its
length came from, so a future disagreement is about evidence, not a magic
number): `client_build_terrain_then_nothing_20` (the tail regression),
`client_pipette_ghost_item_20`, `client_entity_ref_upgrade_20`,
`client_entity_ref_copy_20`, `client_selected_entity_unit_number_20`. The
`0xFF` rule gets two focused unit tests instead, because the smallest real
packet containing it is a 272-byte chain of 30 actions: the literal-255 case
(with the deliberately-unasserted wrong player index explained in place) and
the counter-test that a real ID above 255 still uses its 3-byte escape.
**Version-table state leaks, fixed systematically.** `select_version` mutates
module state (`actions`, `segment_types`, and the measured `c2s_lens` map), so a
test that switches version re-runs every later test against those tables. Every
protocol-touching test file now calls `FactorioProtocol.reset_version` in
`setup` and `teardown`, and the whole suite runs green in ONE process — 301
runs, 1 988 assertions — which is the only way to be sure a file cannot poison
the next.

**A walk bug in the measuring tools themselves.** Both measurement passes read
every action's *header* without skipping payloads, so in a two-action closure the
second "type" came from inside the first action's data — `[88, 4]` instead of
`[88, 252]` — and the length arithmetic was meaningless while looking entirely
plausible. Two things came out of fixing it (`tools/action_len_solver.rb`):
`tools/measure_action_lens.rb --type` measures ONE type soundly (enumerate candidate
lengths, keep those where the rest of the closure parses to a known end, refuse
on a tie), and `tools/measure_action_lens.rb --check` re-derives every table
entry from the wire and fails on a disagreement. That check immediately caught
`144 set_ghost_cursor`: the table said 11, the wire says 7 on 36 closures against
11 for the runner-up — worth 35 of the remaining flagged packets. The old corpus
`--emit` is gone; a tool that cannot defend its numbers should not be able to
write the table.

`packet_fixtures_test.rb` additionally enforces the coverage:
`test_every_measured_length_is_pinned_or_acknowledged` fails if a
`C2S_LENS_20` entry has no fixture and no line in `UNPINNED_LENGTHS` (with a
reason), and fails if an entry is listed there but has since been pinned. So
the gap is a maintained list, not a silent one — 18 of 67 lengths are pinned by
a packet today, the rest are acknowledged, and regenerating the table from a
smaller capture cannot quietly drop a fix. `test_translate_string_layout_is_pinned`
covers the other content-defined parser.

**The tail WAS a coverage problem.** On the unknown-packet captures — which
contain only what the old decoder got wrong — 67 of 71 unmeasured types appeared
in one or two closures each, so nothing was decidable. On the full rolling
captures (121 MB, 2.0 M packets, 531 k heartbeats) the same single pass decides
**23 of them at once**, including the largest single remaining item:
`zoom_around_point` = **24 bytes on 50 393 closures** (the 2.1 table's value —
the 29/24/23 three-way split on the small sample was noise). Also
`264 fast_entity_transfer` (1, 9 484), `65 drop_item` (8, 6 643), `250
change_picking_state` (1, 948), `76 cursor_transfer` (16, 868), `126 deconstruct`
(23, 330), `125 start_repair` (8, 386). `C2S_LENS_20` is now 94 entries and
`--decide` reports nothing left that the wire settles.

Against the full captures: **91.4%** of heartbeats parse to exactly the last
byte and **0.7%** hit an unknown action (3 527 of 531 367). What is left is the
same flat tail — `236` (348), `210` (202), `248 instantly_create_space_platform`
(189), `233`, `209`, `239 lua_shortcut` (144) — a long list of rare or
content-defined actions, each needing its own decode.

Older notes, kept for the record: Each is one action's own variable
payload, and the culprit histogram (the action *before* the desync — see the
`0xFF` note above, the first hit is usually a tick byte read as a type) names
them: `88 pipette` (31), `128 copy` (21), `144 set_ghost_cursor` (15),
`nothing` (14), `66 build` (12, drag forms), `116 gui_location_changed` (11),
`127 upgrade` (11), `155 cancel_deconstruct` (9), `143 spawn_item` (6). Most
are GUI-style records with a variable tail, e.g. all 31 `pipette` cases are
`pipette` (1 byte) followed by an action whose payload runs
`00 00 00 00 00 01 01 00 XX 00 YY YY` — the same shape under five different
type IDs. The tool prints the inputs as `unmeasured types still seen`.

**`254 selected_entity_changed_based_on_unit_number` is a 0-byte action**
(the by-name-inherited length said 8). Its whole encoding is the two header
bytes `FE FF` before the closure trailer — the same "one more action than is
visible" shape as the `FF FF` case, which is what finally identified it.
`remote_view_surface` 245 (374 — no candidate length is supported by more
than 3 closures, so nothing honest to put in the table), `zoom_around_point`
123 (29/24/23 with no winner), and the same handful of content-dependent
actions as before (92: 8/9, 99: 22/23, 87: 8/18, 14: 0/10, 102: 17/27,
6: 0/9/11/27/55) where the table holds the majority and the tool prints
every value it saw.

**How a length may be measured** (all three rules are load-bearing; each one
was added after the version without it produced a wrong table):

1. **Budget**: a closure holding a single action measures it exactly. 32
   types, thousands of closures each — ground truth.
2. **Subtraction**: a closure with one unmeasured type splits its budget
   over it, once every other type is known. Needs the other types to be
   right, which is why it runs as iterations after (1).
3. **Candidate search**: for a type that is never alone and never last,
   enumerate lengths 0..40 per closure and keep the ones where the REST of
   the closure then parses exactly — with at least one following action of
   NON-ZERO length (a 0-length tail aligns any guess), and only counting a
   closure that admits exactly ONE candidate. Without that uniqueness rule
   129 unrelated types all "measured" 26 bytes (build_terrain's two-record
   length, charged to whatever followed it).

A length that did not come from (1) ships only with ≥5 agreeing closures AND
a ≥3× margin over the runner-up; a tie is two shapes sharing an ID, and
picking one mis-parses the other (`12 reset_assembling_machine` ties 3 vs 28
and stays unmeasured). Anything above ID 400 is a desync artifact, not an
action (the largest real ID in either dump is 355) and is discarded. The
result is printed either way, so a future capture can settle it.

**Three attempts to squeeze the tail further, all rejected by measurement.**
The capture set itself is the independent check — a wrong length desyncs the
closure and the flagged-packet count says so — and each of these made it
worse, so none shipped:

- A **two-unknown solve** (enumerate the first length, derive the second):
  4.2% → 7.5% unknown. With zero-length actions around, a shifted boundary
  satisfies both ends of the pair.
- Letting the search treat **table-based lengths as "known"** (the parser
  decoded them without error, so they looked corroborated): 4.0% → 5.2%.
  The parse just echoes the table, and the table is what is under suspicion.
- The same idea restricted to the **content-defined** actions, judged per
  closure: 4.0% → 5.8% for the same reason — when a 171 parse is wrong, the
  action behind it is garbage and the search measures the garbage. Under a
  genuinely sound condition (closure fully decoded AND ending exactly on the
  byte area) the idea yields nothing extra, which is the honest answer.

So the tail needs per-type layout work, not a cleverer search. The tool now
prints the work list: `evidence but ambiguous` (ties or too few closures) and
`unmeasured types still seen` (no anchorable closure at all) — the top entries
are `254 selected_entity_changed_based_on_unit_number` (always the last
action, always 0 bytes, but its closures all contain a `171` whose length is
content-defined), then a spread of IDs the 2.0 table does not name
(122, 147, 229, 210, 82, …) whose NAMES still need
`tools/validate_actions.rb --capture 60 --toggle`.
