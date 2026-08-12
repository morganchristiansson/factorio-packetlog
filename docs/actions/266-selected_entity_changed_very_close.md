# Hover/selection actions + camera actions (types 9, 60, 128, 129, 262, 266-268, 310)

Identified by correlating `/toggle-action-logging` output with the packet
capture **by tick** — the log tick equals the packet's heartbeat tick, and
the action data carries `hb_tick - 3`:

```
8465.967 [495897 0 SelectedEntityCleared]           ↔ type 9  (hb 495897)
8468.884 [496072 0 SelectedEntityChangedVeryClose]  ↔ type 266 (hb 496072)
8474.134 [496387 0 SelectedEntityChangedRelative]   ↔ type 268 (hb 496387)
8584.317 [502998 0 RotateEntity]                    ↔ type 280
8665.334 [507859 0 FlipEntity]                      ↔ type 281
```

## Confirmed names

| Type | Name | Payload (C→S) | Status |
|------|------|----------------|--------|
| 9 | selected_entity_cleared | 0 (`[tick][pad]`) | log-confirmed |
| 60 | close_gui | 2 (`00 01` = [gui_type][flags]) | log-confirmed |
| 128 | zoom_around_point | 24 (3 doubles) | log-confirmed |
| 129 | move_on_pan | 17 (pos int32×2 in 1/256 tiles + int + float + byte) | log-confirmed |
| 262 | close_remote_view | 2 | from .pdb alignment, unconfirmed |
| 266 | selected_entity_changed_very_close | 1 | log-confirmed |
| 267 | selected_entity_changed_very_close_precise | 2 | log-confirmed |
| 268 | selected_entity_changed_relative | 4 | log-confirmed |
| 310 | render_mode_changed | 1 (mode) | log-confirmed |

NOT in this game version: `selected_entity_changed_based_on_unit_number` (was
in older builds, removed). Type 265 is `change_picking_state` (live defines).

## Data Length (direction-dependent, verified from `factorio.pcap`)

```
C→S: [payload][tick(4)][pad(4)]                        = payload + 8
S→C: [payload][entity_ref(4)][token(4)][tick-1(4)][pad(4)] = payload + 16
```

The server resolves the hovered entity (ref tag `0x54`, same as open_gui
echoes). C→S tick = local action tick (hb tick - 3).

## Table alignment (important!)

`defines.input_action` (queried live via RCON on 2.1.14) is the authoritative
name source. The local `external/input_actions_dump.txt` and the Hornwitser
dissector table predate `super_forced_select_area` being inserted at type 209,
which shifted everything ≥209 by one in earlier versions of this codebase.
The full table was rebuilt against the live enum (2026-08-12). Earlier
confusion examples: type 279 was misnamed rotate_entity (it's
fast_entity_transfer), 262 was misnamed instantly_create_space_platform
(that's 263; 262 is close_remote_view).

## Fixtures

- `spec/fixtures/selected_entity_cleared.bin` (client packet)
- `spec/fixtures/selected_entity_changed_very_close.bin` (type 265 — now
  known to be change_picking_state; renamed `265-change_picking_state.bin`)
