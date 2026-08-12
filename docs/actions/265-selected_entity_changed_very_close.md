# SelectedEntityChanged family (types 265-268) + related hover actions

Hover/selection actions — fire when the cursor is over an entity on the map.
Identified by correlating `/toggle-action-logging` output with the packet
capture **by tick** (the log tick equals the packet's heartbeat tick):

```
7094.221 [414173 SelectedEntityChangedVeryClosePrecise]  ↔ type 267
7094.304 [414178 SelectedEntityCleared]                  ↔ type 9
7093.951 [414157 SelectedEntityChangedRelative]          ↔ type 268
```

## Status

**Real names** from the game's internal symbols (InputActionHandler.cpp,
`/toggle-action-logging`), cross-checked against the packet stream. Not
present in `defines.input_action`.

| Type | Name | Payload len (C→S) | Confidence |
|------|------|-------------------|------------|
| 9 | selected_entity_cleared | 0 | confirmed by tick correlation |
| 265 | selected_entity_changed_very_close | 1 | from .pdb order (never fired in captures) |
| 266 | selected_entity_changed_based_on_unit_number | 1 | best guess by elimination |
| 267 | selected_entity_changed_very_close_precise | 2 | confirmed by tick correlation |
| 268 | selected_entity_changed_relative | 4 | confirmed by tick correlation |

Earlier confusion: the Hornwitser dissector's table (old version) lists these
shifted by one (267 = Relative there), which initially misnamed 267/268.

## Data Length (direction-dependent, verified from `factorio.pcap`)

```
C→S: [payload][tick(4)][pad(4)]                        = payload + 8
S→C: [payload][entity_ref(4)][token(4)][tick-1(4)][pad(4)] = payload + 16
```

The server resolves the hovered entity (ref tag `0x54`, same as open_gui
echoes). C→S tick = local action tick (hb tick - 3).

## Identified with the same technique

| Type | Name | Payload |
|------|------|---------|
| 128 | zoom_around_point | 3 doubles (24B) — position + zoom, field order unverified |
| 129 | move_on_pan | 17B: pos int32×2 (1/256 tiles) + int + float + byte, semantics unverified (1 sample) |
| 310 | render_mode_changed | 1 byte mode |

All follow the same `[payload][tick][pad]` / `[payload][ref][token][tick-1][pad]`
shapes.

## Fixtures

- `spec/fixtures/selected_entity_changed_very_close.bin` (client packet)
- `spec/fixtures/selected_entity_cleared.bin` (client packet)
