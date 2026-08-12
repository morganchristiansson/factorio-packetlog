# SelectedEntityChanged family (types 265-268)

Hover/selection actions — fire when the cursor is over an entity on the map.

## Status

**Real names** — from the game's internal symbols (InputActionHandler.cpp),
confirmed live via the client command `/toggle-action-logging`:

```
6345.867 Info InputActionHandler.cpp:672: Action performed [369846 0 SelectedEntityChangedVeryClose]
6356.234 Info InputActionHandler.cpp:672: Action performed [370468 0 SelectedEntityChangedRelative]
6356.167 Info InputActionHandler.cpp:672: Action performed [370464 0 SelectedEntityCleared]
```

Not present in `defines.input_action` (the API enum is incomplete for internal
actions). Matches the Hornwitser dissector table (built from factorio.pdb).

| Type | Name | Payload len (C→S) |
|------|------|-------------------|
| 265 | selected_entity_changed_very_close | 1 |
| 266 | selected_entity_changed_very_close_precise | 1 |
| 267 | selected_entity_changed_relative | 2 |
| 268 | selected_entity_changed_based_on_unit_number | 4 |

## Data Length (direction-dependent, verified from `factorio.pcap`)

```
C→S: [payload][tick(4)][pad(4)]                       = payload + 8
S→C: [payload][entity_ref(4)][token(4)][tick-1(4)][pad(4)] = payload + 16
```

The server resolves the hovered entity (ref tag `0x54`, same as open_gui
echoes). C→S tick = local action tick (hb tick - 3).

The dissector's lens (1/2/4/8) are from an older version; verified payloads
are 1/1/2/4.

## Related

Type 9 (`cursor_select`) is likely the base variant of this family
(SelectedEntityChanged) or SelectedEntityCleared — see
`docs/actions/009-cursor_select.md`. Pinning it down: run the sniffer live
with `/toggle-action-logging` on the client, hover, and match the log tick
with the tick field in the captured action data.

## Fixtures

- `spec/fixtures/selected_entity_changed_very_close.bin` (client packet)
