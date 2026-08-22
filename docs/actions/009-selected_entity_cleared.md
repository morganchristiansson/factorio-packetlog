# selected_entity_cleared (Type 9)

Cursor leaves an entity — the hover/selection "cleared" action.

## Status

**Real name** — confirmed by correlating `/toggle-action-logging` output with
the packet capture by tick (the log tick equals the packet's heartbeat tick):

```
7094.304 Info InputActionHandler.cpp:672: Action performed [414178 0 SelectedEntityCleared]
     ↔  C→S packet hb tick 414178, type 9
```

Previously named `cursor_click_select` (working name) — not a click; fires on
hover/selection changes. Type 9 is not in `defines.input_action` (gap between
`disconnect_rolling_stock = 8` and `clear_cursor = 10`, verified live via RCON).

## Data Length

8 bytes both directions:

```
C→S: [tick(4)][pad(4)]           — tick = local action tick (hb tick - 3)
S→C: [entity_ref(4)][token(4)]   — last-hovered entity, server-resolved
```

## Related

The hover family (types 265-268) and `zoom_around_point` (128) /
`render_mode_changed` (310) were identified with the same technique — see
`docs/actions/265-selected_entity_changed_very_close.md`.

## Fixtures

- `test/fixtures/selected_entity_cleared.bin` (client packet)
- `test/fixtures/packets.rb`: `client_selected_entity_cleared`
