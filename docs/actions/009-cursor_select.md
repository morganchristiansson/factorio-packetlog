# cursor_select (Type 9)

Cursor selects/hovers an entity on the map.

## Status

Working name — reverse-engineered from live captures. **Not present in
`defines.input_action`** (the current game enum has a gap at type 9:
`disconnect_rolling_stock = 8`, then `clear_cursor = 10`). The Hornwitser
dissector's table is from an older game version and is shifted for the low
types (it maps 9 = DisconnectRollingStock), so it does not apply.

## Behavior (verified in `factorio.pcap`)

Fires when the cursor moves onto an entity — **hover/selection, not a click**.
Observed sequence: `start_walking` → `stop_walking` → `cursor_select`, with no
`open_gui` (a click would open the GUI). The server resolves the hovered
entity and echoes `[entity_ref(4)][token(4)]`.

## Data Length

8 bytes both directions (C→S and S→C):

```
C→S: [tick(4)][pad(4)]           — tick = local game tick (hb tick - 3)
S→C: [entity_ref(4)][token(4)]   — server-resolved hovered entity
```

## Fixtures

- `spec/fixtures/cursor_select.bin` (client packet)
- `spec/fixtures/packets.rb`: `client_cursor_select`
