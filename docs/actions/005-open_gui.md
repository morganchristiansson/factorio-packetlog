# open_gui (Type 5)

Open the GUI of the currently selected entity (assembling machine, furnace, etc.).

## Data Length

6 bytes

## Wire Format

```
Action Type:  uint16v = 5 (open_gui)
Player Delta: uint16v = delta to previous player index
Data:         6 bytes (constant header + tick sequence + flag)
```

## Notes

- The GUI type is NOT in this action — it's determined by the entity under
  the cursor (tracked via `selected_entity_changed` events).
- The first 2 bytes are always `30 00` (constant identifier).
- A `nothing` (type 0) action often follows as tick closure padding.

## Player Index

1-indexed game player
