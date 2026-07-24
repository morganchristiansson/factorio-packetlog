# quick_bar_pick_slot (Type 245)

Pick up an item from a quickbar slot using a keyboard shortcut (e.g., Ctrl+number).

## Data Length

2 bytes

## Wire Format

```
Action Type:  uint16v = 245 (quick_bar_pick_slot)
Player Delta: uint16v = delta to previous player index
Data:         2 bytes
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 1 | uint8 | Row (0-9: which quickbar row) |
| 1 | 1 | uint8 | Slot within row (0-9) |

## Notes

- The action only sends the position in the quickbar grid, not the item ID.
  The server knows what item is in each slot from the player's quickbar configuration
  (set via `quick_bar_set_slot` actions).
- Total quickbar capacity: 10 rows × 10 slots = 100 slots.

## Related Actions

| Type | Name | Data Len | Description |
|------|------|----------|-------------|
| 244 | quick_bar_set_slot | ? | Assign item to quickbar slot |
| 246 | quick_bar_set_selected_page | 0 | Switch visible quickbar page |

## Player Index

1-indexed game player
