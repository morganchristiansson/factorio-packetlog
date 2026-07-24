# quick_bar_set_slot (Type 244)

Assign an item to a quickbar slot by clicking the slot with an item on your cursor.
Middle-click to clear a slot.

## Data Length

9 bytes

## Wire Format

```
Action Type:  uint16v = 244 (quick_bar_set_slot)
Player Delta: uint16v = delta to previous player index
Data:         9 bytes
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 1 | uint8 | Row (0-9) |
| 1 | 1 | uint8 | Slot (0-9) |
| 2 | 1 | uint8 | Action (0=set, 1=clear) |
| 3 | 2 | bytes | Sentinel (0xFFFF) |
| 5 | 3 | uint24 LE | Cursor transaction ID (monotonic sequence per cursor operation) |
| 8 | 1 | uint8 | Flag (always 0x01) |

## Notes

- The stack ID identifies the item stack on your cursor. For items pipetted from
  world entities, this is the entity's unit_number. For inventory/quickbar items,
  it's an inventory stack ID. Both share the same ID space.
- The item type and quality are determined by the server from the stack ID.
- `clear_cursor` (type 10) is used to empty the cursor after setting.

## Related Actions

| Type | Name | Data | Description |
|------|------|------|-------------|
| 10 | clear_cursor | 0 | Empty the cursor |
| 27 | cycle_quality_up | 0 | Cycle cursor item quality |
| 90 | pipette | 9 | Pick up item to cursor |
| 244 | quick_bar_set_slot | 9 | Set/clear quickbar slot |
| 245 | quick_bar_pick_slot | 2 | Pick up item from quickbar |

## Player Index

1-indexed game player
