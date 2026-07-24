# drop_item (Type 67)

Drop an item from the cursor onto the ground at a specific position.

## Data Length

8 bytes

## Wire Format

```
Action Type:  uint16v = 67 (drop_item)
Player Delta: uint16v = delta to previous player index
Data:         8 bytes = 2 x int32 LE (fixed-point 24.8)
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 4 | int32 LE | X position (fixed-point 24.8: value/256) |
| 4 | 4 | int32 LE | Y position (fixed-point 24.8: value/256) |

## Notes

- Uses the same position format as `begin_mining_terrain`
- Positions are NOT snapped to the tile grid (free placement)
- The item type and count are determined by the cursor state

## Player Index

1-indexed game player
