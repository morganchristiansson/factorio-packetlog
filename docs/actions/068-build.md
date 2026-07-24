# build (Type 68)

Place an entity at a specific position and direction.

## Data Length

9 bytes

## Wire Format

```
Action Type:  uint16v = 68 (build)
Player Delta: uint16v = delta to previous player index
Data:         9 bytes = int32 LE + int32 LE + uint8
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 4 | int32 LE | Tile X position (fixed-point 24.8: value/256) |
| 4 | 4 | int32 LE | Tile Y position (fixed-point 24.8: value/256) |
| 8 | 1 | uint8 | Direction (0-3 or 0-7, see Direction enum) |

## Notes

- Uses the same fixed-point 24.8 coordinate format as `begin_mining_terrain`
- The direction byte encodes the rotation of the placed entity
- The entity type to build is determined by the item currently on the cursor

## Related Actions

| Type | Name | Data Len | Description |
|------|------|----------|-------------|
| 70 | begin_mining_terrain | 8 | Mining (position only, no direction) |

## Player Index

1-indexed game player
