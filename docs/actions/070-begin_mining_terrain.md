# begin_mining_terrain (Type 70)

Mine a tile of terrain (resources, concrete, etc.).

## Data Length

8 bytes

## Wire Format

```
Action Type:  uint16v = 70 (begin_mining_terrain)
Player Delta: uint16v = delta to previous player index
Data:         8 bytes = 2 x int32 LE (fixed-point 24.8)
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 4 | int32 LE | Tile X position (fixed-point 24.8: value/256) |
| 4 | 4 | int32 LE | Tile Y position (fixed-point 24.8: value/256) |

The coordinates are fixed-point with 8 fractional bits:
- Actual position = `raw_value / 256.0` (in tile units)
- Common value 128/256 = 0.5 (tile center)

## Examples

| Hex | Raw X | Raw Y | Position |
|-----|-------|-------|----------|
| `8069ffff80dbffff` | -38528 | -9344 | (-150.500, -36.500) |
| `806affff80dbffff` | -38400 | -9344 | (-150.000, -36.500) |

## Related Actions

| Type | Name | Data Len | Description |
|------|------|----------|-------------|
| 3 | stop_mining | 0 | Stop mining (no data) |

## Player Index

1-indexed game player
