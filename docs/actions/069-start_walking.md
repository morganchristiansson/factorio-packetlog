# start_walking (Type 69)

Fires when the player starts moving in a direction. Contains the movement direction as a unit vector.

## Data Length

16 bytes

## Wire Format

```
Action Type:  uint16v = 69 (start_walking)
Player Delta: uint16v = delta to previous player index
Data:         16 bytes = 2 x IEEE 754 float64 LE
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 8 | float64 LE | Direction X (-1.0 to 1.0) |
| 8 | 8 | float64 LE | Direction Y (-1.0 to 1.0) |

The (X, Y) pair forms a unit vector:

| Direction | (X, Y) |
|-----------|--------|
| Right | (1.0, 0.0) |
| Up-Right | (0.7, 0.7) |
| Up | (0.0, 1.0) |
| Up-Left | (-0.7, 0.7) |
| Left | (-1.0, 0.0) |
| Down-Left | (-0.7, -0.7) |
| Down | (0.0, -1.0) |
| Down-Right | (0.7, -0.7) |

## Related Actions

| Type | Name | Data | Description |
|------|------|------|-------------|
| 1 | stop_walking | 0 bytes | Stop movement |

## Player Index

1-indexed game player: `game_player = ((last_player + delta) & 0xFFFF) + 1`

## Used In

- [ClientToServerHeartbeat](../packets/06-client-to-server-heartbeat.md)
