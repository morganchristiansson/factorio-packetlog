# stop_walking (Type 1)

Sent when the player stops moving (releases the movement key).

## Data Length

0 bytes

## Wire Format

```
Action Type:  uint16v = 1 (stop_walking)
Player Delta: uint16v = delta to previous player index
Data:         none
```

## Notes

No additional data needed — the server already knows your position from the
last `start_walking` direction and simulates movement each tick. This action
just signals that movement stopped.

## Related Actions

| Type | Name | Data Len | Description |
|------|------|----------|-------------|
| 69 | start_walking | 16 | Start moving with direction vector |

## Player Index

1-indexed game player
