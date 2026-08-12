# rotate_entity (Type 279)

Rotate the selected entity (R key).

## Data Length

1 byte — the new direction (0-15).

## Wire Format

```
Action Type:  uint16v = 279
Player Delta: uint16v = delta to previous player index
Data:         direction (1 byte, 0-15)
```

## Observed

Server echo (Player_37, direction 1):

```
07 06 c8bdb200 a472b20000000000 | 04 | 54 01 [12B tick_info]
  | ff 17 01 | 24 | 01
      │       │    └ data = direction 1
      │       └ delta 0x24 = 36 (Player_37)
      └ type 279 (uint16v escape: ff + 0117)
```

## Player Index

1-indexed game player.

## Fixtures

- `spec/fixtures/packets.rb`: `server_rotate_entity_echo`
