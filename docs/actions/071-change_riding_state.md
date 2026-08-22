# change_riding_state (Type 71)

Enter or leave a vehicle (train, car, etc.).

## Data Length

2 bytes — [entering(1)][vehicle_id_hi(1)] or similar state pair.

## Wire Format

```
Action Type:  uint16v = 71
Player Delta: uint16v = delta to previous player index
Data:         2 bytes
```

## Observed

Client (Player_12, entering state):

```
06 06 eeda5f39 8a78b20000000000 | 02 | 47 0c | 01 00
                                            └ data = [01][00]
```

## Player Index

1-indexed game player.

## Fixtures

- `test/fixtures/packets.rb`: `client_change_riding_state`
