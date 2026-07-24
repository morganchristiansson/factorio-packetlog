# setup_assembling_machine (Type 88)

Set the recipe of an assembling machine or similar crafting entity.

## Data Length

2 bytes

## Wire Format

```
Action Type:  uint16v = 88 (setup_assembling_machine)
Player Delta: uint16v = delta to previous player index
Data:         2 bytes = uint16 LE
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 2 | uint16 LE | Recipe ID (matches `game.recipe_prototypes` runtime order) |

## Notes

- Recipe IDs match the game's internal prototype numbering, which may differ
  from the `--dump-data` JSON order. Use `game.recipe_prototypes` iteration
  at runtime to get the correct mapping.
- The GUI must be opened first via `open_gui` before setting the recipe.

## Related Actions

| Type | Name | Data | Description |
|------|------|------|-------------|
| 5 | open_gui | 2 | Open entity GUI |

## Player Index

1-indexed game player
