# cursor_transfer (Type 78)

Transfer items between cursor and an entity/inventory. When you pick up an item
from a chest, inventory, or output slot, this action sends the transfer details.

## Data Length

9 bytes

## Wire Format

```
Action Type:  uint16v = 78 (cursor_transfer)
Player Delta: uint16v = delta to previous player index
Data:         9 bytes
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 2 | uint16 LE | Item prototype ID (1-indexed, matches `game.item_prototypes` order) |
| 2 | 4 | uint32 LE | Action type (1 = put/pickup, 0 = clear cursor) |
| 6 | 1 | uint8 | Quality offset? (0 = normal, higher for higher qualities) |
| 7 | 2 | bytes | Padding/unknown (usually `00 00`) |

## Notes

- The item count is NOT in this action. The server knows the cursor stack size from
  previous state, so this action just signals "transfer cursor contents" or "clear cursor".
- `action=0, item=0` means clearing the cursor (dropping items).
- `action=1` means transferring the item from cursor to target or vice versa.
- The item type is implicit from the cursor state — the server knows what's on your cursor.

## Examples

| Action | Hex | Decoded |
|--------|-----|---------|
| Pick up assembling-machine-1 | `6a0001000000000000` | Item 106, action=put |
| Clear cursor | `000000000000000000` | Item 0, action=clear |

## Player Index

1-indexed game player
