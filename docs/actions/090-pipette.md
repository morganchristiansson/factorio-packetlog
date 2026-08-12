# pipette (Type 90)

Activate the pipette tool (select entity under cursor, like middle-click). Copies the
item under the cursor to your cursor, determining the item from the source context.

## Data Length

9 bytes

## Wire Format

```
Action Type:  uint16v = 90 (pipette)
Player Delta: uint16v = delta to previous player index
Data:         9 bytes
```

## Data Structure

| Offset | Size | Type | Description |
|--------|------|------|-------------|
| 0 | 1 | uint8 | Source type (0=inventory/quickbar, 4=world entity) |
| 1 | 4 | uint32 LE | Reference: item prototype ID (src=0) or entity prototype ID (src=4) |
| 5 | 2 | bytes | Padding (zeros) |
| 7 | 1 | uint8 | Flag (always 0x01) |
| 8 | 1 | uint8 | Quality (1=normal, 2=uncommon, etc.) |

## Source Types

| Value | Source | Reference Field |
|-------|--------|-----------------|
| 0 | Inventory or quickbar | Item prototype ID (1-indexed, `prototypes.item` iteration order) |
| 4 | World entity | Entity prototype ID (1-indexed, `prototypes.entity` iteration order) |

## Examples

| Action | Hex | Decoded |
|--------|-----|---------|
| Pipette transport-belt from quickbar | `000500000000000101` | Item #5 = transport-belt, qual=1 |
| Pipette underground-belt from quickbar | `000900000000000101` | Item #9 = underground-belt, qual=1 |
| Pipette assembling machine from world | `045f00000000000101` | Entity #95 = assembling-machine-1, qual=1 |

## Notes

- src=4 refs are ENTITY prototype ids, NOT item ids and NOT unit_numbers.
  Capture-verified against a live server (`prototypes.entity` order):
  entity #87 = stone-furnace, #148 = copper-ore, #149 = iron-ore — while
  item #87 = nuclear-reactor, #149 = carbon. Entity pipettes like ores
  (iron/copper) only decode correctly via the entity list.
- Both lists start identically for early buildable items (item/entity
  registration order coincide for the first ~80 entries), which can make
  the item db look right for low ids — it diverges after that.
- Dump both lists from a live server with `tools/item_db.rb`; the sniffer
  also populates them from RCON automatically in server mode.
- When pipetting from inventory/quickbar (src=0), the reference is the item
  prototype ID directly, and the source slot/row is implicit.

## Player Index

1-indexed game player
