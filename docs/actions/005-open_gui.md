# open_gui (Type 5)

Open the GUI of an entity (assembling machine, furnace, chest, etc.).

## Data Length

**Direction-dependent** — 8 bytes client→server, 14 or 2 bytes server echo.
Verified from live captures (2026-08-11 and 2026-08-12, `factorio.pcap`).

### 8-byte form (client → server)

```
Byte 0: gui_type  (0x30 = entity container, observed)
Byte 1: flags     (0x00 = open)
Bytes 2-5: tick   (uint32 LE) — local game tick when the click happened
              (heartbeat tick - 3 in captures)
Bytes 6-7: pad    (0x0000)
```

Observed client packet (morganc opens an entity container, hb tick 0x423a7):

```
06 06 9060406f a723040000000000 | 04 | 05 01 | 30 00 a42304000000 | 00 00
                                     │   │      │                   │
                                     │   └delta └ 8-byte data       └ nothing action
                                     └ count_flagged (count=2)
```

The tick matches `selected_entity_cleared` sent immediately after (same sequence,
tick+1). The `nothing` (type 0) action after it is skipped in logging.

**Regression (2026-08-12):** the parser used to read the 8-byte payload as a
2-byte bare form and then misread the payload tail as phantom actions with
bogus player deltas — e.g. `add_decider_combinator_condition` (Player_36) and
`select_next_valid_gun` (Player_59) in a single-player game. The 8-byte length
is locked in by fixtures `client_open_gui_8b`, `_2`, `_3`.

### 14-byte form (server echo with entity ref)

```
Bytes 0-1:  gui_type, flags
Bytes 2-5:  entity ref (tag, hi, lo)   — stable per entity
Bytes 6-9:  per-call token
Bytes 10-13: game tick - 1
```

Observed server echo (Player_6, entity ref tag 0x45):

```
07 06 db8eb200 b743b20000000000 | 08 | 54 01 [12B tick_info]
  | 05 05 | 30 00 45 24 00 00 00 00 00 00 00 00 80 00 | 00 00 00 00 00 00 f0 3f
```

Data = `30 00 45 24 00 00 00 00 00 00 00 00 80 00` (14 bytes).

### 2-byte form (bare server echo)

The server echoes `[gui_type][flags]` with no entity info when the client's
open_gui had nothing to resolve (fixture `server_open_gui_echo_2b`).

## Parsing

`parse_action` uses direction: client → 8 bytes; server → 14 bytes when 14+
are available, else 2 (bare echo).

## Player Index

1-indexed game player.

## Fixtures

- `test/fixtures/packets.rb`: `client_open_gui_8b`, `client_open_gui_8b_2`,
  `client_open_gui_8b_3`, `server_open_gui_echo_14b`, `server_open_gui_echo_2b`
