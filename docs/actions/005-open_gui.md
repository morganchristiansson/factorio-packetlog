# open_gui (Type 5)

Open the GUI of an entity (assembling machine, furnace, chest, etc.).

## Data Length

**Variable** — 2 bytes or 14 bytes. Verified from live captures
(2026-08-11, `factorio_capture.pcap`); both forms appear in the same session.

### 2-byte form (client → server, and bare server echoes)

```
Byte 0: gui_type  (0x30 = entity container, observed)
Byte 1: flags     (0x00 = open)
```

The client sends only this bare form; the server is expected to fill in
entity details for the echo (see 14-byte form).

Observed client packet (Player_12 opens an entity container):

```
06 06 68cd5f39 f76ab20000000000 | 04 | 05 0c | 30 00 | f4 6ab20000000000
                                     │   │      │
                                     │   └delta └ data = [30][00]
                                     └ count_flagged (count=2)
```

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

## Parsing

`parse_action` consumes 14 bytes when 14+ are available, otherwise 2.
This matches every observed packet; the ambiguous case (2-byte form
followed immediately by ≥12 bytes of another action) has not been
observed in captures.

## Player Index

1-indexed game player.

## Fixtures

- `spec/fixtures/packets.rb`: `server_open_gui_echo_14b`, `server_open_gui_echo_2b`
