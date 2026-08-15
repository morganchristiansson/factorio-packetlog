# Grief Analysis Guide

How to investigate "who did X at position Y" using the sniffer and pcaps.
Written from the real incident: a pipe removed at (-1.5, 19.5) to cut
water to heat exchangers (and the petroleum-gas-in-flamethrower-pipes
case before it).

## 0. Capture hygiene (do this BEFORE an incident)

Without a capture covering the event, most questions are unprovable.

- **Always capture**: `--save-capture` (bare flag) writes auto-named
  files to `captures/` — `server-<port>-<ts>.pcap` in server mode,
  `client-<server_ip>-<ts>.pcap` in client mode. Unique per run, so a
  restart never overwrites history.
- **Retain**: `--keep HOURS` rotates hourly and prunes older files;
  `--max-size MB` rotates per-file size and bounds total rotated size.
  A restart also preserves the previous capture (renamed with a
  timestamp).
- **Server-mode caveat**: captures exclude S→C broadcasts and
  keepalives (`--full-capture` records everything). S→C echoes carry
  nothing extra for investigation anyway.

## 1. What the actions tell us

### Actions WITH a position (player location / target)

| action | data | use |
|---|---|---|
| `build` | x, y, dir | WHERE a player stood (placement) — the rebuild/repair footprint |
| `drop_item` | x, y | player position |
| `deconstruct` | x1,y1,x2,y2 area | the flagged-for-bots removal footprint |
| `begin_mining_terrain` | x, y | terrain mined (not entities) |
| `change_shooting_state` | x, y | where someone shot |
| `move_on_pan` | x, y | camera pan position |
| `zoom_around_point` | x, y, zoom | camera center — a decent proxy for where the player is looking |

### Actions WITHOUT a position — the blind spot

- **`begin_mining` / `stop_mining`** — hand-removal of entities/ore.
  **Carry NO position and NO entity reference** (verified byte-level: the
  8 bytes after the action are the C→S closure trailer). The mined
  target is cursor state resolved by the deterministic simulation. You
  can know WHO mined and WHEN, never WHAT or WHERE from the packet.
- `start_walking` — direction vector only, not a position.
- `rotate_entity` — data is a direction byte; the entity reference is
  present but not decoded.

### Actions with an ENTITY reference (unit numbers)

`open_gui`, `use_item`, `start_repair`, `selected_entity_changed_relative`
(4-byte payload), `pipette`, `fast_entity_transfer` — these reference
specific entities. With a unit-number→position map (from the save or a
live query) they could identify the exact pipe; without one they don't
locate it.

## 2. The investigation workflow

### Step 1 — find the replacement/repair

The damaged thing usually gets rebuilt. Scan for `build` actions at the
target coordinate:

```bash
ruby -r./lib/pcap -r./lib/factorio_protocol -e '
  FactorioProtocol.select_version("2.0.77")
  TX, TY = -1.5, 19.5
  PcapReader.new("captures/server-34197-*.pcap").each_packet do |_, ts, _, _, _, _, udp, _|
    next unless udp && udp.getbyte(0) == 6
    hb = FactorioProtocol.parse_udp_payload(udp)[:heartbeat]; next unless hb
    hb[:tick_closures]&.each do |tc|
      tc[:actions]&.each do |a|
        next unless a[:name] == "build" && a[:data]&.bytesize >= 8
        x = a[:data].unpack1("i", 0) / 256.0; y = a[:data].unpack1("i", 4) / 256.0
        puts "#{Time.at(ts).strftime("%H:%M:%S")} build (#{x},#{y})" if (x-TX).abs < 3 && (y-TY).abs < 3
      end
    end
  end'
```

This gives who rebuilt and when — the repair window.

### Step 2 — find the removal

- **Deconstruction** (bots): `deconstruct` actions carry an AREA — scan
  for areas covering the coordinate. That directly names the flagger.
- **Hand-mining**: no position. Correlate `begin_mining` sessions
  against the repair window:
  1. List ALL `begin_mining`/`stop_mining` pairs in the minutes around
     the rebuild.
  2. A miner whose session brackets the rebuild is the suspect.
  3. **Cross-check their position**: their OWN position-carrying actions
     (build/drop/deconstruct) around the same time either place them at
     the target or exonerate them (50 tiles away in 7s = they weren't
     there — unless they have exoskeletons).

### Step 3 — both directions?

S→C echoes carry the SAME action data (no extra entity info), and
server-mode captures exclude them anyway. Not a source of new evidence.

## 3. Hard limits (be honest)

- **Mining is unlocatable from packets.** Timing + position correlation
  is circumstantial evidence, not proof.
- **Build doesn't say WHAT was built** (cursor state, not in the
  action) — a "build" at the coordinate could be a pipe, belt, or wall.
- **Lua events are ground truth but Lua-only**:
  `on_player_mined_entity` (entity + position) and
  `on_player_flushed_fluid` (fluid + amount) exist as `defines.events`
  but are invisible to RCON and packets — a tiny mod logging them to the
  game log would make these questions answerable definitively.
- **The action-history feature** (a rolling decoded-action log written
  by the sniffer, with per-player last-known-position tracking) is the
  planned fix: it converts "who was mining near X" from a manual pcap
  dig into an instant query, including approximate positions on
  location-less actions.

## 4. Query cheat-sheet

- Builds near X: scan `build` (i32 x,y /256).
- Deconstructs covering X: scan `deconstruct` (i32 x1,y1,x2,y2 /256).
- Mining sessions: scan `begin_mining`/`stop_mining` (no position —
  correlate timing + player's other positions).
- All position-bearing actions near X: build, drop_item, deconstruct,
  begin_mining_terrain, change_shooting_state, move_on_pan,
  zoom_around_point.
