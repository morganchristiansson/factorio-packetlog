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
| `deconstruct` | x1,y1,x2,y2 area | the flagged-for-bots removal footprint |
| `begin_mining_terrain` | x, y | terrain mined (not entities) |
| `change_shooting_state` | x, y | where someone shot |
| `move_on_pan` | x, y | camera pan position |

NOT positions, despite earlier notes:

- **`drop_item`** — the 8-byte payload is a DIRECTION double (1.0 / −1.0 /
  ±√2/2 observed), not a position. Verified byte-level on the 2026-08-16
  capture; the old "drop_item = player position" note was wrong.
- **`zoom_around_point`** — the 3 doubles do NOT match player/camera
  positions in practice (values like −137, 90 while working at
  (558, 83)); field order/semantics unverified. Do not use as a
  position source until decoded.

### Actions WITHOUT a position — the blind spot

- **`begin_mining` / `stop_mining`** — hand-removal of entities/ore. The
  action itself carries NO payload (0 bytes, byte-verified; the 8 bytes
  after it are the C→S closure trailer). **BUT the mining target is
  locatable on 2.0**: the player's cursor state is communicated by the
  `selected_entity_changed_*` family, and the `based_on_unit_number`
  variant (type 254, 2.0 only — REMOVED in 2.1) carries the hovered
  entity's **unit number** directly: `[unit(4)][pad(4)]` + C→S
  `[tick][pad]` trailer. Hover→`begin_mining` correlation (verified:
  64 pairs, mostly 0.0s apart) proves the hovered entity is the mining
  target. Resolve the unit number with RCON
  `game.get_entity_by_unit_number(n)` → position. Mining a pole, tree or
  rock is therefore a ONE-click query on 2.0: last type-254 hover before
  `begin_mining`. The 2.1-era "mining is unlocatable" claim only holds
  when the 254 variant is absent (2.1+, or players whose hovers used the
  other variants).
- `start_walking` — direction vector only, not a position.
- `rotate_entity` — data is a direction byte; the entity reference is
  present but not decoded.

### Hover payload semantics (2.0, C→S-only captures)

- `selected_entity_changed_based_on_unit_number` (254): 4-byte unit
  number of the hovered entity + `[pad(4)]` + C→S `[tick][pad]` trailer.
  **This is the locator.**
- `selected_entity_changed_relative` (253): 4-byte payload =
  cursor offset from the player's character `[dx(2)][dy(2)]` i16 LE in
  1/256 tiles (verified: cursor −9,0 during a pipe drag while the build
  line sat 9 tiles west of the player's path). Target world position =
  player position + offset — needs the player's position, which is NOT in
  the packet stream (start_walking is direction-only). Useful for
  exonerating: offsets far from the location under investigation rule
  the session out.
- `selected_entity_changed_very_close` (251): 1-byte payload, semantics
  undecoded (varies per hover event even for the same entity — not an
  entity/item prototype id, not stable per entity).

### Dead-reckoning from move actions (when anchors are sparse)

`start_walking` carries a direction vector (2 doubles, unit-ized) and
`stop_walking` ends the segment; durations come from the tick closures
(60 ticks/s). Player position = last known anchor + Σ speed × ticks ×
dir. The player's character position is NOT in the packet stream — this
is an estimate, and it has hard limits:

- **Walking speed is NOT a constant we can trust.** It depends on ground
  tile (path vs grass vs stone), armor equipment (exoskeletons), vehicle
  use, and obstacles that stop the player — all invisible to the packet
  stream. We do NOT run the simulation and CANNOT query historical
  simulation state, so speed can only be calibrated per-segment from
  anchors. Measured on the 2026-08-16 capture: free walking ≈ 0.145
  tiles/tick, drag-build placement ≈ 0.10, and a long unanchored run
  drifted tens of tiles over a minute.
- **Use for short segments and exonerations only.** Anchored estimates
  over a few seconds are fine; multi-minute extrapolation is not.
- **During a drag-build the player may stand still while the cursor
  sweeps** (no walk events; the build positions advance). In that case
  the player position is fixed for the whole drag — anchor once via a
  fresh REL offset (player = build − offset) and it holds for every tile.
- Good anchors: any build with a REL offset ≤ ~2s old (player = build_pos
  − offset). A fresh REL right before a `begin_mining` gives the mining
  target directly: target = player + offset.

## 2. Tooling (built 2026-08-16, keep improving)

**Position decoding lives in ONE place**: `FactorioProtocol::Position`
(lib/factorio_protocol/position.rb) — the sniffer's console formatter and
every tool below call it, so they can never disagree (the earlier
inconsistencies — shoot as i32, drop_item as position, zoom as position —
came from ad-hoc per-tool decodes; all now fixed + spec'd in
spec/position_spec.rb).

All take the capture path and `--ver 2.0|2.1` (this server is 2.0 —
wrong table = garbage names/positions, e.g. build 277 vs the real
29,524 under 2.0). RCON (tools/rcon.rb) is used for ground truth.

- `tools/grief_scan.rb` — quick pass: builds / deconstruct areas near a
  coordinate, mining sessions, position-bearing actions. Start here.
- `tools/dump_builds.rb` — all build positions + mining session summary.
- `tools/timeline.rb` — per-player action timeline with positions.
- `tools/posmap.rb` — per-player position footprints (build/shoot/pan
  only — NOT drop_item/zoom, see corrections above).
- `tools/track_player.rb` — dead-reckoning tracker (start_walking
  direction + ticks, anchored by build−offset). Treat output as
  approximate; see the caveats above.
- `tools/hover_mining.rb` — 2.0-only: auto-correlates type-254 hovers with
  `begin_mining` and prints the hovered unit numbers (--resolve queries
  RCON for survivors; nil = deleted = the mined entity).
- `tools/rcon.rb exec "/sc …"` — live ground truth: current entities at
  a tile, unit-number resolution
  (`game.get_entity_by_unit_number(n)`), pole/power-line state.

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

- **On 2.0 servers, mining IS locatable** — via
  `selected_entity_changed_based_on_unit_number` (type 254) hovers before
  `begin_mining` (see section 1). On 2.1+ (254 removed) it reverts to
  the old blind spot: timing + position correlation only.
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
- Mining sessions: on 2.0, correlate `selected_entity_changed_based_on_unit_number` (254)
  hovers with `begin_mining` and resolve the unit number (see section 1);
  on 2.1+, scan `begin_mining`/`stop_mining` (no position —
  correlate timing + player's other positions).
- All position-bearing actions near X: build, drop_item, deconstruct,
  begin_mining_terrain, change_shooting_state, move_on_pan,
  zoom_around_point.
