# Factorio Packet Sniffer — Agent Context

## Project Overview

Factorio multiplayer protocol reverse-engineering tool. Captures UDP traffic, decodes the binary protocol, extracts player actions, and logs them.

## Key Files

- `/workspace/factorio-sniffer.rb` — Main sniffer application
- `/workspace/lib/factorio_protocol.rb` — Protocol parser (ACTIONS table, parsing logic)
- `/workspace/lib/item_db.rb` — Item prototype name lookup
- `/workspace/players.json` — Player ID→name mapping
- `/workspace/external/` — Game dumps and reference files
  - `input_actions_dump.txt` — `defines.input_action` dump (names and API IDs)
  - `item_prototypes_runtime.txt` — Item prototypes in runtime order
  - `players_dump.txt` — All players from `game.players`
  - `data-raw-dump.json` — Full game prototype data (29MB)
  - `defines_events.txt` — Event IDs

## Current State

### ACTIONS Table (`lib/factorio_protocol.rb`)

Built from `defines.input_action` dump. IDs from the dump may DIFFER from protocol IDs in some sessions. The mapping includes:
- Core actions (build=68, wire_dragging=86, etc.)
- Internal-only actions (nothing=0, stop_walking=1, stop_mining=3)
- Session-verified protocol IDs for some types (wire_dragging at 84 vs 86)

### Key Protocol Findings

**Player IDs**: 0-indexed in protocol, 1-indexed in game. `players.json` uses 1-indexed. Add `+1` to decoded values.

**Ghost flag**: Detected via `next_receive & 1` in client heartbeats. When bit 0 of the 8-byte client timeshift field is 1, ghost mode is active.

**Build action lengths**:
- Single build: 9 bytes (int32 x + int32 y + uint8 dir)
- Ghost build: 10 bytes (9 + 0x00 flag)
- Drag build (subsequent): 11 bytes (9 + 0x01 0x01 marker)

**Input Action Segments**: Some actions (like write_to_console) have data stored in input action segments, not in the standard action data field. These are parsed after the main action list.

**Direction naming**: 16 directions defined (north=0, northnortheast=1, ..., northnorthwest=15).

**Chat messages**: `write_to_console` (type 106). Data format varies:
- Segment format (outgoing): `[0x05][text_len][text]`
- Non-segment format: `[0x04][text]`
- Raw text (fallback)

### Unknown Types (old protocol IDs not in current dump)

| Type | Observed | Suspected |
|------|----------|-----------|
| 84 | 12 bytes S→C | wire_dragging (protocol ID, dump says 86) |
| 265 | 17+ bytes S→C | cursor hover/selection |
| 9 | 16+ bytes S→C | cursor/selection action |
| 128 | 20+ bytes S→C | copy operation |
| 266 | 10+ bytes C→S | flip entity? |
| 267 | 20+ bytes S→C | fast entity split? |
| 268 | 16+ bytes C→S | unknown |
| 60 | observed | cheat? |
| 21, 31, 151 | observed | unknown |

### Fixed Issues

1. ✅ **deconstruct (type 131) data length** — Was 8 bytes (entity ID), corrected to **16 bytes** (two tile positions for area selection). Deconstruct marks a rectangular area with two corner coordinates: `x1,y1,x2,y2` (4 × int32 = 16 bytes). Previously the second position was misinterpreted as a separate phantom action with a fake player ID. Fixed: `131=>["deconstruct",16]`.
   - Before: `<- Player_164       quick_bar_pick_slot    row=254 slot=255 [feff]`
   - After:  `<- Moon-O-Cronic    deconstruct            area=(-352.387, 430.109)-(-349.043, 463.797)"

2. ✅ **server_tick_info (type 84)** — Server-to-client wrapper action with 12 bytes (4B hash + 8B tick). Was `nil` in ACTIONS, causing `hit_unknown` cascading into phantom segment parsing. Fixed: `84=>["server_tick_info",12]`.

3. ✅ **Segment parsing guard** — When `hit_unknown` is triggered during main action parsing, segment parsing is now skipped (offset is unreliable). Prevents reading garbage as segment data.

4. ✅ **Truncated data guard** — Added missing `else` branch for `alen > 0` with insufficient data, now sets `hit_unknown=true`.

5. ✅ **open_gui (type 5) length** — Was 9 bytes, corrected to **14 bytes**. Server heartbeats with count=3, 35B packets: action_section=20B, overhead=6B, data=14B. First 6 bytes are header `30 00 54 ff ff ff` (GUI type + entity ref).

6. ✅ **open_character_gui (type 61) length** — Was 2 bytes, corrected to **15 bytes**. Server heartbeats with count=2, 34B packets: action_section=19B, overhead=4B, data=15B. First 2 bytes `01 54` are GUI type, followed by 13B of metadata.

7. ✅ **open_blueprint_library_gui (type 64) length** — Was 2 bytes, corrected to **15 bytes**. Same packet structure as open_character_gui.

8. ✅ **change_active_item_group_for_filters (type 110) length** — Was 5 bytes, corrected to **15 bytes**. Server heartbeats with count=2, 34B packets.

9. ✅ **Chat echo parsing** — `server_tick_info` wrapper + segment with write_to_console. Server echoes chat via type 84 wrapper followed by segment type 106. Fixed by mapping type 84.

10. ✅ **Server echo metadata suppression** — Server-to-client heartbeats append metadata entries after each echoed player action in the action list. These metadata entries (types include server_tick_info, nothing, paste_entity_settings, Unknown(128), start_walking, etc.) were being parsed as separate actions with phantom player IDs. Fixed by passing `is_server` through to `parse_tick_closure` and discarding all actions after the first when processing server heartbeats.

11. ✅ **`nothing` (type 0) filtered** — Added `return if act[:type] == 0` guard in the sniffer display as an additional safety net for server padding actions.

12. ✅ **Chat message decoding (write_to_console)** — Fixed `decode_action_string` to handle multiple prefix formats correctly:
    - `[0x05][meta][text...]`: text starts at byte 2, runs to end of data. Previously used byte 1 as a uint8 text length, which truncated long messages split across segments (byte 1 contains the TOTAL message length, not the current segment's length).
    - `[0x3d][meta][text...]`: server echo with `=` marker. Previously unhandled, fell through to uint32v decode which mistreated the prefix bytes as a length.
    - `[0x01][meta][text...]`: server echo alternate format. Previously unhandled.
    - Messages split across multiple segments each get their own `write_to_console` action. First segment has `[0x05][total_len][first_part]`, subsequent segments have raw `[continuation]` text.
    - Before: `<- Moon-O-Cronic: ` followed by garbled chars
    - After:  `<- Moon-O-Cronic: Jimbo I want lightning fast trains. What would be the optimal train setup (how much locomotives an`
             `<- Moon-O-Cronic: d huch much cargo wagons) with legendary locomotives and legendary nuclear fuel?`

### Remaining Known Issues

1. **Server heartbeat action metadata filtering** — Server-to-client heartbeats append metadata entries after each echoed player action in the tick closure action list. These metadata entries look like separate actions with varied types (server_tick_info, nothing, paste_entity_settings, Unknown(128), etc.) and player IDs that may coincidentally match real player IDs. The parser now discards all actions after the first in each tick closure for server heartbeats, which eliminates phantom players. However, this means legitimate multi-action server echoes (if any exist) are also truncated.

2. **Server heartbeat action lengths** — Many server-echoed actions have different data lengths than their client counterparts. Compare with the ACTIONS table for each type when debugging new phantom action issues.

### Usage

```bash
# Live capture
sudo ruby factorio-sniffer.rb -i eth0 -p 34197 --local-ip 192.168.1.144

# Pcap analysis
ruby factorio-sniffer.rb -r capture.pcap

# With item names
ruby factorio-sniffer.rb -r capture.pcap --item-db external/item_prototypes_runtime.txt

# Save packets for analysis
ruby factorio-sniffer.rb -i eth0 --save-capture session.pcap

# Validate (show warnings about unknown actions)
ruby factorio-sniffer.rb -r capture.pcap --validate

# Debug with raw hex
ruby factorio-sniffer.rb -r capture.pcap --dump-raw-types
```

### Server Heartbeat Action Structure

Server-to-client heartbeats use a different action encoding from client-to-server. Each server heartbeat typically contains a `server_tick_info` (type 84) action with 12 bytes. When echoing player actions, the server wraps them with additional metadata bytes.

The data layout for echoed actions varies by action type but follows a consistent packet-level pattern:
- Packet size is determined by `15 + action_section` where `action_section = 2 + data_len + ((count-1) * 2)`
- count_flagged byte at offset 14: `count = flagged >> 1, has_segments = flagged & 1`
- Each action: `[type_uint8] [delta_uint8] [data...]` (using uint8, NOT uint16v like client)

### Key Protocol Findings

- **Player IDs**: 0-indexed in protocol, 1-indexed in game. `players.json` uses 1-indexed. Add `+1` to decoded values.
- **server_tick_info (type 84)**: 12 bytes, appears in every server heartbeat. First 4 bytes are per-packet hash, last 8 bytes are the tick value.
- **Action IDs are stable** — `defines.input_action` dump is reliable. IDs don't change between sessions.
- **Build action legacy lengths**: 9B (single), 10B (ghost, trailing 0x00), 11B (drag build, 01 01 marker). Server echoes use 11B for drag builds.
- **Deconstruct (type 131)** — Area selection with two tile positions (16 bytes: 4 × int32 for x1,y1,x2,y2). NOT an entity ID. Server echoes include the full area data; previously parsed as 8-byte entity + phantom metadata.
- **Server echo metadata suppression** — Server-to-client heartbeats append metadata entries after each echoed player action in the tick closure action list. The layout VARIES by session/game version:
  - Session A: `[real_action][metadata...]` — first action is genuine.
  - Session B: `[server_tick_info(84)][real_action][metadata...]` — the wrapper comes first (delta=1 → player 0), then the real echoed action (delta encodes player relative to the wrapper), then metadata.
  - Parser rule: keep the server_tick_info wrapper(s) (needed for player delta decoding; filtered at display) plus the FIRST non-84/non-0 action; drop trailing metadata. Metadata may also trigger hit_unknown on unknown-length types (128, 266, etc.), which stops further parsing.
  - Note: this truncates legitimate multi-action server echoes (if any exist) to the first real action.
- **Chat message formats** — `write_to_console` (type 106) data has several prefix formats:
  - `[0x05][meta(1)][text...]` — Segment format (outgoing). `meta` byte at offset 1 is the total message length (may span multiple segments). Text starts at offset 2 and runs to end of payload. When a message exceeds segment size, it is split: first segment has `[0x05][total_len][first_part]`, subsequent segments have raw `[continuation]` (no prefix).
  - `[0x0b][meta(1)][text...]` — Same layout as `[0x05]` (observed live 2026-08-11: `[0x0b][0x2c]` + 44-byte message). Previously unhandled — fell through to uint32v decode which read `0x0b`=11 as text length and truncated the message to 11 bytes.
  - `[0x24][meta(1)][text...]` — Same layout as `[0x05]` (observed live: `[0x24][0x18]` + 24-byte message). Previously unhandled — decoded with `$` garbage prefix.
  - `[0x29][meta(1)][text...]` — Same layout as `[0x05]` (observed live: `[0x29][0x30]` + 48-byte message). Previously unhandled — decoded with `)` garbage prefix.
  - `[0x3d][meta(1)][text...]` — Server echo with `=` marker.
  - `[0x01][meta(1)][text...]` — Server echo alternate format.
  - `[0x04][text...]` — Non-segment format.
  - `[0x00][meta(1)][text...]` — Server echo format (legacy).
  - `[0x05][0x00]` (2 bytes) — Zero-length message (server echo of empty chat submission). Decodes to nil; not a truncation case.
- **Network header random flag does NOT add bytes** — The 0x20 bit in the network header byte is header metadata only (checksum perturbation flag); the heartbeat payload always starts at byte 1. Parsing from byte 5 (treating the flag as a 4-byte offset) silently dropped ALL tick closures from ~half of all heartbeats (every `0x26`/`0x27`-prefixed packet). Verified against factorio_dissector (`dissect_heartbeat` reads flags at pos 1) and 97,656 affected packets in one capture. Fragmented messages (0x40 bit) are skipped.
- **open_gui (type 5)** — 14 bytes. Format: `[gui_type(1)][flags(1)][entity_tag(1)][entity_hi(1)][entity_lo(2)][token(4)][tick_minus_1(4)]`.
  - GUI type 0x30 = entity container/chest. Byte 1 flags: 0 = open
  - **Bytes 2-5: stable entity reference** (constant per entity, never changes). Tag `0x54` = container. The 3 payload bytes (hi+lo) uniquely identify the entity instance.
  - **Bytes 6-9: per-call token** (changes every invocation, NOT the entity ID)
  - **Bytes 10-13: tick - 1** (uint32). Game tick when action was performed.
  - The actual entity ID is NOT in this action. Entity is identified by the ref tag+payload (bytes 2-5). The client sends an empty open_gui; the server fills the ref from the player's current cursor selection context.
- **cursor_hover (type 265)** — 8 bytes. Format: `[flags(1)][tick(4)][padding(3)]`. Sent when hovering cursor over an entity.
- **cursor_click_select (type 9)** — 8 bytes. Format: `[tick(4)][padding(4)]`. Sent when clicking to select an entity. Tick value matches the open_gui tick (client direction only; server echoes have different wrapped data).

### Server Echo Action Data Lengths (Verified)

| Type | Name | Client Len | Server Echo Len | Notes |
|------|------|-----------|----------------|-------|
| 5 | open_gui | 9 | **14** | 6B header + 8B meta |
| 61 | open_character_gui | 2 | **15** | 2B+13B |
| 64 | open_blueprint_library_gui | 2 | **15** | Same as 61 |
| 84 | server_tick_info | nil | **12** | Server-only action |
| 110 | change_active_item_group_for_filters | 5 | **15** | 5B+10B |
| 131 | deconstruct | 8 | **16** | Area selection: x1,y1,x2,y2 (4 × int32). Previously wrongly set to 8B (entity). |

Server echo data lengths are consistently larger than client lengths due to additional metadata bytes appended by the server.

## Player List / Save File Findings (2026-08-11)

### Peer IDs vs Game Player Indexes — CRITICAL

- **Game player index** (what heartbeat action player fields carry,
  0-indexed in protocol; `players.json` uses 1-indexed) = index into
  `game.players`. Learn it from actions, e.g. the user's own C→S heartbeats.
- **Network peer id** (ConnectionAcceptOrDeny `clientPeerInfo` entry ids,
  `new_peer_id`, and NewPeerInfo sync peer_id) is a per-connection counter.
  It only equals the game index for brand-new joiners (Valoneu: peer 102 =
  game 102). Returning players keep their saved game index (morganc: peer
  101 but game 12).
- Do NOT store peer ids as game indexes. The sniffer now learns the user's
  own index from C→S actions and corrects the peer-based guess
  (`remove_other_entries_for`).

### Where player data is (and isn't) on the wire

- **Map download** (TransferBlock msg 13, 503-byte blocks, block numbers
  0..N): the server's save archive (`mp-save-100.zip`). Contains scenario
  files + `level.dat0..N` chunks. Player data lives inside `level.dat`.
- **level.dat chunks**: independently zlib-compressed (`78 01` header), each
  decompresses to ~1 MiB; join in NAME order (zip entry order is random
  transfer order).
- **level.dat header** (parsed, 0.17+ layout per factorio-server-manager
  save.go): version64(4×u16) + random byte + campaign/name/base_mod
  (optim-str) + difficulty + bools + loaded_from(3×optim-u16) +
  loaded_from_build(u32) + allowed_commands + [00 00 a0 00] + mods
  [count][name][ver][crc]. Optim encoding: byte < 0xFF = value, else full
  dtype. Verified: version 2.1.14.1, build 87436.
- **Console buffer** in level.dat (near the end, with the chat log):
  `02 [len]["name [planet=...]: msg"] 00 [INDEX] 00 [color][tick]` — the
  INDEX is the sender's 0-indexed game index (VERIFIED: morganc=27,
  Darkcry=0, star3Watcher=21, wampastompa09=43 match heartbeat echoes).
  Rolling window — only recent chatters appear.
- **Offline player cache**: 17 records near the console (Phoenix_str,
  Shakarez, Sensual, …) with [v1≈playtime][v2≈last-online tick][color]
  [name][flags][position][locale] — offline players only, no index. Loosen
  the post-name signature to catch all (zero-count varies).
- **Post-zip block** (last transfer block): vanilla server data — game name,
  motd, server addr, and name lists with 0.0.0.0 IP fields + real Steam IDs.
  The lists are ALPHABETICAL, NOT index-ordered (the morganc=12 "match" was
  a coincidence).
- **The `game.players` roster records do NOT contain plain-text names** in
  this version — online players' names appear only in the console buffer +
  alerts. The roster mapping still needs: a player who chats (console), RCON
  (`game.players`), or loading the save in single player.
- Full details: `docs/save/` (index), `docs/save/level-dat.md`,
  `docs/save-file-format.md` (transfer/capture). Tools:
  `tools/extract_save_from_pcap.rb`, `tools/extract_players_from_save.rb`.

### Red herrings (don't re-investigate)

1. Blueprint author names in level.dat (Montoyo, Guillaumeb810, MasterTaz,
   …) look like a player roster — they are imported blueprint book authors.
2. "players" strings in level.dat are inside blueprint labels.
3. Alerts (`added-filter [item=recycler]`) reference player names but carry
   NO index — not usable for mapping.
4. GUI layout names (`top`, `horizontal_flow`, `empty_widget`) sit next to
   length-prefixed name records — GUI state, not player data.
5. The post-zip "player info" block is NOT a mod (server has no mods); its
   name lists are alphabetical, not index-ordered.
6. The 15/17 "player records" found are an OFFLINE cache (playtime +
   last-online), NOT the roster — online players are absent (morganc not in
   the list, consistent).
7. `level.datmetadata` is 8 bytes (timestamp/counter), not player data.
8. A second server connection reuses block numbers — split downloads by
   ConnectionRequest timestamps before reconstructing a save.

### Protocol fixes made for player lists

- `parse_network_header` now computes the full variable header (message_id,
  frag_number, confirm items). ConnectionAcceptOrDeny header = 9 bytes here.
- `parse_connection_confirm` (msg 4) fixed: 3-byte header, extracts the
  client's username ("morganc"); the old client_id+1 guess was garbage.
- `parse_connection_accept` (msg 5) added: extracts clientPeerInfo
  (peer_id + name for every online player) and serverUsername.
- Sniffer: prints NewPeerInfo "joined the game" events (was silent), resolves
  PeerDisconnect via a peer_id→name map, and confirms the user's own game
  index from their C→S heartbeat actions.
