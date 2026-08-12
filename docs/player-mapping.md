# Player Identity Mapping (peer IDs, game indexes, save data)

Findings from the 2026-08-11 sessions on mapping wire identities to player
names. Save-file internals are detailed in `docs/save/`.

## Peer IDs vs Game Player Indexes — CRITICAL

- **Game player index** (what heartbeat action player fields carry,
  0-indexed in protocol; `players.json` uses 1-indexed) = index into
  `game.players`. Learn it from actions, e.g. the user's own C→S heartbeats.
- **Network peer id** (ConnectionAcceptOrDeny `clientPeerInfo` entry ids,
  `new_peer_id`, and NewPeerInfo sync peer_id) is a per-connection counter.
  It only equals the game index for brand-new joiners (Valoneu: peer 102 =
  game 102). Returning players keep their saved game index (morganc: peer
  101 but game 12).
- Do NOT store peer ids as game indexes. The sniffer learns the user's own
  index from C→S actions and corrects the peer-based guess
  (`remove_other_entries_for`).

## Where Player Data Is (and Isn't) on the Wire

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

## Red Herrings (don't re-investigate)

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

## Protocol Fixes Made for Player Lists

- `parse_network_header` now computes the full variable header (message_id,
  frag_number, confirm items). ConnectionAcceptOrDeny header = 9 bytes here.
- `parse_connection_confirm` (msg 4) fixed: 3-byte header, extracts the
  client's username ("morganc"); the old client_id+1 guess was garbage.
- `parse_connection_accept` (msg 5) added: extracts clientPeerInfo
  (peer_id + name for every online player) and serverUsername.
- Sniffer: prints NewPeerInfo "joined the game" events (was silent), resolves
  PeerDisconnect via a peer_id→name map, and confirms the user's own game
  index from their C→S heartbeat actions.
