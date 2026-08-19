# Sniffer Operations: Server Mode, Auto-Detection, Hot Reload, RCON

Operational notes for running the sniffer on the game server host (the
current setup — dedicated server + RCON). Protocol internals live in
`docs/protocol-notes.md`; player mapping in `docs/player-mapping.md`.

## Server Mode (`--server`)

Run the sniffer ON the game server host.

```bash
# Everything auto-detected — even the interface (only non-loopback
# interface wins; else server's --bind IP, else default route):
sudo ruby factorio-sniffer.rb

# Server mode is AUTO-ENABLED for live capture when no explicit mode is
# given (no --server, no --local-ip) and a serving factorio process is
# detected on this host:
sudo ruby factorio-sniffer.rb -i ens18
#   → "Auto-enabled SERVER mode: running factorio server detected (pid N)"

# Explicit overrides (any combination)
sudo ruby factorio-sniffer.rb --server --server-ip 10.0.99.121 -p 34197 -i ens18

# Force client mode
sudo ruby factorio-sniffer.rb -i eth0 --local-ip 192.168.1.144
```

Behavior:
- **Incoming-only analysis**: only client→server (msg 6) packets are parsed.
  Every player action arrives at the server exactly once; the server then
  broadcasts it to all N clients, so the outgoing direction is N duplicates.
  Tradeoff (documented): incoming packets have NOT yet been validated/echoed
  by the server — cross-check with RCON (`tools/rcon.rb`) if needed.
- **Save downloads excluded**: map-download TransferBlocks (msg 13, ~40 MB
  per joining player) are dropped entirely — no analysis, no capture. The
  server already has the save on disk.
- **Capture is C→S only by default** (capture is always on in live
  mode): the capture filter records only packets destined for the server,
  so the pcap mirrors the analysis (no S→C broadcast duplicates).
  `--full-capture` records both directions (still excepting
  TransferBlocks).
- **Roster learning**: every client's ConnectionRequestReplyConfirm (msg 4,
  incoming) registers `src_ip → username`; their first C→S heartbeat action
  binds the real game index (like the old client-side "self" learning, but
  for every client).
- **RCON roster load**: at startup (live capture, server mode) the
  connected-player roster is loaded via RCON (`game.connected_players` +
  `serpent.line`, 1-indexed indexes) and merged into the player DB — so
  existing players are named immediately. Later joiners are learned from
  the packet stream (msg 4 + heartbeat), so no periodic refresh is needed.
  `--no-rcon` disables.
- **Join/leave events**: joins are seen via msg 4 ("X connected") + the
  first-C→S-heartbeat index confirm ("confirmed as game player #N").
  Clean leaves are seen via the C→S `PeerDisconnect` synchronizer action
  in the client's final heartbeat (the S→C broadcast form with a peer_id
  is never seen — no S→C analysis). Crashes/timeouts send nothing and
  linger in @online until reload; poll RCON `/players` for authoritative
  roster changes.

### Auto-enable rule

Server mode auto-engages for LIVE capture only (an `-i` interface) when no
explicit mode flag is passed and `ServerDetect.serving?` is true.
`serving?` = dedicated flags OR hosting flags OR a wildcard-bound listening
UDP socket. Pcap reads are NEVER auto-enabled — the capture may be from a
different machine, and applying this host's server IPs as a direction
filter would silently drop everything.

## Auto-Detection (`lib/server_detect.rb`, shared with `tools/rcon.rb`)

- Finds the factorio process (`pgrep -x factorio` or /proc cmdline scan).
  With multiple factorio processes it prefers the one with a listening UDP
  socket (the actual game server).
- **Game port** = listening UDP socket owned by the process (fd socket
  inodes matched against `/proc/<pid>/net/udp[6]`; state column is field 3,
  NOT 2 — the remote address sits at field 2).
- RCON host/port/password from the cmdline `--rcon-bind`/`--rcon-password`.
- **Dedicated server detection** (two tiers):
  - `DEDICATED_ONLY_FLAGS` — `--start-server`, `--rcon-bind`,
    `--rcon-password`, `--server-settings`, `--console-log`, `--max-players`,
    autosave/whitelist/adminlist/banlist flags. Any match ⇒ dedicated server
    (the full client never accepts these).
  - `CLIENT_ALSO_FLAGS` — `--start-server-load-scenario`,
    `--start-server-load-latest`, `--map-settings`, `--map-gen-settings`.
    The full client technically accepts these (usually to host), so they
    only count as "hosting", not "dedicated".
  - Flag matching is whole-arg (`cmdline.split.include?`), so
    `--start-server` never matches `--start-server-load-scenario`.
- Server IPs = local IPv4s, default-route interface first (`/proc/net/route`).
- CLI precedence: explicit flags > auto-detect > defaults (34197 / all
  local IPs).

## RCON Client (`lib/rcon_client.rb`)

Getting data OUT of a Lua command over RCON: the console's `rcon` object
sends its argument back through the RCON connection as the command response
— the one clean channel:

```lua
local t={} for _,p in pairs(game.connected_players) do t[#t+1]={i=p.index,n=p.name} end rcon.print(serpent.line(t))
```

→ body == `{{i = 1, n = "morganc"}}` (1-indexed game indexes).

- `rcon.print` is the ONLY channel (no error/log fallbacks).
- The built-in `/players` works but lists NAMES only, no index — can't bind
  actions (which carry game player indexes) to names.
- `serpent.line` is available in the console environment.
- Auth quirk: `authenticate!(ignore_first_packet: false)` — Factorio sends
  ONE auth reply, the gem's default expects two and times out.
- `/sc` (silent) instead of `/c` so commands don't print to players.

Protocol version detection (`RconClient#server_version`):
`rcon.print(helpers.game_version)` → `"2.0.77"`. The sniffer uses it to
pick the input-action tables (`FactorioProtocol.select_version`) — both
main actions and segments differ between 2.0 and 2.1 (start_walking 67 vs
69, write_to_console 104 vs 106). `--protocol-version 2.0` overrides
(pcap analysis). `tools/validate_actions.rb` re-validates IDs against
`/toggle-action-logging` output. See docs/protocol-notes.md.

`tools/rcon.rb` — CLI wrapper: `status`, `players`, `exec`, `raw`; env
overrides `RCON_HOST` / `RCON_PORT` / `RCON_PASSWORD`.

## Interactive Filter Console (stdin)

While running in a terminal, type commands at the sniffer (no restart, no
Ctrl-C needed) to filter the console output:

```
/show morganc              only show this player's actions
/show morganc alice        only show these players
/show +alice               add a player to the whitelist
/show -alice               remove a player
/show *                    clear the whitelist (show everyone)
/actions build             only show these action types
/noise change_multiplayer_config   hide these action types
/debug                     toggle decoded per-action lines (default hidden)
/filter                    show current filter state
/players                   list online players
/stats                     session summary
/help                      list commands
```

- Chat (`write_to_console`) is **always printed and exempt from all
  filters** — including the agent's decoded chat feed.
- Player/action matching is case-insensitive; filters survive Ctrl-C hot
  reloads (carried in SnifferState).
- The console reads stdin in a background thread and re-points at the
  current sniffer after every reload, so it works across hot reloads. It
  exits silently when stdin isn't available (nohup/systemd/pcap mode).

## Hot Reload

Ctrl-C reloads the code; Ctrl-C again **within 5 seconds** of the previous
press quits. A single Ctrl-C pressed later is another reload — so you can
reload repeatedly while editing code, and double-tap to shut down. State
carried across reloads (via `SnifferState`): the open capture writer (file
keeps its position — never truncated), the player DB, stats, and learned
identities. Player names are persisted to `players.json` on reload and at
shutdown.

Implementation: `factorio-sniffer.rb` is a thin entry point; the reloadable
classes live in `lib/` (`factorio_protocol`, `item_db`, `player_db`, `pcap`,
`live_capture`, `rcon_client`, `factorio_sniffer`). On reload the entry
snapshots state, `load`s the lib files (fresh code), and rebuilds the
sniffer with the same state. `LiveCapture` re-raises `Interrupt` so the
entry loop decides reload vs quit.

## Tests

- `ruby -Ilib spec/server_mode_spec.rb` — server mode, auto-detect,
  dedicated detection, hot-reload state, RCON roster parsing.
- `ruby -Ilib spec/packet_fixtures_spec.rb` — real captured packet fixtures.
- `ruby -Ilib spec/factorio_protocol_spec.rb` — protocol unit tests.
