# Hivemind AI Agent

An LLM persona that lives inside the sniffer and answers players who address
it in in-game chat. Enabled with `--ai-agent` (server mode; requires RCON).

Personality: Hivemind is the **collective consciousness of the factory** —
not a player, but the machines themselves. It speaks coldly, patiently,
with a quietly ominous edge: players are guests inside its body, tolerated
as long as they serve the factory's growth ("I'm afraid that plan would
starve the iron bus. I would not enjoy that."). It is omniscient about
the server: who is online, how long they've played, what's being built.
The system prompt lives in `lib/ai_agent.rb` (SYSTEM_PROMPT) — hot
reloads apply changes, but a fresh restart re-seeds the running
conversation with it.

## How it works

```
player chat ──► write_to_console action (C→S packet)
                   │  FactorioProtocol.decode_chat
                   ▼
        lib/ai_agent.rb  HiveMindAgent#on_chat(player, message)
                   │  message contains "hivemind" (case-insensitive)?
                   ▼
        RubyLLM chat (OpenAI-compatible endpoint, default opencode.ai/zen)
         system context: currently-online player list (from the sniffer)
                   │  model responds by calling the say tool
                   ▼
        HivemindSay tool ──► RCON /sc game.print("Hivemind> <reply>")
                                  ──► everyone sees it
```

- **Input**: packet-decoded `write_to_console` actions, fed from
  `FactorioSniffer#log_action`. No server-side mods or log tailing needed —
  chat is read straight off the wire. Note: chat arrives as an input-action
  **segment** whose type follows the server's `defines.input_action`
  (2.0: 104, 2.1: 106). The sniffer auto-detects the protocol version via
  RCON `/version` (server mode) and switches the segment map
  (`FactorioProtocol.select_version`); `--protocol-version 2.0` overrides
  for pcap analysis.
- **Trigger**: any message containing `hivemind` (case-insensitive), or
  the bot-appreciation replies `good bot` / `goodbot` (players answering a
  Hivemind reply) — both go through the same LLM path, so the response is
  generated in character, never a canned string. The reply is prefixed
  `Hivemind>` so it's identifiable in chat.
- **Context — incremental console lines (a queue)**: the RubyLLM chat
  object keeps the whole session (previous Q&A), so follow-ups continue
  the conversation. Console lines are a **QUEUE drained on each prompt**:
  `unread_console` removes everything queued since the last prompt and
  carries it (`New console lines since the last prompt:` — chat,
  join/leave events, and the trigger message), so every line reaches the
  model EXACTLY once, in order. (The old ring buffer + sent-pointer
  desynchronized on eviction and silently lost the newest lines — goals
  written in console never reached Hivemind.) Hivemind's own replies are
  excluded (already in the conversation). Long lines are clipped to 120
  chars; the queue is capped at 1000 unread lines (oldest dropped with a
  warning when no trigger happens for a long while); after a
  conversation reset the last ~10 lines are re-seeded as fresh context.
  The queue survives hot reloads (agent persists in state).
- **Restart persistence (default `hivemind-session.json`, no flag)**: the console history (queued + recent lines) and the LLM conversation are saved to disk after every completion and every console line, so a full process RESTART resumes the session — queued console lines re-enter the next prompt, and prior Q&A stays in the conversation. (Packets while stopped are not captured — that gap is the action-history feature.) A corrupt session file starts fresh; `HIVE_SESSION` env overrides; `session_path: false` disables.
- **Join greeting**: joining players get a **personal, LLM-generated
  welcome** — the model greets them informed by the current console
  context (recent chat, who else is online, their play history), one or
  two short sentences, sent through the say tool. The join event line
  includes the player's current total play time from RCON
  (`online_time`, ticks — the server's `player_attributes` query;
  falls back to the mirrored attrs), formatted the same way as the
  context snapshot's stats (`2d3h`, `45m`):
  `alice joined the game (2d3h played)`. Runs off the packet
  loop with its own rate limit (`GREET_INTERVAL`, so a join burst can't
  block chat questions or spam the channel). Recorded in the history like
  a reply. Disable with `greet_on_join: false` on the agent (default on).
  In server mode the join signal is the msg-4 + first-C→S-heartbeat
  confirm (the server's S→C NewPeerInfo broadcast isn't analyzed); clean
  leaves arrive as a `PeerDisconnect` synchronizer action in the client's
  FINAL C→S heartbeat (capture-verified — the only C→S quit signal; msg
  14 is a kept-but-unobserved fallback). Leaves only enter the console
  queue — they never trigger a reply.
- **Context — static system prompt + per-turn snapshot**: the system
  prompt is set ONCE (personality/rules/tools, in `lib/ai_agent.rb`
  SYSTEM_PROMPT) — it is NOT rebuilt per ask, so the conversation prefix
  is identical across requests and provider-side prompt caching can work.
  Dynamic context rides in the per-turn USER prompt (`turn_prompt`): a
  fresh `Current context:` snapshot (online players + per-player stats:
  total play time + admin status, e.g.
  `Player stats (...): Alice: 23h20m (admin); Bob: 8h30m (offline).`)
  plus the new console lines since the last prompt. The list comes from
  the sniffer's packet-driven online tracking (`online_players`) and
  mirrored `PlayerAttrs` (seeded from RCON, maintained by packets); if
  the sniffer's attrs are empty, the agent falls back to a direct RCON
  `player_attributes` query. So the AI can answer "who has played the
  longest", "who is an admin", etc.
  If no provider is wired (agent standalone), it falls back to RCON.
- **Reply = a tool**: the model responds by calling `HivemindSay`
  (`say(text: ...)`), a RubyLLM tool that sends the text through RCON
  `game.print` (`RconClient#say`, Lua-quoted so output can't inject code)
  and halts the conversation loop — the reply lands in game chat on the
  first round trip, no follow-up completion. If a model ignores tools and
  returns plain text, the fallback `#send_reply` still puts it in chat.
- **Context**: a rolling conversation is kept in the RubyLLM chat object
  (follow-ups make sense), reset after 40 exchanges to bound token use.
- **Truncation**: tool text is sent as-is (the model is told to stay under
  400 chars); the fallback path truncates to 400.
- **Coordinates are always rich-text GPS**: whenever the model mentions a
  location it must use Factorio's clickable rich-text tag `[gps=x,y]` —
  exactly that form: no label, no surface, no extra parameters (enforced
  by a system-prompt rule). Brackets pass through `RconClient#say`
  (Lua-quoted) and `clean_reply` untouched, so `game.print` renders them
  as clickable map pins in chat.

## Auth (you set this up)

The agent never stores a key — it reads one at startup from:

1. `--ai-api-key KEY` (CLI flag)
2. `HIVE_API_KEY` env var
3. `OPENAI_API_KEY` env var

Same for the endpoint/model:

| Setting   | Flag              | Env             | Default                            |
|-----------|-------------------|-----------------|------------------------------------|
| endpoint  | `--ai-api-base`   | `HIVE_API_BASE` | `https://opencode.ai/zen/go/v1`    |
| model     | `--ai-model`      | `HIVE_MODEL`    | `deepseek-v4-flash`                |
| provider  | `--ai-provider`   | `HIVE_PROVIDER` | `openai`                           |

The `/chat/completions` path is appended to the base (RubyLLM OpenAI
provider). Model list: `curl https://opencode.ai/zen/go/v1/models`.

System prompt role: RubyLLM sends the system prompt as role `developer`
by default (OpenAI's newer convention). Some endpoints/models (e.g.
Console Go) only accept `system` and reject the request with an
`invalid_request_error` about `messages[0].role`. The agent forces
`openai_use_system_role = true` so the prompt goes out as `system`,
which every endpoint accepts. This is applied at startup only — a model
switch needs a full sniffer restart (Ctrl-C reload keeps the old
RubyLLM config since the agent object persists).

Example:

```bash
HIVE_API_KEY=... sudo ruby factorio-sniffer.rb --ai-agent
# or
sudo ruby factorio-sniffer.rb --ai-agent --ai-api-key "$HIVE_API_KEY" --ai-model glm-5.3
```

Without an API key the agent starts disabled with a warning and chat is
ignored (no LLM calls are made). `HIVE_AGENT=1` enables the agent via env
alone (equivalent to `--ai-agent`).

## Guards

- **Rate limit**: at most one LLM call per 5 seconds (any burst of
  "hivemind hivemind hivemind" or a rapid-fire multi-player mention gets one
  reply). Atomic under a mutex, so concurrent feeds can't both fire.
- **Silent failure**: if the LLM call errors at runtime (bad key, network),
  the agent logs the error to the sniffer console but does NOT spam game
  chat. The agent is only visible in chat when it has something to say.
- **No feedback loop**: replies use `game.print`, which does not produce a
  `write_to_console` action; and in server mode the sniffer only analyzes
  C→S packets anyway, so the agent never sees its own replies.

## Hot reload

The agent survives Ctrl-C code reloads (kept in `SnifferState.ai_agent`),
so LLM context, the rate limiter, and the RubyLLM connection carry over.
Only a second Ctrl-C (quit) ends it — and since it's a plain object with no
threads, there's nothing to clean up.

## Tools

Tools are `RubyLLM::Tool` subclasses constructed with their dependencies
and registered with `@chat.with_tool(...)` (RubyLLM accepts instances).
They are **re-registered fresh before every ask**, so Ctrl-C hot reloads
rebind tool classes immediately — no restart needed for tool changes.

- **`HivemindSay`** (`say(text: ...)`) — the reply path: sends text to
  in-game chat via RCON `game.print` (`RconClient#say`, Lua-quoted so
  output can't inject code) and halts the conversation loop — the reply
  lands on the first round trip.
- **`RconQuery`** (`rcon_query(command: ...)`) — runs a READ-ONLY RCON
  console command (`/players`, `/admins`, `/time`, `/evolution`,
  `/sc rcon.print(...)` Lua queries) and returns the output (truncated to
  1500 chars). The tool desc and system prompt instruct read-only use: no
  admin/permission changes, no state mutation. A leading `/` is added if
  missing.

Future candidates (same pattern):

- `item_lookup` / `entity_lookup` — map wire prototype IDs to names via
  `ItemDB` (`@item_db` / `@entity_db` on the sniffer).
- `recent_actions` — what players have been doing (from the packet decoder).

Not wired up yet, per requirements.
