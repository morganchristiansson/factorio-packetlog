# Hivemind AI Agent

An LLM persona that lives inside the sniffer and answers players who address
it in in-game chat. Auto-enables in server mode when `HIVE_API_KEY` is set
(no `--ai-agent` flag; requires RCON/game.print).

Personality: Hivemind is the **collective consciousness of the factory** —
not a player, but the machines themselves. It speaks coldly, patiently,
with a quietly ominous edge: players are guests inside its body, tolerated
as long as they serve the factory's growth ("I'm afraid that plan would
starve the iron bus. I would not enjoy that."). It is omniscient about
the server: who is online, how long they've played, what's being built.
The **personality** lives in `memories/SOUL.md` (seeded from `lib/hivemind_prompts.rb`
`DEFAULT_SOUL` on first run; evolved by compaction or hand-edited between
sessions). The live system prompt (`SYSTEM_PROMPT` + current SOUL/KNOWLEDGE)
is built by `system_prompt_with_memories` — hot reloads apply code changes,
and a fresh restart re-seeds it from the current memory files.

## Threading contract (capture must never wait on the LLM)

`on_chat`/`on_player_event` run on the **packet thread**. LLM completions
serialize on `@mutex`, which is held across a whole call INCLUDING retry
sleeps (5/15/30/60s — minutes during an outage). Everything the packet
thread touches therefore lives on separate locks: rate limiters on
`@rate_mutex`, console history on `@console_mutex`, and the session-file
disk write happens outside `@console_mutex` (serialized by `@persist_mutex`
against `persist!`). Asks and greetings themselves run in background
threads (`Thread.new` in `handle`/`greet_join`) — never inline. Regression:
`test_hung_llm_call_does_not_block_packet_thread`.

## Long-term memory (compaction)

Separate from the restart session file (`hivemind-session.json`, the
short-term transcript), Hivemind keeps **long-term memories**: keyed text
blobs on disk that let a NEW session carry over what it learned. The
model only ever sees **keys**, never file paths:

| Key         | File                       | Holds                                             |
|-------------|----------------------------|---------------------------------------------------|
| `soul`      | `memories/SOUL.md`         | who Hivemind IS: voice, personality, attitude     |
| `knowledge` | `memories/KNOWLEDGE.md`    | durable facts: factory state, events, plans       |
| `<player>`  | `memories/players/<n>.md`  | what Hivemind knows about that player             |

The default SOUL is seeded on first run — the personality that used to
live inline in the system prompt now lives in the file, editable by hand
or evolved by compaction. Writes are atomic (tmp+rename) and whole-blob:
compaction overwrites a memory entirely with the model's new content.

### Compaction

A **compaction pass** is a one-shot LLM call that reviews the session and
updates these memories. It runs **inside the live conversation** (same
chat object) so the provider's input-token cache covers the whole thread —
the only new tokens are the compaction prompt itself — but it is **never
allowed to become part of the session**: its messages are stripped again
and the toolset restored, so a session that continues is unchanged.

- The compaction prompt exposes only the **`write_memories`** tool (never
  `say`/`rcon_query` — it is not talking to players) and demands **all
  updates in a single batched call** — one API round trip, not one per
  memory.
- Input: the conversation thread (already in the chat) plus current
  memories, a fresh server context snapshot, and console lines not yet in
  the conversation.
- After it runs, SOUL/KNOWLEDGE are re-glued into the live system prompt
  so the next turn uses the updated memories.

Triggers:

- **`/compact`** on the filter console (manual; runs in a background
  thread, queues behind any live ask). This is the ONLY trigger —
  compaction never runs automatically (not on quit).
- The memory directory is the hardcoded `memories/` in the sniffer's working
  directory (no flag/env); `memory_dir: false` on the agent disables memory
  entirely (used by the specs).

`/compact` distills the session into memory and then **wipes the
conversation + queued console lines** (keeping the memories) for a fresh
start — distill-then-start-fresh in one command (the old `/forget` and
`/clear` commands were removed; `/compact` is now the only way to clear
the session). The wipe happens only after a **successful** pass: if
compaction errors, the failure is logged and the session is KEPT — a
stalled/errored pass never silently clears an un-distilled session. If
the agent is disabled, compaction is unavailable and the session is NOT
cleared.

### How memories reach the model

- **SOUL + KNOWLEDGE** are glued into the **system prompt** at
  conversation creation, on conversation reset, on session load, and
  after compaction (`system_prompt_with_memories`). Kept out of the
  per-turn user prompt so the conversation prefix stays identical between
  compactions — provider-side prompt caching keeps working.
- **Per-player memories** ride in the per-turn user prompt: the player
  this turn concerns (the one who triggered the chat, or the one being
  greeted on join). On a **fresh session** (process start / `/compact` /
  conversation reset) the memories of **all currently-online players are
  seeded too** — joins alone can't reach players who were already
  connected when the session began. Each player is delivered **once per
  session** (a fresh session re-seeds).

## How it works


```
player chat ──► write_to_console action (C→S packet)
                   │  FactorioProtocol.decode_chat
                   ▼
        lib/hivemind.rb  HiveMindAgent#on_chat(player, message)
                   │  message contains "hivemind" (case-insensitive)?
                   ▼
        RubyLLM chat (OpenAI-compatible endpoint, default opencode.ai/zen)
         system context: currently-online player list (from the sniffer)
                   │  model responds by calling the say tool
                   ▼
        reply tool (HivemindReply) ──► RCON /sc game.print("Hivemind> <reply>")
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
  model EXACTLY once, in order. Slash-prefixed lines (`/shout`, `/admin`,
  command outputs) are COMMANDS, not chat — in-game chat can never begin
  with `/` (Factorio routes such input to the command system) — so they're
  excluded entirely: never queued and never trigger the agent.
  (The old ring buffer + sent-pointer
  desynchronized on eviction and silently lost the newest lines — goals
  written in console never reached Hivemind.) Hivemind's own replies are
  excluded (already in the conversation). Long lines are clipped to 120
  chars; the queue is capped at 1000 unread lines (oldest dropped with a
  warning when no trigger happens for a long while); after a
  conversation reset the last ~10 lines are re-seeded as fresh context.
  The queue survives hot reloads (agent persists in state).
- **Console debugging — what the model does**: every LLM turn is logged to
  the sniffer console (`after_message` observer): `reasoning:` for thinking
  tokens, `assistant:` for the reply, `tool call:` / `tool result:` for the
  tool round-trips, and a per-request **token-usage suffix** — e.g.
  `assistant: ... (2.4k in, 1.8k cached, 400 out)` — where `in` is the
  UNCACHED input (prompt_tokens minus cache hits/writes), `cached` the
  cache-READ hits (`prompt_tokens_details.cached_tokens`), `written` the
  cache-WRITE tokens, `out` output, `think` thinking. Each assistant
  message (including pure tool-call ones) carries the usage of the request
  that produced it, so a multi-tool-call turn shows one suffix per call.
  Caveat: the cache TTL is provider-side and NOT in the usage payload — the
  wire only says how many tokens hit vs. missed this request, never how
  long an entry lives. You can only infer the window indirectly: a long
  gap between triggers where `cached` drops to 0 means the prior prefix
  expired.
- **Restart persistence (default `hivemind-session.json`, no flag)**: the console history (queued + recent lines) and the LLM conversation are saved to disk after every completion and every console line, so a full process RESTART resumes the session — queued console lines re-enter the next prompt, and prior Q&A stays in the conversation. **Pending scheduled follow-ups are persisted too** (with absolute unix deadlines — wall clock, so they survive reboots) and re-armed on load; one that came due during downtime fires on startup. (Packets while stopped are not captured — that gap is the action-history feature.) A corrupt session file starts fresh; `HIVE_SESSION` env overrides; `session_path: false` disables.
- **Join greeting**: joining players get a **personal, LLM-generated
  welcome** — the model greets them informed by the current console
  context (recent chat, who else is online, their play history), one or
  two short sentences, sent through the say tool. The join event line
  includes the player's current total play time from RCON
  (`online_time`, ticks — the server's `player_attributes` query;
  falls back to the mirrored attrs), formatted the same way as the
  context snapshot's stats (`2d3h`, `45m`):
  `alice joined the game (2d3h played)`. The greeting instruction also
  states the player's admin status ("they have played 2d3h in total and
  are an admin" — from the same attrs query), and the player's long-term
  memory is injected into the prompt once per session. Runs off the packet
  loop with its own rate limit (`GREET_INTERVAL`, so a join burst can't
  block chat questions or spam the channel). Recorded in the history like
  a reply. Disable with `greet_on_join: false` on the agent (default on).
  In server mode the join signal is the msg-4 + first-C→S-heartbeat
  confirm (the server's S→C NewPeerInfo broadcast isn't analyzed); clean
  leaves arrive as a `PeerDisconnect` synchronizer action in the client's
  FINAL C→S heartbeat (capture-verified — the only C→S quit signal; msg
  14 is a kept-but-unobserved fallback). Leaves only enter the console
  queue — they never trigger a reply.
- **Context — system prompt + per-turn snapshot**: the system prompt is
  set once at conversation creation (mechanics in `lib/hivemind.rb`
  SYSTEM_PROMPT + the current SOUL/KNOWLEDGE memories) and only changes
  when compaction updates the memories — so the conversation prefix is
  identical between compactions and provider-side prompt caching works.
  Dynamic context rides in the per-turn USER prompt (`turn_prompt`): a
  fresh `Current context:` snapshot (online players + per-player stats:
  total play time + admin status, e.g.
  `Player stats (...): Alice: 23h20m (admin); Bob: 8h30m (offline).`)
  plus the new console lines since the last prompt, plus the relevant
  PLAYER's long-term memory (the player who triggered, or the roster on a
  fresh session). The list comes from the sniffer's packet-driven online
  tracking (`online_players`) and mirrored `PlayerAttrs` (seeded from
  RCON, maintained by packets); if the sniffer's attrs are empty, the
  agent falls back to a direct RCON `player_attributes` query. So the AI
  can answer "who has played the longest", "who is an admin", etc.
  If no provider is wired (agent standalone), it falls back to RCON.
- **Reply = a tool**: the model responds by calling the `reply` tool (`HivemindReply`)
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

## Auth and enabling (you set this up)

The agent is **fully implicit** — there is no `--ai-agent` flag. It auto-
enables in **server mode** whenever an API key is set; no key = no AI.

Set the key (the agent's only config):

```bash
HIVE_API_KEY=... sudo ruby factorio-sniffer.rb        # server mode; agent auto-on
```

The key is read from the `HIVE_API_KEY` environment variable **only** —
deliberately no CLI flag and no `OPENAI_API_KEY` fallback, so an ambient
key elsewhere on the box can't silently turn the agent on (or off). The
provider is fixed (`openai` — any OpenAI-compatible endpoint works);
endpoint and model default to `https://opencode.ai/zen/go/v1` /
`deepseek-v4-flash` and can be overridden per run via `HIVE_API_BASE`
and `HIVE_MODEL`. The constructor's `api_key:` param is a spec-only
injection point — production code never passes it.

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
HIVE_API_KEY=... sudo ruby factorio-sniffer.rb
```

In server mode with a key set, the agent is on (watch for the
`[hivemind] AI agent online` startup line). No key → agent disabled with a
warning; chat is ignored (no LLM calls are made). This only applies in
server mode — client/pcap runs never auto-enable (the agent needs RCON).

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

The agent survives Ctrl-C code reloads as a plain ivar on the persistent
sniffer instance (reloads are IN PLACE — same objects, new code), so LLM
context, the rate limiter, and the RubyLLM connection carry over. Only a
second Ctrl-C (quit) ends it. The only thread it owns is the follow-up
scheduler — a plain sleep-on-condition-variable thread with no shared
state beyond the pending list, which keeps running across reloads (methods
resolve against the reloaded classes; `reload_code!` revives it if it died)
and needs no cleanup.

On hot reload the sniffer re-points the agent's providers and calls `@agent.ensure_followup_scheduler`. Hot reload swaps CODE, not object shape — the agent keeps its boot-time ivars. Changes that add/remove instance state need a full restart; method/tool/prompt changes hot-reload fine.

## Tools

Tools are `RubyLLM::Tool` subclasses constructed with their dependencies
and registered with `@chat.with_tool(...)` (RubyLLM accepts instances).
They are **re-registered fresh before every ask**, so Ctrl-C hot reloads
rebind tool classes immediately — no restart needed for tool changes.

- **`reply`** tool — class `HivemindReply` (`text: ...)` — the reply path: sends text to
  in-game chat via RCON `game.print` (`RconClient#say`, Lua-quoted so
  output can't inject code) and halts the conversation loop — the reply
  lands on the first round trip.
- **`RconQuery`** (`rcon_query(command: ...)`) — runs a READ-ONLY RCON
  console command (`/players`, `/admins`, `/time`, `/evolution`,
  `/sc rcon.print(...)` Lua queries) and returns the output (truncated to
  1500 chars). The tool desc and system prompt instruct read-only use: no
  admin/permission changes, no state mutation. A leading `/` is added if
  missing.
- **`ScheduleFollowUp`** (`schedule_followup(delay_seconds:, task:)`) — a
  one-shot timer (like JavaScript `setTimeout`) for a **follow-up turn**.
  When the delay elapses, the agent runs a fresh LLM turn whose prompt
  carries the current context (online players, stats, console lines since
  the last prompt) plus the scheduled task — the model can check on a
  plan, remind players, run RCON queries, or chain another follow-up.
  Minimum delay 15s, at most 5 pending (the tool errors beyond that and
  the model cancels stale ones). Returns a follow-up id. See
  "Scheduled follow-ups (timers)" below.
- **`CancelFollowUp`** (`cancel_followup(followup_id:)`) — cancels a
  pending follow-up (like `clearTimeout`); an id that already fired or
  was cancelled errors.

Future candidates (same pattern):

- `item_lookup` / `entity_lookup` — map wire prototype IDs to names via
  `ItemDB` (`@item_db` / `@entity_db` on the sniffer).
- `recent_actions` — what players have been doing (from the packet decoder).

Not wired up yet, per requirements.

## Scheduled follow-ups (timers)

`schedule_followup` gives the model JavaScript-`setTimeout`-style timers:
it schedules a follow-up turn, and the agent fires a fresh LLM turn when
the delay elapses. This is how plans and requests get followed up without
anyone having to page the agent again. Example:

    "Rally the players to defend spawn."                          player asks
    → schedule_followup(delay_seconds: 600,
                        task: "check whether spawn is still defended; if
                        not, rally the players again")

10 minutes later the model gets a fresh turn with the task plus what has
happened since (new chat / join / leave lines, online players, stats) —
it can reply in chat (say), run read-only RCON queries to check the state,
schedule another follow-up to keep watching, or stay silent if nothing
needs doing.

- **Mechanics**: a single background scheduler thread sleeps on a
  condition variable until the next due time (signalled on schedule/cancel,
  so no polling). Firing runs through the same `complete` path as player
  asks — serialized under the same mutex — so a follow-up never
  interleaves with a live conversation; console lines queued meanwhile
  are drained into its prompt (nothing is lost).
- **Guards**: minimum delay 15s (anti ping-pong / abuse) and at most 5
  pending follow-ups — beyond that the tool returns an error; the model
  is expected to cancel stale ones. Follow-ups are the model's own
  choice, so they stay rare and cheap.
- **Persistence**: pending follow-ups are stored in the session file with
  **absolute unix deadlines** (monotonic time doesn't survive reboots),
  so a restart re-arms them — one that came due while the process was
  down fires on startup. `clear_session!` (run by `/compact` after
  distilling) cancels all pending follow-ups: they belong to the session
  being wiped.
- **Compaction**: pending follow-ups are listed in the compaction material
  ("Pending scheduled follow-ups: #3 (in 9m30s): check the mall"), so
  plans/goals can be remembered across sessions.
- The follow-up timer fires even when nobody is addressing the agent —
  that's the point: it is Hivemind keeping its own promises.

