# frozen_string_literal: true

# Mirrors per-player attributes from Factorio's LuaPlayer API into Ruby,
# populated once from RCON at startup and maintained by packet decoding:
#
#   connected   — true while in-game (NewPeerInfo / PeerDisconnect)
#   admin       — seeded from RCON; there is no reliable packet signal for
#                 admin changes (the wire action is a UI action, not a
#                 status change), so it stays as seeded. Re-seed / re-query
#                 via RCON to refresh.
#   online_time — total ticks played across ALL sessions. Seeded from RCON
#                 (which includes the current session), then computed
#                 LAZILY on read — never auto-incremented:
#                 base_ticks (frozen, previous sessions) + live session
#                 duration (current_game_tick − session_start_tick).
#   afk_time    — ticks since the player's last action. Seeded from RCON,
#                 then maintained from the packet stream: any real input
#                 action (heartbeat tick-closure action, incl. chat) resets
#                 it. Lazily computed:
#                   action seen → current_tick − last_action_tick
#                   otherwise   → seeded_afk + (current_tick − anchor_tick)
#
# For a player who is connected when seeded, the RCON online_time already
# includes the live session whose start we did not observe. That value is
# frozen into base_ticks and the live session is anchored at the first
# observed game tick (#anchor_sessions), so the computed total is exact at
# the anchor and grows correctly afterwards. Players whose join we observe
# (NewPeerInfo) get a real session_start_tick. The same anchor tick seeds
# the afk_time growth (the seeded delta grows with elapsed ticks until the
# player's first observed action resets it to 0).
#
# Keyed by player NAME (unique in Factorio); game indexes are bound from
# C→S heartbeats / the roster.
#
# This is ALSO the single live-roster structure: "online" == record with
# :connected. Each record carries :hb (monotonic ts of the last C→S
# heartbeat proof) which drives the server-mode timeout watchdog. One hash,
# one lock — status, index and liveness are always updated together
# atomically (one structure per player — no parallel copies to drift).
class PlayerAttrs
  def initialize
    @players = {}  # name -> {index:, connected:, admin:, base_ticks:,
                   #         session_start:, afk_seed:, afk_anchor:, last_action:,
                   #         hb:}
    @mutex = Mutex.new
  end

  # Seed from an RCON player_attributes query result (one hash per player:
  # {index:, name:, connected:, admin:, online_time:, afk_time:}).
  # Connected seeds are the authoritative live-roster entry at startup;
  # they get an immediate liveness stamp so the watchdog can't drop them
  # before proof of life arrives.
  def seed(name, index:, connected:, admin:, online_time:, afk_time: 0)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      p = (@players[name] ||= {})
      p[:index] ||= index
      p[:connected] = connected
      p[:admin] = admin
      p[:base_ticks] = online_time.to_i
      p[:afk_seed] = afk_time.to_i
      p[:afk_anchor] = nil  # anchored at the first observed game tick
      p[:last_action] = nil # first real action resets afk to 0
      # Connected players are anchored at the first observed game tick;
      # offline players have no live session at all.
      p[:session_start] = nil
      p[:hb] = now if connected && !p[:hb]
      p
    end
  end

  # NewPeerInfo — player joined. Session start = current game tick; the
  # join itself is liveness proof. If the player was seeded as connected but
  # not yet anchored, anchor here.
  def connect(name, tick)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      p = (@players[name] ||= {})
      if p[:connected] && p[:session_start]
        p  # already tracked live — don't restart the session (double-count)
      else
        p[:connected] = true
        p[:session_start] ||= tick
        p[:hb] = now
        p
      end
    end
  end

  # PeerDisconnect — fold the live session into base_ticks and go offline
  # (removes the player from the live roster; hb goes irrelevant).
  def disconnect(name, tick)
    @mutex.synchronize do
      p = @players[name]
      next nil unless p
      if p[:connected] && p[:session_start]
        p[:base_ticks] += [tick - p[:session_start], 0].max
      end
      p[:connected] = false
      p[:session_start] = nil
      p[:last_action] = nil
      p[:hb] = nil
      p
    end
  end

  # Bind a game index (C→S heartbeat confirmation / roster). The confirming
  # heartbeat is itself liveness proof.
  def set_index(name, index)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      p = (@players[name] ||= {})
      p[:index] = index
      p[:hb] = now if p[:connected]
      p
    end
  end

  # A real input action from the player resets afk_time to 0. Called with
  # the player name and the current game tick for every decoded action
  # that isn't server-internal (nothing / server_tick_info).
  def register_action(name, tick)
    p = @players[name]
    return unless p
    p[:last_action] = tick
    p[:afk_anchor] = nil  # afk now derives from last_action
    p
  end

  # Anchor live sessions seeded while connected (no observed session start
  # yet), and anchor seeded afk_time growth. Called with the game tick on
  # every heartbeat.
  def anchor_sessions(current_tick)
    @players.each_value do |p|
      p[:session_start] = current_tick if p[:connected] && p[:session_start].nil?
      p[:afk_anchor] = current_tick if p[:connected] && p[:afk_seed] && p[:afk_anchor].nil?
    end
  end

  # Lazily computed total play time in ticks: previous sessions + live
  # session duration. Never incremented — always derived.
  def online_time_ticks(name, current_tick)
    p = @players[name]
    return 0 unless p
    base = p[:base_ticks] || 0
    if p[:connected] && p[:session_start]
      base + [current_tick - p[:session_start], 0].max
    else
      base
    end
  end

  # Lazily computed ticks since the player's last action (0 while actively
  # playing). Only meaningful for connected players; nil otherwise.
  def afk_time_ticks(name, current_tick)
    p = @players[name]
    return nil unless p && p[:connected]
    if p[:last_action]
      [current_tick - p[:last_action], 0].max
    elsif p[:afk_anchor]
      (p[:afk_seed] || 0) + [current_tick - p[:afk_anchor], 0].max
    else
      p[:afk_seed] || 0
    end
  end

  # Snapshot for context / AI queries, sorted by name:
  # [{name:, index:, connected:, admin:, online_time_ticks:, afk_time_ticks:}]
  def snapshot(current_tick)
    @players.map do |name, p|
      {
        name: name,
        index: p[:index],
        connected: !!p[:connected],
        admin: !!p[:admin],
        online_time_ticks: online_time_ticks(name, current_tick),
        afk_time_ticks: afk_time_ticks(name, current_tick),
      }
    end.sort_by { |p| p[:name] }
  end

  # ── Live roster / liveness (drives the server-mode timeout watchdog) ──

  # Liveness stamp by name — ANY incoming C→S packet from the player proves
  # they're connected. Only stamps CONNECTED records: a stale packet from a
  # past session must not resurrect anyone.
  def touch(name)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      p = @players[name]
      p[:hb] = now if p && p[:connected]
    end
  end

  # Liveness stamp by game index — a C→S heartbeat carrying input actions
  # names its sender by index, no IP needed. Reaches players whose src_ip
  # was never learned (roster-seeded at startup, NAT'd clients sharing one
  # IP). Returns the names stamped (normally exactly one).
  def touch_by_index(game_index)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    names = []
    @mutex.synchronize do
      @players.each do |n, p|
        next unless p[:connected] && p[:index] == game_index
        p[:hb] = now
        names << n
      end
    end
    names
  end

  # Watchdog scan: connected players whose last liveness proof is older
  # than +timeout+ seconds → [[name, idle_seconds], …].
  def stale_online(timeout)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    stale = []
    @mutex.synchronize do
      @players.each do |name, p|
        next unless p[:connected] && p[:hb]
        idle = now - p[:hb]
        stale << [name, idle] if idle > timeout
      end
    end
    stale
  end

  # Watchdog re-check under the lock: did fresh liveness arrive since the
  # scan? (A packet that landed between scan and re-check cancels the drop.)
  def still_stale?(name, timeout)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      p = @players[name]
      p && p[:connected] && p[:hb] && (now - p[:hb]) > timeout
    end
  end

  # Names of players currently in-game. Sorted for stable output.
  def online_names
    @mutex.synchronize { @players.select { |_, p| p[:connected] }.keys.sort }
  end

  # RCON roster seed (load_roster): authoritative live-roster entry —
  # connected + index + fresh hb — WITHOUT touching time accounting
  # (session/afk anchoring is player_attributes' job).
  def roster_online(name, index)
    now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    @mutex.synchronize do
      p = (@players[name] ||= {})
      p[:connected] = true
      p[:index] ||= index
      p[:hb] ||= now
      p
    end
  end
end
