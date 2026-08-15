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
#
# For a player who is connected when seeded, the RCON online_time already
# includes the live session whose start we did not observe. That value is
# frozen into base_ticks and the live session is anchored at the first
# observed game tick (#anchor_sessions), so the computed total is exact at
# the anchor and grows correctly afterwards. Players whose join we observe
# (NewPeerInfo) get a real session_start_tick.
#
# Keyed by player NAME (unique in Factorio); game indexes are bound from
# C→S heartbeats / the roster.
class PlayerAttrs
  def initialize
    @players = {}  # name -> {index:, connected:, admin:, base_ticks:, session_start:}
  end

  # Seed from an RCON player_attributes query result (one hash per player:
  # {index:, name:, connected:, admin:, online_time:}).
  def seed(name, index:, connected:, admin:, online_time:)
    p = (@players[name] ||= {})
    p[:index] ||= index
    p[:connected] = connected
    p[:admin] = admin
    p[:base_ticks] = online_time.to_i
    # Connected players are anchored at the first observed game tick;
    # offline players have no live session at all.
    p[:session_start] = nil
    p
  end

  # NewPeerInfo — player joined. Session start = current game tick. If the
  # player was seeded as connected but not yet anchored, anchor here.
  def connect(name, tick)
    p = (@players[name] ||= {})
    if p[:connected] && p[:session_start]
      p  # already tracked live — don't restart the session (double-count)
    else
      p[:connected] = true
      p[:session_start] ||= tick
      p
    end
  end

  # PeerDisconnect — fold the live session into base_ticks and go offline.
  def disconnect(name, tick)
    p = @players[name]
    return unless p
    if p[:connected] && p[:session_start]
      p[:base_ticks] += [tick - p[:session_start], 0].max
    end
    p[:connected] = false
    p[:session_start] = nil
    p
  end

  # Bind a game index (C→S heartbeat confirmation / roster).
  def set_index(name, index)
    p = (@players[name] ||= {})
    p[:index] = index
    p
  end

  # Anchor live sessions seeded while connected (no observed session start
  # yet). Called with the game tick on every heartbeat.
  def anchor_sessions(current_tick)
    @players.each_value do |p|
      p[:session_start] = current_tick if p[:connected] && p[:session_start].nil?
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

  # Snapshot for context / AI queries, sorted by name:
  # [{name:, index:, connected:, admin:, online_time_ticks:}]
  def snapshot(current_tick)
    @players.map do |name, p|
      {
        name: name,
        index: p[:index],
        connected: !!p[:connected],
        admin: !!p[:admin],
        online_time_ticks: online_time_ticks(name, current_tick),
      }
    end.sort_by { |p| p[:name] }
  end
end
