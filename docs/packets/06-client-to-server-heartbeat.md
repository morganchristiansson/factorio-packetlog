# ClientToServerHeartbeat (Type 6)

Regular heartbeat sent from client to server. Contains tick closures with
player input actions for the client's local player.

## Direction

Client → Server

## Structure

```
Network Header (1 byte)
Heartbeat Flags (1 byte)
Sequence Number (4 bytes) uint32 LE
[Tick Closures...]
NextToReceiveServerTickClosure (8 bytes) uint64 LE
[Synchronizer Actions...]
[Heartbeat Requests...]
```

### Heartbeat Flags

| Bit | Field | Description |
|-----|-------|-------------|
| 0 | HasHeartbeatRequests | Contains heartbeat request list |
| 1 | HasTickClosures | Contains tick closures |
| 2 | HasSingleTickClosure | Only one tick closure (count is omitted) |
| 3 | AllTickClosuresAreEmpty | All tick closures have no input actions |
| 4 | HasSynchronizerAction | Contains synchronizer actions |
| 5-7 | (unknown) | Unused? |

### Tick Closure

Each tick closure represents game state at a specific tick:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 8 | Update Tick | uint64 LE, the game tick this closure belongs to |
| var | var | Input Actions | (see below) |

### Input Actions

```
Input Actions Count (uint32v, count = value >> 1, has_segments = value & 1)
[Input Actions...]
[Input Action Segments...] (if has_segments)
```

Each Input Action:

| Size | Field | Description |
|------|-------|-------------|
| uint16v | Action Type | The type of input action |
| uint16v | Player Delta | Delta-encoded player index |
| varies | Action Data | Action-specific data (length depends on type) |

Player Index = `(previous_player_index + player_delta) & 0xFFFF`
Previous player index starts at `0xFFFF` at the start of each tick closure.

### Synchronizer Actions

Used for peer synchronization (connection management, map downloads, etc.).

### NextToReceiveServerTickClosure

8-byte uint64 indicating the next tick the client expects to receive from the server.
This field is only present in client-to-server heartbeats.

## See Also

- [ServerToClientHeartbeat](07-server-to-client-heartbeat.md)
- [Input Actions](../actions.md)
