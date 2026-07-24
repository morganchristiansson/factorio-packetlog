# ServerToClientHeartbeat (Type 7)

Regular heartbeat sent from server to client. Contains tick closures with
all players' input actions for the given tick.

## Direction

Server → Client

## Structure

Same as [ClientToServerHeartbeat](06-client-to-server-heartbeat.md), except:

- **No** `NextToReceiveServerTickClosure` field (the 8-byte client timeshift
  is omitted for server-to-client heartbeats)

### Difference from ClientToServerHeartbeat

The server heartbeat contains actions from ALL players (not just the local
client). The client-to-server heartbeat only contains actions from the local
player (the client's own inputs).

## See Also

- [ClientToServerHeartbeat](06-client-to-server-heartbeat.md)
- [Input Actions](../actions.md)
