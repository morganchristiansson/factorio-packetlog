# GameInformationRequestReply (Type 17)

Server responds with game information for the server browser.

## Direction

Server → Client

## Structure

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 1 | Network Header | `msg_type=17` |
| 1 | var | Game Info | Variable-length game information data |

Contains details such as game name, map name, version, player count, mod list, etc.

## See Also

- [GameInformationRequest](16-game-info-request.md)
