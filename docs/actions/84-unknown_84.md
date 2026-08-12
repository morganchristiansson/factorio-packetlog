# Unknown (Type 84)

## Status

⚠️ Not yet identified.

## Observed in Pcap

server→client 12 bytes after delta (likely wire dragging visual data)

## Direction

Observed in both client→server and server→client heartbeats.

## Notes

- Not present in `defines.input_action` (internal protocol type at this ID)
- The Lua dissector (`factorio.lua`) may have a name for this type at a different index
- To help identify: perform a single known action and check if this type appears in the output
