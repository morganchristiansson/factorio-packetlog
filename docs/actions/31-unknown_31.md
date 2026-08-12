# Unknown (Type 31)

## Status

⚠️ Not yet identified.

## Observed in Pcap

observed in pcap, format unknown

## Direction

Observed in both client→server and server→client heartbeats.

## Notes

- Not present in `defines.input_action` (internal protocol type at this ID)
- The Lua dissector (`factorio.lua`) may have a name for this type at a different index
- To help identify: perform a single known action and check if this type appears in the output
