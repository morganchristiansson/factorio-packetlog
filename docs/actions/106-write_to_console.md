# write_to_console (Type 106)

Send a chat message or console command.

## Data Length

Variable (uint32v-prefixed string)

## Wire Format

```
Action Type:  uint16v = 106 (write_to_console)
Player Delta: uint16v = delta to previous player index
Data:         uint32v length + string bytes
```

## Notes

- Used for both chat messages and `/` commands
- The string is prefixed with a uint32v length field
- Commands like `/w` are processed by the server, not locally

## Player Index

1-indexed game player
