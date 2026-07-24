# wire_dragging (Type 86)

Sent while a player is dragging a wire (copper or red/green wire) between
entities. This is a visual update sent to all clients so they can render
the wire being dragged in real-time.

## Data Length

Variable (custom dissector)

## Wire Format

```
Action Type:  uint16v = 86 (wire_dragging)
Player Delta: uint16v = delta to previous player index
Data:         variable length
```

## Notes

- Wire dragging is a **visual-only** update, not a game state change
- The data contains position/rendering info for the wire being dragged
- In non-verbose mode, this action is filtered out as noise
- The player ID in this action is 65535 (broadcast), not a real player —
  the rendering is synchronized for all clients

## Player Index

This action uses a special player index (65535) for broadcast rendering.
The actual player doing the dragging is tracked by the server separately.
