# frozen_string_literal: true

# Synthetic variations of write_to_console message payloads (type 106).
# These test FactorioProtocol.decode_chat against every documented format
# plus edge cases. `data` is an array of byte values; `expected` is the
# decoded string (or nil for empty/undecodable messages).

CHAT_DECODE_FIXTURES = [
  # ── [0x05][meta][text...] — meta = TOTAL message length (may span segments) ──
  {
    name: 'type_0x05_short',
    data: [0x05, 0x2b] + 'missing some turret coverage in the middle?'.bytes,
    expected: 'missing some turret coverage in the middle?',
  },
  {
    name: 'type_0x05_multisegment_first',
    description: 'First segment: meta is total length, text runs to end of payload',
    data: [0x05, 164] + 'I was also thinking of mod to unlock all qualities from start so there is more focus on quality. an'.bytes,
    expected: 'I was also thinking of mod to unlock all qualities from start so there is more focus on quality. an',
  },
  {
    name: 'type_0x05_continuation',
    description: 'Subsequent segment: raw continuation text, no prefix',
    data: "d there's mods that add additional quality tiers after legendary.".bytes,
    expected: "d there's mods that add additional quality tiers after legendary.",
  },
  {
    name: 'type_0x05_meta_zero',
    description: 'Zero-length message: [0x05][0x00], no text — decodes to nil (not garbage)',
    data: [0x05, 0x00],
    expected: nil,
  },

  # ── [0x0b][meta][text...] — same layout as 0x05 (observed live) ──
  {
    name: 'type_0x0b',
    description: 'Regression: 0x0b was unhandled, uint32v fallback read 0x0b=11 as text length',
    data: [0x0b, 44] + 'that nuke is not gonna be finished this hour'.bytes,
    expected: 'that nuke is not gonna be finished this hour',
  },
  {
    name: 'type_0x0b_meta_zero',
    data: [0x0b, 0x00],
    expected: nil,
  },

  # ── [0x24][meta][text...] — same layout (observed live, '$' marker) ──
  {
    name: 'type_0x24',
    description: 'Regression: 0x24 was unhandled, decoded with $ garbage prefix',
    data: [0x24, 24] + "maybe that's the reason?".bytes,
    expected: "maybe that's the reason?",
  },

  # ── [0x29][meta][text...] — same layout (observed live, ')' marker) ──
  {
    name: 'type_0x29',
    description: 'Regression: 0x29 was unhandled, decoded with ) garbage prefix',
    data: [0x29, 48] + 'vulcanus labs low on red science for some reason'.bytes,
    expected: 'vulcanus labs low on red science for some reason',
  },
  {
    name: 'type_0x29_multisegment',
    description: '0x29 with meta > segment text (split message): text runs to end of payload',
    data: [0x29, 56] + 'first segment of a longer message that continues el'.bytes,
    expected: 'first segment of a longer message that continues el',
  },

  # ── [0x04][text...] — non-segment, text to end ──
  {
    name: 'type_0x04',
    data: [0x04] + 'hello world'.bytes,
    expected: 'hello world',
  },

  # ── Server echoes: [0x00|0x3d|0x01][meta][text...] ──
  {
    name: 'server_echo_0x3d',
    data: [0x3d, 37] + 'Do we need the legendary insect eggs?'.bytes,
    expected: 'Do we need the legendary insect eggs?',
  },
  {
    name: 'server_echo_0x01',
    data: [0x01, 26] + 'spoilage may break the system'.bytes,
    expected: 'spoilage may break the system',
  },
  {
    name: 'server_echo_0x00',
    data: [0x00, 13] + 'legacy echo'.bytes,
    expected: 'legacy echo',
  },

  # ── Localized string (protobuf-like) ──
  {
    name: 'localized_literal',
    description: 'mode=2 (Literal): key is the text',
    data: [0x03] + 'abc'.bytes + [0x02, 0x00],
    expected: 'abc',
  },
  {
    name: 'localized_empty',
    description: 'mode=0 (Empty) with non-empty key (first byte must not collide with a prefix format)',
    data: [0x03] + 'abc'.bytes + [0x00, 0x00],
    expected: '',
  },

  # ── Main action list format: [uint32v len][text] ──
  {
    name: 'uint32v_prefixed',
    data: [13] + 'short message'.bytes,
    expected: 'short message',
  },

  # ── Raw text (no prefix) ──
  {
    name: 'raw_text',
    data: 'raw text here'.bytes,
    expected: 'raw text here',
  },

  # ── Empty / undecodable input ──
  {
    name: 'empty_data',
    data: [],
    expected: nil,
  },
].freeze
