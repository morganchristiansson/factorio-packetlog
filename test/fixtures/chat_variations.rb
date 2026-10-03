# frozen_string_literal: true

# write_to_console message payloads (segment type 104 in 2.0, 106 in 2.1)
# as FactorioProtocol.decode_chat must read them.
#
# The wire shape is [uint16v player][uint32v len][text] — the sender's
# 0-based index (0xff-escaped past 254) and the FULL message length. The
# `data` entries are hex of REAL payloads taken from captures/ (2026-10-03,
# 2.0.77) unless the entry says `synthetic`; `expected` is the decoded
# string (nil for an empty message).
#
# The escaped-player cases are the regression: the index was read as a
# 5-byte uint32v escape, so 82 of the 255 chat messages in that capture set
# decoded as "?d\u0001$mod bug or are we talking actual bug".

CHAT_DECODE_FIXTURES = [
  # ── escaped player index: [ff][u16 LE][uint32v len][text] ──────────
  {
    name: 'escaped_player_356',
    description: 'captures/server-34197-20261003-170056.pcap.gz pkt 413385 (player 357): the 0xff escape read as a 5-byte uint32v length is what printed the "?d" prefix',
    data: 'ff6401246d6f6420627567206f72206172652077652074616c6b696e672061637475616c20627567',
    expected: 'mod bug or are we talking actual bug',
  },
  {
    name: 'escaped_player_318_short',
    description: 'the smallest escaped case: player 319 says "hi"',
    data: 'ff3e01026869',
    expected: 'hi',
  },
  {
    name: 'escaped_player_359',
    data: 'ff67010e74686174732061207468696e673f',
    expected: 'thats a thing?',
  },
  {
    name: 'escaped_player_295',
    data: 'ff27012b7468696e6b207765206861766520656e6f7567682068657265205b6770733d3132312e392c3832362e355d',
    expected: 'think we have enough here [gps=121.9,826.5]',
  },
  {
    name: 'escaped_player_266_long',
    description: 'a 111-byte message from player 267 — the escaped index must not be mistaken for the length either',
    data: 'ff0a016f69742077696c6c20737061776e20612073746f6d7065722070656e7461706f642e20496620796f752061' \
           '7265206e6f7420737572726f756e6465642062792067756e207475727265747320796f752077696c6c206e6f742062' \
           '652061626c6520746f206669676874206974206f6666',
    expected: 'it will spawn a stomper pentapod. If you are not surrounded by gun turrets you will not be able to fight it off',
  },
  {
    name: 'escaped_player_empty',
    description: '[ff][u16 LE][0x00] — a zero-length message decodes to nil, never to the header bytes',
    data: 'ff3e0100',
    expected: nil,
  },

  # ── plain player index (1 byte, < 254) ────────────────────────────
  {
    name: 'player_11',
    description: 'same shape as the escaped cases, index below the escape',
    data: '0b2c74686174206e756b65206973206e6f7420676f6e6e612062652066696e6973686564207468697320686f7572',
    expected: 'that nuke is not gonna be finished this hour',
  },
  {
    name: 'player_0',
    description: 'player index 0 — a zero byte is a length, not an empty payload',
    data: '000b6c6567616379206563686f',
    expected: 'legacy echo',
  },
  {
    name: 'player_4_long_length',
    description: 'synthetic: length itself needs the 0xff escape (>= 255) — the 5-byte uint32v form after a 1-byte player',
    data: "04ff2a010000#{'48' * 298}",
    expected: 'H' * 298,
  },

  # ── lone continuation segment: raw text, no header ─────────────────
  # (the sniffer merges these — chat_action_data — before decoding)
  {
    name: 'continuation_raw_text',
    data: '776f6f7073',
    expected: 'woops',
  },
  {
    name: 'continuation_space_initial',
    description: 'a fragment can start with any text byte, including 0x24/0x2d/0x30 — the old slot-enumerating decoder mangled these',
    data: '2d206f6e6c79206c61746572',
    expected: '- only later',
  },

  # ── localized string (protobuf-like) — server-side formats ────────
  {
    name: 'localized_literal',
    description: 'mode=2 (Literal): key is the text',
    data: '036162630200',
    expected: 'abc',
  },
  {
    name: 'localized_empty',
    description: 'mode=0 (Empty) with a non-empty key',
    data: '036162630000',
    expected: '',
  },

  # ── [uint32v len][text] — main-action-list form ────────────────────
  {
    name: 'uint32v_prefixed',
    data: "0d#{'short message'.unpack1('H*')}",
    expected: 'short message',
  },

  # ── raw text (no prefix) ──────────────────────────────────────────
  {
    name: 'raw_text',
    data: '72617720746578742068657265',
    expected: 'raw text here',
  },

  # ── empty input ───────────────────────────────────────────────────
  {
    name: 'empty_data',
    data: '',
    expected: nil,
  },
].freeze