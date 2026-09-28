# frozen_string_literal: true

module FactorioProtocol
  # Quickbar input actions (2.0 wire IDs in parentheses). Single source of
  # truth for what each payload means, so the sniffer's tracker and its
  # console formatter agree.
  #
  # Measured on the 2.0.77 captures in captures/ (2026-09-25, 14 files,
  # ~500k heartbeats); see docs/protocol-notes.md.
  #
  #   quick_bar_set_slot (230) — 9 bytes:
  #     [item u8][slot u8][op u8][src u16 LE][client tick u32]
  #     op 0 = set the slot's filter, 1 = clear it. src = the inventory slot
  #     the item came from, 0xFFFF = none. The trailing u32 is the CLIENT's
  #     tick for the event — measured 15..21 ticks before the closure tick
  #     (it interpolates, so the offset wobbles).
  #     byte 0 is the ITEM, not the slot: the values it takes across the
  #     captures (0..0x25) are exactly base-game item prototype ids in
  #     prototypes.item order (0=wooden-chest, 13=splitter, 30=substation,
  #     32=pipe-to-ground, 33=pump), and byte 1 (the slot) only ever takes
  #     0 or 1. The page the slot belongs to is NOT in this action — the
  #     client announces it separately (see below).
  #
  #   quick_bar_pick_slot (231) — 4 bytes: [item u8][slot u8][op u8][pad u8]
  #     The item the player picked up / selected. op is 1 in every clean
  #     sample. Measured 4 bytes in 1126 single-action closures (runner-up
  #     62) — the 0 the 2.1 table inherited by name is wrong and used to
  #     desync the rest of every closure containing one.
  #
  #   quick_bar_set_selected_page (232) — 2 bytes: [pad u8][page u8]
  #     byte 0 is 0 in every clean sample; page is byte 1 (0..4 observed).
  #
  #   change_active_quick_bar (286) — 1 byte: [page u8]
  #
  # ponytail: the item field is read as a plain u8. No capture shows 0xFF
  # there, so an item id >= 255 (a possible 3-byte uint16v escape) has
  # never been observed; if one shows up the payload will be 11 bytes and
  # .decode returns nil rather than misrecording a slot.
  module QuickBar
    # Decode a quickbar action's payload into a hash, or:
    #   nil           — not a quickbar action at all (every other input action)
    #   :undecodable  — a quickbar action whose payload shape we do not know
    #     (see the ponytail note above); callers treat it as desync evidence
    def self.decode(act)
      d = act[:data]
      case act[:name]
      when 'quick_bar_set_slot'
        return :undecodable unless d && d.bytesize == 9
        src = d.unpack1('v', offset: 3)
        {item: d.getbyte(0), slot: d.getbyte(1), op: d.getbyte(2),
         src: (src == 0xFFFF ? nil : src), tick: d.unpack1('V', offset: 5)}
      when 'quick_bar_pick_slot'
        return :undecodable unless d && d.bytesize == 4
        {item: d.getbyte(0), slot: d.getbyte(1), op: d.getbyte(2)}
      when 'quick_bar_set_selected_page'
        d && d.bytesize >= 2 ? {page: d.getbyte(1)} : :undecodable
      when 'change_active_quick_bar'
        d && !d.empty? ? {page: d.getbyte(0)} : :undecodable
      end
    end
  end
end
