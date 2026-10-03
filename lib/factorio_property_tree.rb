# frozen_string_literal: true

# Factorio's PropertyTree serialization — the format of `mod-settings.dat`, and
# therefore of the mod-settings blob a joining client sends in msg 4.
#
# The spec (and a reference implementation, pinned by
# /factorio-legendary-deathworld/tools/sync-mod-settings):
#   https://codeberg.org/whitequark/factorio-data-codec
#     factorio_data.py — PropertyTree.load / ImmutableString.load
#
#   value  := [type u8][any_type u8][payload]
#     0 Null        — (nothing)
#     1 Bool        — 1 byte
#     2 Number      — f64
#     3 String      — [is_none u8][len u8 (0xFF then u32 LE)][bytes]
#     4 List        — [u32 count] then count × (key, value)
#     5 Dictionary  — [u32 count] then count × (key, value)
#     6 SignedInt   — i64
#     7 UnsignedInt — u64
#   key    := an ImmutableString: [is_none u8][len][bytes]  (is_none = 1 when present)
#
# TWO bytes of value header — that is the bit that makes the msg-4 settings
# blob parse: a boolean is `01 00 00` (type, any_type, value) and a string is
# `03 00 00 5b …`, so a reader that assumes a u32 type word walks one byte
# off and then treats the NEXT key's length byte as a value length.
#
# NOTE this is NOT the save file's own LuaValue framing (see
# FactorioSave.lua_value, which is fitted from save bytes, not from this spec).
module FactorioPropertyTree
  NULL = 0
  BOOL = 1
  NUMBER = 2
  STRING = 3
  LIST = 4
  DICTIONARY = 5
  SIGNED_INT = 6
  UNSIGNED_INT = 7
  MAX_LENGTH = 65_536 # sanity bound; the spec has no limit, real settings do

  module_function

  # An ImmutableString -> [String or nil, next_offset]; nil when malformed.
  # The leading byte is 1 for a NULL string, 0 for a present one (verified
  # against the server's own mod-settings.dat decoded with the reference
  # codec — `07 "startup"` and `00 12 "wall-repair-ignore"`).
  def string(data, at)
    return nil if at >= data.bytesize
    return [nil, at + 1] if data.getbyte(at) == 1 # a null string carries no length
    return nil if at + 2 > data.bytesize
    len = data.getbyte(at + 1)
    body = at + 2
    if len == 0xFF # long string: a u32 LE follows the 0xFF
      return nil if at + 6 > data.bytesize
      len = data.byteslice(at + 2, 4).unpack1('V')
      body = at + 6
    end
    return nil if len > MAX_LENGTH || body + len > data.bytesize
    text = data.byteslice(body, len).dup.force_encoding(Encoding::UTF_8)
    return nil unless text.valid_encoding? # a misdecode, not a name with junk in it
    [text, body + len]
  end

  # A whole mod-settings.dat envelope -> [Hash, next_offset]:
  #   version 4×u16 LE, has_quality 1 byte, then the data tree.
  # A client's msg 4 carries the DATA TREE only (no envelope) — which is why
  # the join starts straight at `05 00`.
  def mod_settings(data, at = 0)
    return nil if at + 9 > data.bytesize
    version = data.byteslice(at, 8).unpack('v4')
    has_quality = data.getbyte(at + 8) != 0
    data_tree, after = value(data, at + 9)
    return nil unless data_tree.is_a?(Hash)
    [{version: version, has_quality: has_quality, data: data_tree}, after]
  end

  # A value -> [value, next_offset]; nil when the type is unknown or the bytes
  # do not hold together (a misdecode, not an empty value).
  #
  # Tables come back as [Hash|Array, next]; entries keep their key.
  def value(data, at)
    return nil if at + 2 > data.bytesize
    type = data.getbyte(at)
    body = at + 2
    case type
    when NULL then [nil, body]
    when BOOL
      return nil if body >= data.bytesize

      [data.getbyte(body) != 0, body + 1]
    when NUMBER
      return nil if body + 8 > data.bytesize
      [data.byteslice(body, 8).unpack1('E'), body + 8]
    when STRING
      found = string(data, body)
      found && [found[0], found[1]]
    when LIST, DICTIONARY
      return nil if body + 4 > data.bytesize
      count = data.byteslice(body, 4).unpack1('V')
      return nil if count > 100_000
      i = body + 4
      out = []
      count.times do
        key = string(data, i)
        return nil unless key
        i = key[1]
        item = value(data, i)
        return nil unless item
        i = item[1]
        out << (type == DICTIONARY ? [key[0], item[0]] : item[0])
      end
      [type == DICTIONARY ? out.to_h : out, i]
    when SIGNED_INT
      return nil if body + 8 > data.bytesize
      [data.byteslice(body, 8).unpack1('q<'), body + 8]
    when UNSIGNED_INT
      return nil if body + 8 > data.bytesize
      [data.byteslice(body, 8).unpack1('Q<'), body + 8]
    end
  end
end