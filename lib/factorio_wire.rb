# frozen_string_literal: true

# The binary primitives BOTH Factorio wire formats are read with: the
# length-prefixed string and the variable-length integer. The UDP protocol and
# the save file use the same container, tuned differently:
#
#   packets  uint32v length (0xFF then a u32 LE), NO terminator — the
#            protocol is built to save bytes
#   save     the same varint length, NUL TERMINATED (and consumed)
#
# So one reader, one switch: `terminator:` is the only difference, and the
# reader cannot be fooled into the wrong one — a missing terminator, a length
# past the end, or bytes that are not valid UTF-8 all return nil.
#
# nil means "this is not a string here" — a MISDECODE, not an empty string.
# A caller on the packet path must act on it (keep the frame in
# captures/unknown.packets-*.pcap); the save path reports it as a missing
# field.
#
# USED AS A BASE, not a namespace: `extend FactorioWire` gives a module
# (FactorioSave, FactorioProtocol) the module-level reader, and
# `include FactorioWire` gives the packet classes an instance-level one
# (FactorioProtocol::WireDecode), so no caller has to spell out a namespace.
module FactorioWire
  ESCAPE = 0xFF # varint escape: the real length follows as a u32 LE
  # Nothing in either format is longer than this: a username, a mod name, a
  # tag, a locale, a mod setting key. A length past it is a misdecode.
  MAX_LENGTH = 4096

  # Instance-level entry points, for `include`ers (the packet classes) — the
  # module-level pair below is `def self.`, not `module_function`, which
  # would quietly turn these into private methods.
  def varint_at(data, at)
    FactorioWire.varint(data, at)
  end

  # `allow_empty:` for fields that legitimately carry an empty string — the
  # msg-4 session token and timestamp are empty on a client's FIRST join.
  def string_at(data, at, terminator: nil, allow_empty: false)
    FactorioWire.string_at(data, at, terminator: terminator, allow_empty: allow_empty)
  end

  # Factorio's variable-length integer: one byte below 0xFF, else 0xFF + a
  # u32 LE (5 bytes total). => [offset_after, value] or [nil, nil]
  def self.varint(data, at)
    head = data.getbyte(at)
    return [nil, nil] if head.nil?
    return [at + 1, head] unless head == ESCAPE
    return [nil, nil] if at + 5 > data.bytesize
    [at + 5, data.unpack1('V', offset: at + 1)]
  end

  # [length][bytes] at `at`.
  #   terminator: nil — none (the packet protocol)
  #               0   — expect a NUL and consume it (the save format)
  # => [String, offset_after] or nil (truncated, over-long, empty, not UTF-8,
  #    or a missing terminator).
  def self.string_at(data, at, terminator: nil, allow_empty: false)
    after, length = varint(data, at)
    return nil if length.nil?
    return nil if length.zero? && !allow_empty # a zero length is a nil field
    return nil if length > MAX_LENGTH || after + length > data.bytesize
    terminator_at = after + length
    if terminator
      return nil unless data.getbyte(terminator_at) == terminator
      terminator_at += 1
    end
    text = data.byteslice(after, length).dup.force_encoding(Encoding::UTF_8)
    return nil unless text.valid_encoding? # scrubbed text is a misdecode, not a name
    [text, terminator_at]
  end
end
