# frozen_string_literal: true

require_relative '../../factorio_wire'

module FactorioProtocol
  # Shared binary decode primitives (varints, length-prefixed strings).
  # Mixed into both the module (`FactorioProtocol.decode_uint16v` etc. —
  # specs and legacy callers depend on those) and every packet class.
  #
  # The shared binary primitives (FactorioWire) as instance methods, plus the
  # names the packet classes read with. The string container is the SAME
  # `[length][bytes]` shape the save uses, with no terminator on the wire; a
  # failed read is nil — a misdecode, never a scrubbed guess — so the caller
  # can keep the frame for later analysis instead of logging garbage.
  module WireDecode
    include FactorioWire # string_at / varint_at, inherited

    # [uint16v] — 1 byte, or 3 when the first byte is 0xFF (u16 follows).
    # Returns [next_offset, value] or [offset + 1, nil] when truncated.
    def decode_uint16v(data, offset)
      return [offset + 1, nil] if offset >= data.bytesize
      val = data.getbyte(offset)
      if val == 0xFF
        return [offset + 1, nil] if offset + 3 > data.bytesize
        return [offset + 3, data.unpack1('v', offset: offset + 1)]
      end
      [offset + 1, val]
    end

    # [uint32v] — 1 byte, or 5 when the first byte is 0xFF (u32 follows).
    def decode_uint32v(data, offset)
      # A truncated read must still hand back a USABLE offset: the callers do
      # `offset = v_off` and then compare/parse from there, so [nil, nil]
      # (which is what FactorioWire.varint returns out of bounds) would blow up
      # with NoMethodError on a malformed packet instead of failing the read.
      after, value = varint_at(data, offset)
      [after || offset + 1, value]
    end

    # [uint32v len][bytes] — returns [next_offset, string] or [nil, nil].
    # Strings are forced to UTF-8; INVALID UTF-8 is a misdecode (nil), not a
    # scrubbed string — a scrubbed name would silently become a different
    # player. Callers turn that into a kept frame (unknown.packets).
    def decode_string(data, offset, allow_empty: false)
      found = string_at(data, offset, allow_empty: allow_empty)
      found ? [found[1], found[0]] : [nil, nil]
    end
  end

  # Base class for one network message (msg_type 0-18) from the wire.
  #
  # Subclasses implement #parse and populate #result — the hash shape the
  # rest of the codebase consumes (sniffer, fixtures, specs):
  #   { header: {...}, <msg-specific key>: {...} }
  #
  # Inheritance is used for genuinely shared behavior: header parsing,
  # the wire-decode mixin, and the parse lifecycle.
  class FactorioPacket
    include WireDecode

    attr_reader :data, :header, :result

    def self.parse(data)
      new(data).parse
    end

    def initialize(data)
      @data = data
      @result = nil
    end

    # Parse the network header (flags byte, optional message_id/fragments)
    # and dispatch to the subclass body. Returns self; callers read #result.
    def parse
      @header = FactorioProtocol.parse_network_header(@data)
      raise "not a factorio packet" unless @header
      @result = { header: @header }
      parse_body
      self
    end

    private

    def parse_body
      raise NotImplementedError
    end
  end
end
