# frozen_string_literal: true

module FactorioProtocol
  # Shared binary decode primitives (varints, length-prefixed strings).
  # Mixed into both the module (`FactorioProtocol.decode_uint16v` etc. —
  # specs and legacy callers depend on those) and every packet class.
  module WireDecode
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
      return [offset + 1, nil] if offset >= data.bytesize
      val = data.getbyte(offset)
      if val == 0xFF
        return [offset + 1, nil] if offset + 5 > data.bytesize
        return [offset + 5, data.unpack1('V', offset: offset + 1)]
      end
      [offset + 1, val]
    end

    # [uint32v len][bytes] — returns [next_offset, string] or [nil, nil].
    # Strings are forced to UTF-8 + scrubbed so non-ASCII (Unicode player
    # names, game names) never leak through as binary-flagged strings — a
    # binary string with high bytes taints prompt/JSON/console assembly
    # downstream (Encoding::CompatibilityError, JSON::GeneratorError).
    def decode_string(data, offset)
      noff, len = decode_uint32v(data, offset)
      return [nil, nil] if len.nil? || noff + len > data.bytesize
      [noff + len, data[noff, len].force_encoding('UTF-8').scrub('?')]
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
