# frozen_string_literal: true

module FactorioProtocol
  # Shared, verified position decoding for position-bearing input actions.
  # Single source of truth so the sniffer's console formatter, the analysis
  # tools (tools/grief_scan.rb, posmap.rb, dump_builds.rb, timeline.rb) and
  # ad-hoc scans all agree on what a position looks like.
  #
  # Corrections verified on the live 2.0.77 capture (2026-08-16); see
  # docs/protocol-notes.md:
  #   * drop_item (2.0: 65 / 2.1: 67): the 8-byte payload is a DIRECTION
  #     double (1.0, −1.0, ±√2/2 …), NOT an x,y position. Handled by
  #     .direction, not .decode.
  #   * change_shooting_state (85/87): [flag(1)][V x][V y] (unsigned, /256)
  #     — NOT signed i32 at offset 0.
  #   * zoom_around_point (123/128): its 3 doubles do NOT match
  #     player/camera positions in practice (field order/semantics
  #     unverified) — deliberately not decoded here.
  #   * move_on_pan (124/129): pos int32×2 in 1/256 tiles at offset 0.
  module Position
    module_function

    # World position(s) of a position-bearing action, in tiles.
    # Returns [x, y] for point positions (build, begin_mining_terrain,
    # move_on_pan, change_shooting_state) or [x1, y1, x2, y2] for the
    # deconstruct area. Returns nil when the action carries no decodable
    # position (or the data is truncated).
    def decode(act)
      d = act[:data]
      return nil unless d && act[:name]
      case act[:name]
      when 'build', 'begin_mining_terrain', 'move_on_pan'
        FactorioTypes::TilePos.from_data(d)&.to_tiles
      when 'change_shooting_state'
        return nil if d.bytesize < 9
        [d.unpack1('V', offset: 1) / 256.0, d.unpack1('V', offset: 5) / 256.0]
      when 'deconstruct'
        rect = FactorioTypes::TileRect.from_data(d)
        return nil unless rect
        [*rect.top_left.to_tiles, *rect.bottom_right.to_tiles]
      end
    end

    # Direction vector(s) of a direction-carrying action, as doubles.
    # start_walking → [dx, dy]; drop_item → [dx] (single double).
    # Not a world position — do not feed into position logic.
    def direction(act)
      d = act[:data]
      return nil unless d
      case act[:name]
      when 'start_walking'
        return nil if d.bytesize < 16
        [d.unpack1('E', offset: 0), d.unpack1('E', offset: 8)]
      when 'drop_item'
        return nil if d.bytesize < 8
        [d.unpack1('E', offset: 0)]
      end
    end
  end
end
