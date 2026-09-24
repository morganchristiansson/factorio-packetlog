# frozen_string_literal: true

# Small binary value types used by position-bearing protocol actions.
# Tile coordinates are int32 units; one tile is 256 units.
module FactorioTypes
  TilePos = Struct.new(:x, :y) do
    def self.from_data(data, offset = 0)
      return nil if offset + 8 > data.bytesize
      new(data.unpack1('i', offset: offset), data.unpack1('i', offset: offset + 4))
    end

    def to_tiles
      [x / 256.0, y / 256.0]
    end
  end

  TileRect = Struct.new(:top_left, :bottom_right) do
    def self.from_data(data, offset = 0)
      return nil if offset + 16 > data.bytesize
      new(TilePos.from_data(data, offset), TilePos.from_data(data, offset + 8))
    end
  end
end
