# frozen_string_literal: true

# Reusable data structures for Factorio protocol types.
#
# Position encoding: tile coordinates are stored as int32 values
# where 1 tile = 256 units. Convert with x / 256.0 or x * 256.

module FactorioTypes
  # A tile position in the Factorio world.
  # Stored as raw int32 units (1 tile = 256).
  TilePos = Struct.new(:x, :y) do
    # Convert to tile coordinates
    def to_tiles
      [x / 256.0, y / 256.0]
    end

    def to_s
      "(#{format('%.3f', x / 256.0)}, #{format('%.3f', y / 256.0)})"
    end

    def ==(other)
      x == other.x && y == other.y
    end

    # Parse from a binary string at the given offset
    def self.from_data(data, offset = 0)
      return nil if offset + 8 > data.bytesize
      new(data.unpack1('i', offset: offset), data.unpack1('i', offset: offset + 4))
    end

    # Encode to binary
    def to_data
      [x, y].pack('i2')
    end

    # Distance to another position in tiles
    def tile_distance_to(other)
      tx1, ty1 = to_tiles
      tx2, ty2 = other.to_tiles
      Math.sqrt((tx2 - tx1) ** 2 + (ty2 - ty1) ** 2)
    end
  end

  # A rectangular area defined by top-left and bottom-right corners.
  TileRect = Struct.new(:top_left, :bottom_right) do
    def to_s
      "#{top_left}-#{bottom_right}"
    end

    def width_tiles
      ((bottom_right.x - top_left.x) / 256.0).abs
    end

    def height_tiles
      ((bottom_right.y - top_left.y) / 256.0).abs
    end

    def area_tiles
      width_tiles * height_tiles
    end

    # Parse from 16 bytes of binary data (4 × int32: x1, y1, x2, y2)
    def self.from_data(data, offset = 0)
      return nil if offset + 16 > data.bytesize
      tl = TilePos.from_data(data, offset)
      br = TilePos.from_data(data, offset + 8)
      new(tl, br)
    end

    # Encode to binary
    def to_data
      top_left.to_data + bottom_right.to_data
    end
  end

  # Entity reference (entity ID in the Factorio world).
  EntityRef = Struct.new(:id) do
    def to_s
      "##{id}"
    end

    def self.from_data(data, offset = 0)
      return nil if offset + 8 > data.bytesize
      new(data.unpack1('Q<', offset: offset))
    end
  end

  # Direction in the Factorio world (0-15).
  # 0=north, 1=northnortheast, ..., 15=northnorthwest
  DIR_NAMES = %w[
    north northnortheast northeast eastnortheast east eastsoutheast
    southeast southsoutheast south southsouthwest southwest
    westsouthwest west westnorthwest northwest northnorthwest
  ].freeze

  Direction = Struct.new(:value) do
    def name
      DIR_NAMES[value] || "dir_#{value}"
    end

    def to_s
      name
    end
  end

  # Item stack reference.
  ItemStack = Struct.new(:item_id, :count, :quality) do
    def to_s
      s = "item_#{item_id}"
      s += " x#{count}" if count && count > 1
      s += " q#{quality}" if quality && quality > 1
      s
    end
  end
end
