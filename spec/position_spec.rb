#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the shared position decoder (FactorioProtocol::Position) — the
# single source of truth used by the sniffer formatter AND the analysis
# tools. Locks in the verified corrections from the 2026-08-16 session:
#   * change_shooting_state = [flag(1)][V x][V y] (unsigned /256)
#   * drop_item = direction double, NOT a position
#   * zoom_around_point deliberately NOT decoded as a position
# Run: ruby -Ilib spec/position_spec.rb

require 'minitest/autorun'
require 'factorio_protocol'

class TestPosition < Minitest::Test
  def act(name, data)
    { name: name, data: data ? data.dup.force_encoding('BINARY') : nil }
  end

  # ── build ────────────────────────────────────────────────────────

  def test_build_positive_tile
    # (558.5, 85.5) = raw i32 142976, 21888 LE + dir byte 0
    data = [0x80, 0x2e, 0x02, 0x00, 0x80, 0x55, 0x00, 0x00, 0x00].pack('C*')
    assert_equal [558.5, 85.5], FactorioProtocol::Position.decode(act('build', data))
  end

  def test_build_negative_tile
    # (-1.5, 19.5) = raw -384, 4992 LE
    data = [0x80, 0xfe, 0xff, 0xff, 0x80, 0x13, 0x00, 0x00, 0x00].pack('C*')
    assert_equal [-1.5, 19.5], FactorioProtocol::Position.decode(act('build', data))
  end

  def test_build_truncated_returns_nil
    data = [0x80, 0x2e, 0x02].pack('C*')
    assert_nil FactorioProtocol::Position.decode(act('build', data))
  end

  # ── change_shooting_state ────────────────────────────────────────

  def test_shooting_state_unsigned_layout
    # [flag 0x01][V x 142976][V y 21248] → (558.5, 83.0)
    data = [0x01, 0x80, 0x2e, 0x02, 0x00, 0x00, 0x53, 0x00, 0x00].pack('C*')
    assert_equal [558.5, 83.0], FactorioProtocol::Position.decode(act('change_shooting_state', data))
  end

  def test_shooting_state_negative_byte_is_not_signed_error
    # flag 0x80 (high bit set) must not break the x/y read at offsets 1/5
    data = [0x80, 0x80, 0x2e, 0x02, 0x00, 0x00, 0x53, 0x00, 0x00].pack('C*')
    assert_equal [558.5, 83.0], FactorioProtocol::Position.decode(act('change_shooting_state', data))
  end

  # ── deconstruct ──────────────────────────────────────────────────

  def test_deconstruct_area
    # (0,0)-(16,16) in tiles
    data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0x10, 0, 0].pack('C*')
    assert_equal [0.0, 0.0, 16.0, 16.0], FactorioProtocol::Position.decode(act('deconstruct', data))
  end

  # ── drop_item is NOT a position ──────────────────────────────────

  def test_drop_item_is_not_decoded_as_position
    # The old formatter read this as i32×2 and printed a bogus pos.
    # Verified: the payload is a direction double (1.0 = east).
    data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f].pack('C*') # double 1.0
    assert_nil FactorioProtocol::Position.decode(act('drop_item', data))
    assert_equal [1.0], FactorioProtocol::Position.direction(act('drop_item', data))
  end

  def test_start_walking_direction
    # (0.7071067811865476, 0.7071067811865476) = southeast
    data = [0xcc, 0x3b, 0x7f, 0x66, 0x9e, 0xa0, 0xe6, 0x3f] * 2
    dir = FactorioProtocol::Position.direction(act('start_walking', data.pack('C*')))
    assert_in_delta 0.70710678, dir[0], 1e-6
    assert_in_delta 0.70710678, dir[1], 1e-6
    assert_nil FactorioProtocol::Position.decode(act('start_walking', data.pack('C*')))
  end

  # ── zoom_around_point deliberately excluded ──────────────────────

  def test_zoom_around_point_not_decoded
    # 24-byte payload (3 doubles). Not a position source until the field
    # order is verified — must stay nil so tools never consume it.
    data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xbf] * 3
    assert_nil FactorioProtocol::Position.decode(act('zoom_around_point', data.pack('C*')))
  end

  # ── generic ──────────────────────────────────────────────────────

  def test_unknown_or_dataless_returns_nil
    assert_nil FactorioProtocol::Position.decode(act('nothing', nil))
    assert_nil FactorioProtocol::Position.decode(act('begin_mining', ''.b))
    assert_nil FactorioProtocol::Position.decode(act('begin_mining', nil))
  end
end
