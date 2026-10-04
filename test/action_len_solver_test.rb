#!/usr/bin/env ruby
# frozen_string_literal: true

# ActionLenSolver tests.
#
# The solver is what makes C2S_LENS_20 reproducible: given a real C→S heartbeat
# and the length of every action in it EXCEPT one, it returns that one's length
# from the byte budget. The fixtures in test/fixtures/packets.rb are real
# packets, so every length the table claims is re-derived here from those bytes —
# if the table drifts from the wire, this fails.
#
# The decisive detail: a closure is walked SEQUENTIALLY, skipping each action's
# payload. An earlier version read every action's header without skipping
# payloads, so in a two-action closure the second type came from inside the first
# action's data and the arithmetic was meaningless while looking fine.
require 'minitest/autorun'
require 'mocha/minitest'
require 'factorio_protocol'
require_relative 'fixtures/packets'
require_relative '../tools/action_len_solver'

class TestActionLenSolver < Minitest::Test
  # The version-dependent tables are module state, and most tests here measure
  # against the 2.0 ones. Reset before AND after, so no 2.0 table survives into
  # another test file when they are run in one process.
  def setup
    FactorioProtocol.reset_version
  end

  def teardown
    FactorioProtocol.reset_version
  end

  def fixture(name)
    fx = REAL_PACKET_FIXTURES.find { |f| f[:name] == name }
    refute_nil fx, "fixture #{name} missing"
    [fx[:hex]].pack('H*')
  end

  def solved(name, type)
    FactorioProtocol.select_version('2.0')
    ActionLenSolver.measure_length(fixture(name), FactorioProtocol.c2s_lens || {}, type)
  end

  # ── Every measured length, re-derived from the fixture bytes ──────────
  #
  # Each of these was wrong in the table at some point, which is exactly why it
  # is re-derived rather than trusted: 88 and 66 by the by-name-inherited guess,
  # 87/102/127/128 because nothing had measured them at all.
  LENGTHS = {
    'client_pipette_ghost_item_20'      => [88, 10],  # was 9 by name, then "measured" as 1
    'client_entity_ref_upgrade_20'      => [127, 23], # was unmeasured
    'client_entity_ref_copy_20'         => [128, 22], # was unmeasured
    'client_gui_click_20'               => [102, 17], # was unmeasured
    'client_selected_entity_changed_20' => [87, 8],   # was unmeasured
  }.freeze

  def test_measured_lengths_are_reproducible_from_fixture_bytes
    LENGTHS.each do |name, (type, want)|
      assert_equal want, solved(name, type), "#{name}: action #{type} length"
    end
  end

  # build's own fixture is two builds in one closure: 12 + 12 is the whole
  # budget, which is what makes 12 (and not 9 or 24) the only reading — but the
  # SPLIT is ambiguous, so the solver refuses and the parse fixture pins it.
  def test_two_builds_fill_the_closure_but_the_split_is_ambiguous
    FactorioProtocol.select_version('2.0')
    data = fixture('client_build_x2_20')
    assert_nil solved('client_build_x2_20', 66),
               'two builds in one closure: any single reading is a guess'
    parsed = FactorioProtocol.parse_udp_payload(data)
    acts = parsed[:heartbeat][:tick_closures].first[:actions]
    assert_equal [12, 12], acts.map { |a| a[:data].bytesize }
  end

  # 254 has no payload, but its fixture is followed by 201
  # swap_infinity_container_filter_items, whose tabulated length (8) the wire
  # contradicts (6) — so the solver's answer here would be an artefact of that
  # wrong length, and the parse fixture is the evidence, not the solver.
  def test_zero_length_action_pinned_by_the_parse
    FactorioProtocol.select_version('2.0')
    parsed = FactorioProtocol.parse_udp_payload(fixture('client_selected_entity_unit_number_20'))
    acts = parsed[:heartbeat][:tick_closures].first[:actions]
    assert_equal 254, acts[0][:type]
    assert_equal '', acts[0][:data].to_s, '254 carries no payload at all'
  end

  # A closure whose actions are all unknown has no hole to fill: the solver must
  # refuse rather than hand out the whole area as one action's payload.
  def test_refuses_when_nothing_is_known
    FactorioProtocol.select_version('2.0')
    data = fixture('client_build_then_start_walking_20') # [66 build][67 start_walking]
    lens = FactorioProtocol.c2s_lens || {}
    # With neither action's length known there is no hole: the solver must not
    # hand the whole area to the first action.
    assert_nil ActionLenSolver.measure_length(data, {}, 66)
    assert_nil ActionLenSolver.measure_length(data, {}, 67)
    # With build known, the walk reaches start_walking and measures it…
    assert_equal 16, ActionLenSolver.measure_length(data, lens, 67)
    # …and symmetrically, with start_walking known, build is measurable.
    assert_equal 12, ActionLenSolver.measure_length(data, lens.reject { |t, _| t == 66 }, 66)
  end

  # build_terrain is content-defined: the parser computes its length, the 2.0
  # table claims 0, and the solver must use the parser's — otherwise the walk
  # steps into its terrain records and every later length is nonsense.
  def test_content_defined_action_comes_from_the_parser_not_the_table
    FactorioProtocol.select_version('2.0')
    data = fixture('client_build_terrain_then_nothing_20')
    assert_equal 0, FactorioProtocol::ACTIONS_20[171].last,
                 'the table really does claim 0 for build_terrain — the wrong zero this work is about'
    walk = ActionLenSolver.walk_lens_for(data, {}, 171)
    assert_equal 25, walk[171],
                 'and the walk must use the parser-derived 25, not the table\'s 0'
    assert_nil ActionLenSolver.hole_type(data, {}),
               'so the whole closure walks: build_terrain 25 + nothing 0 = the area'
  end
end
