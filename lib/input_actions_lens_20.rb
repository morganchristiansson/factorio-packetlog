# frozen_string_literal: true

# MEASURED client→server payload lengths for the 2.0 protocol — by wire ID.
#
# Deliberately NOT in input_actions_20.rb: that file is regenerated wholesale by
# tools/dump_input_actions.rb, which would take every measured length with it
# (and reinstate the by-name-inherited lengths from the 2.1 table that this
# whole exercise exists to replace). Dumped names and measured lengths are
# different kinds of fact, kept in different files and different tools.
#
# C2S_LENS_20 — MEASURED client→server payload lengths, by wire ID.
#
# ACTIONS_20's lengths are guesses (copied from the 2.1 table by name);
# a wrong length desyncs the rest of the tick closure and turns every
# following action into garbage, which is what fills
# captures/unknown.packets-*.pcap. These were measured instead, not
# derived: every C→S heartbeat ends with an 8-byte [tick][pad] block, so
# in a closure holding a SINGLE action that action's payload is exactly
# the remaining budget (tools/measure_action_lens.rb, regenerated with
# `--emit`; observation counts in its report).
#
# They apply to client→server only — the S→C echo carries extra entity
# refs/tokens and is still unmeasured. A missing ID means "not measured",
# not "zero": the table's guess still applies there.
#
# Script/content-defined payloads (custom_input 184, translate_string
# 240) have no fixed length and are deliberately absent; the tool reports
# them instead of inventing a number.
C2S_LENS_20 = {
  3 => 0, # stop_mining
  5 => 0, # open_gui
  6 => 0, # open_character_gui
  10 => 0, # selected_entity_cleared
  14 => 0, # stop_repair
  32 => 0, # UNIDENTIFIED
  33 => 0, # UNIDENTIFIED
  50 => 0, # stop_drag_build
  54 => 0, # UNIDENTIFIED
  61 => 1, # close_gui
  63 => 2, # open_blueprint_library_gui - 6 closures (tools/measure_action_lens.rb --type)
  94 => 7, # UNIDENTIFIED - 6 closures; the name still needs /toggle-action-logging
  246 => 19, # remote_view_entity - 6 closures
  266 => 1, # flip_entity - 15 closures, no runner-up
  64 => 2, # UNIDENTIFIED
  66 => 12, # build
  67 => 16, # start_walking
  75 => 6, # open_equipment
  83 => 6, # craft
  85 => 9, # change_shooting_state
  87 => 8, # selected_entity_changed
  88 => 10, # pipette - the entity reference the cursor picked up (10 bytes,
          # 69 closures; the 1-byte read came from a content-shaped majority)
  92 => 9, # set_filter
  93 => 1, # set_spoil_priority
  95 => 11, # set_circuit_condition
  99 => 23, # set_logistic_filter_item
  101 => 2, # set_circuit_mode_of_operation
  102 => 17, # gui_click
  103 => 1, # gui_confirmed
  104 => 1, # write_to_console
  107 => 1, # change_active_item_group_for_crafting
  108 => 1, # change_active_item_group_for_filters
  116 => 25, # gui_location_changed
  127 => 23, # upgrade - 2x8-byte position records + a 7-byte entity ref
  128 => 22, # copy - 2x8-byte position records + a 7-byte entity ref
  144 => 7,  # set_ghost_cursor - 36 closures against 11 for the next candidate
          # (an earlier, unsound pass put 11 here)
  155 => 23, # cancel_deconstruct - 2x8-byte records + entity ref
  119 => 1, # use_item
  120 => 1, # send_spidertron
  124 => 16, # move_on_pan
  133 => 1, # setup_single_blueprint_record
  134 => 1, # copy_opened_blueprint
  135 => 1, # copy_large_opened_blueprint
  136 => 1, # reassign_blueprint
  137 => 1, # open_blueprint_record
  138 => 6, # grab_blueprint_record
  139 => 1, # drop_blueprint_record
  150 => 5, # export_blueprint
  151 => 1, # import_blueprint
  152 => 1, # import_blueprints_filtered
  160 => 19, # modify_decider_combinator_condition
  168 => 1, # change_programmable_speaker_alert_parameters
  184 => 25, # custom_input
  212 => 12, # UNIDENTIFIED
  231 => 4, # quick_bar_pick_slot - 4 bytes [item][slot][op][pad], NOT the
            # 0 the 2.1 table lends this name; measured 1126 single-action
            # closures against 62 for the runner-up.
  232 => 2, # quick_bar_set_selected_page
  235 => 13, # UNIDENTIFIED
  239 => 27, # lua_shortcut
  251 => 1, # selected_entity_changed_very_close
  252 => 2, # selected_entity_changed_very_close_precise
  253 => 4, # selected_entity_changed_relative
  254 => 0, # selected_entity_changed_based_on_unit_number - 0 bytes: the
          # whole action is the two header bytes (FE FF) before the trailer
  267 => 1, # fast_entity_split
  269 => 1, # trash_not_requested_items
  286 => 1, # change_active_quick_bar
  294 => 9, # render_mode_changed
  304 => 2, # set_pump_fluid_filter
  323 => 4, # gui_hover
  324 => 4, # gui_leave
  331 => 2, # UNIDENTIFIED
  # Not tool-measurable: 171/240 (parsed in code) and the two fixture
  # packets below, which are also real captures but too few to clear MIN_OBS.
  247 => 1, # close_remote_view - 1 byte, then the 8-byte trailer
  299 => 0, # clear_recipe_notification - 0 in the fixture packet; the wire also
          # shows a 2-byte form on 7 closures, so this is content-dependent
  16 => 10, # UNIDENTIFIED — name still needs /toggle-action-logging (86 closures)
  34 => 10, # UNIDENTIFIED — name still needs /toggle-action-logging (19 closures)
  56 => 10, # UNIDENTIFIED — name still needs /toggle-action-logging (29 closures)
  65 => 8, # drop_item (6643 closures)
  69 => 2, # change_riding_state (499 closures)
  71 => 16, # open_item (26 closures)
  72 => 10, # open_parent_of_opened_item (44 closures)
  73 => 8, # destroy_item (11 closures)
  76 => 16, # cursor_transfer (868 closures)
  86 => 3, # setup_assembling_machine (46 closures)
  115 => 7, # gui_switch_state_changed (39 closures)
  122 => 9, # UNIDENTIFIED — name still needs /toggle-action-logging (16 closures)
  123 => 24, # zoom_around_point (50393 closures)
  125 => 8, # start_repair (386 closures)
  126 => 23, # deconstruct (330 closures)
  153 => 7, # UNIDENTIFIED — name still needs /toggle-action-logging (50 closures)
  198 => 8, # alt_reverse_select_area (75 closures)
  199 => 8, # UNIDENTIFIED — name still needs /toggle-action-logging (87 closures)
  217 => 7, # swap_item_filters (63 closures)
  250 => 1, # change_picking_state (948 closures)
  264 => 1, # fast_entity_transfer (9484 closures)
  265 => 1, # rotate_entity (69 closures)
  289 => 1, # set_splitter_priority (23 closures)
}.freeze
