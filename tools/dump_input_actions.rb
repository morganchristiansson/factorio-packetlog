#!/usr/bin/env ruby
# Dump the running Factorio 2.0.x server's defines.input_action into
# lib/input_actions_20.rb (the version-dependent wire tables used by
# FactorioProtocol for 2.0 servers): ACTIONS_20 (main actions) and
# SEGMENT_TYPES_20 (input-action segments).
#
# Usage:
#   ruby tools/dump_input_actions.rb
#
# ACTIONS_20 = the server's defines.input_action + INTERNAL_20 (wire
# actions not exposed in defines — nothing, stop_walking, zoom_around_point,
# the selected_entity_changed family, … — verified with
# tools/validate_actions.rb against /toggle-action-logging output). Data
# lengths are inherited from the 2.1 ACTIONS table BY NAME (payload shapes
# are version-stable).
require_relative '../lib/server_detect'
require_relative '../lib/rcon_client'
require_relative '../lib/factorio_protocol'

# Wire actions not exposed in defines.input_action, verified by
# tools/validate_actions.rb on a live 2.0.77 server (names are the game's
# own; several IDs differ from the 2.1 table — see lib/input_actions_20.rb).
INTERNAL_20 = {
  0 => 'nothing',
  1 => 'stop_walking',
  3 => 'stop_mining',
  10 => 'selected_entity_cleared',
  14 => 'stop_repair',
  61 => 'close_gui',
  87 => 'selected_entity_changed',
  123 => 'zoom_around_point',
  124 => 'move_on_pan',
  247 => 'close_remote_view',
  251 => 'selected_entity_changed_very_close',
  252 => 'selected_entity_changed_very_close_precise',
  253 => 'selected_entity_changed_relative',
  254 => 'selected_entity_changed_based_on_unit_number',
  294 => 'render_mode_changed',
  299 => 'clear_recipe_notification',
}.freeze

out = File.expand_path('lib/input_actions_20.rb', __dir__ + '/..')
detected = ServerDetect.detect
abort 'No running factorio server found (RCON required)' unless detected[:rcon_port]
rcon = RconClient.new(host: detected[:rcon_host] || 'localhost',
                      port: detected[:rcon_port],
                      password: detected[:rcon_password])
version = rcon.server_version
abort 'Could not read server version' unless version
puts "Server: factorio #{version}"

# Full defines dump via helpers.write_file (no 4KB rcon.print cap)
rcon.command(
  '/sc local t={} for k,v in pairs(defines.input_action) do t[#t+1]=v..\'=\'..k end ' \
  'table.sort(t) helpers.write_file(\'input_actions_\'..helpers.game_version..\'.txt\', table.concat(t,\'\n\'), false, 0)'
)
sleep 1
dump = File.read(File.expand_path("~/factorio/script-output/input_actions_#{version}.txt"))
defines20 = {}
dump.lines.each do |l|
  v, k = l.strip.split('=', 2)
  defines20[v.to_i] = k if v && k
end

alen_by_name = {}
FactorioProtocol::ACTIONS.each { |id, (name, alen)| alen_by_name[name] ||= alen }

actions = (INTERNAL_20.merge(defines20)).sort.map { |id, name| "  #{id} => [#{name.inspect}, #{alen_by_name[name].inspect}]," }
segments = defines20.sort.map { |id, name| "  #{id} => #{name.inspect}," }

content = <<~RUBY
  # frozen_string_literal: true

  # Factorio 2.0.x protocol tables, dumped from a #{version} dedicated
  # server's `defines.input_action` (helpers.write_file) plus wire actions
  # verified by tools/validate_actions.rb. Regenerate with
  # `ruby tools/dump_input_actions.rb`.
  #
  # Input-action IDs are version-dependent: 2.0 and 2.1 use different
  # defines.input_action values (2.0: start_walking=67, write_to_console=104,
  # take_equipment=118; 2.1: 69, 106, 123) and different internal wire
  # actions (zoom_around_point 123 vs 128, selected_entity_changed_very_close
  # 251 vs 266, …). Verified on a live 2.0.77 server: a player walking up
  # decoded as drop_item under the 2.1 table (the walk is wire 67 =
  # start_walking per 2.0).
  #
  # ACTIONS_20 — main action types for 2.0: the defines map plus internal
  # wire actions not exposed in defines (nothing, stop_walking,
  # zoom_around_point, the selected_entity_changed family, close_gui, …).
  # Data lengths are inherited from the 2.1 ACTIONS table BY NAME (payload
  # shapes are version-stable).
  #
  # SEGMENT_TYPES_20 — input-action segment types for 2.0 (chat arrives via
  # a segment with type 104 = write_to_console; 2.1 uses 106).
  module FactorioProtocol
    ACTIONS_20 = {
  #{actions.join("\n")}
    }.freeze

    SEGMENT_TYPES_20 = {
  #{segments.join("\n")}
    }.freeze
  end
RUBY

File.write(out, content)
puts "Wrote #{actions.size} main + #{segments.size} segment entries -> #{out}"
