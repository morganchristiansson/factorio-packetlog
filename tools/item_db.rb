#!/usr/bin/env ruby
# Regenerate external/item_prototypes_runtime.txt + entity_prototypes_runtime.txt
# from a live server via RCON.
#
# The wire protocol references prototypes by 1-indexed ID in iteration order:
#   - items:    `prototypes.item`    (pipette src=0, cursor_transfer, stack_transfer, ...)
#   - entities: `prototypes.entity`  (pipette src=4 — e.g. 87=stone-furnace, 149=iron-ore)
# This dumps ID -> name for both so the sniffer can resolve ids offline.
#
# Mechanics (see docs/rcon-knowledge.md): one /sc one-liner writes both lists
# to the server's script-output dir via helpers.write_file (no 4KB response
# cap), then the files are read back. Run on the server host:
#
#   ruby tools/item_db.rb                 # writes external/*_prototypes_runtime.txt
#   ruby tools/item_db.rb /tmp/items.txt  # custom output path (items only)
#
# Override RCON host/port/password with RCON_HOST / RCON_PORT / RCON_PASSWORD.
require_relative "../lib/server_detect"
require_relative "../lib/rcon_client"

detected = ServerDetect.detect
if detected.empty?
  warn "No running factorio process detected; set RCON_HOST/RCON_PORT/RCON_PASSWORD"
  exit 1
elsif !detected[:rcon_port]
  warn "Detected factorio pid #{detected[:pid]} but no RCON endpoint — is it a dedicated server with rcon enabled?"
  exit 1
end

rcon = RconClient.new(host: detected[:rcon_host] || "localhost",
                      port: detected[:rcon_port],
                      password: detected[:rcon_password],
                      script_output_dir: ServerDetect.script_output_dir(detected[:pid]))
sod = rcon.script_output_dir
abort "Cannot locate script-output dir for factorio pid #{detected[:pid]}" unless sod

rcon.dump_prototype_files

items_f = File.join(sod, "factorio-sniffer-items.txt")
abort "Item dump failed — no file at #{items_f}" unless File.exist?(items_f) && File.size(items_f) > 0
out = ARGV[0] || File.expand_path("../external/item_prototypes_runtime.txt", __dir__)
File.write(out, File.read(items_f))
puts "Wrote #{File.readlines(items_f).size} items to #{out}"

unless ARGV[0]
  ents_f = File.join(sod, "factorio-sniffer-entities.txt")
  if File.exist?(ents_f) && File.size(ents_f) > 0
    out = File.expand_path("../external/entity_prototypes_runtime.txt", __dir__)
    File.write(out, File.read(ents_f))
    puts "Wrote #{File.readlines(ents_f).size} entities to #{out}"
  else
    warn "Entity dump failed — no file at #{ents_f}"
  end
end
