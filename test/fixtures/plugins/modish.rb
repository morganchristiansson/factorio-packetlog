# frozen_string_literal: true

# Fixture MODULE — the Hivemind shape: a module the host mixes in and calls
# by name (Plugins.mix_modules).
module Modish
  def on_join_enriched(name, _index, _attrs) = "saw #{name}"
end
