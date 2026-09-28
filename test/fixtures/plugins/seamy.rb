# frozen_string_literal: true

# Fixture feature that hooks a host seam: a host includes its no-op seams
# first, so a module included after it overrides the ones it uses.
module Seamy
  def on_join_enriched(name, _index, _attrs) = "saw #{name}"
end
