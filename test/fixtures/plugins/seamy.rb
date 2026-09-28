# frozen_string_literal: true

# Fixture FEATURE: a class, built with its owner, recording what it was given
# and every event it receives.
class Seamy
  def initialize(host)
    @host = host
  end

  attr_reader :host
  def on_join_enriched(name, _index, _attrs) = @host.on_join_enriched(name, 0, {})
end
