# frozen_string_literal: true

# Fixture feature in the alpha FAMILY (alpha.rb + alpha_extra.rb are the
# files a feature owns, for the hot reload).
class AlphaExtra
  def initialize(_host); end

  def on_join_enriched(name, _index, _attrs) = "saw #{name}"
end
