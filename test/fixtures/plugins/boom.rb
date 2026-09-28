# frozen_string_literal: true

# Fixture feature whose prerequisites are missing: constructing it raises, so
# the machinery reports it disabled instead of handing back a broken object.
class Boom
  def initialize(_host)
    raise 'no rcon, no backup'
  end
end
