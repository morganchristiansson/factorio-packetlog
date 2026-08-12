# frozen_string_literal: true

require 'json'

# Player ID -> name mapping, persisted to a JSON file.
# IDs are 1-indexed game player indexes (protocol values are 0-indexed;
# add +1 when decoding). Survives hot reloads via the SnifferState.
class PlayerDatabase
  attr_reader :players

  def initialize(path = nil)
    @path = path
    @players = {}  # id -> name
    @id_by_name = {}  # name -> id
    load if @path && File.exist?(@path)
  end

  def lookup(id)
    @players[id] || "Player_#{id}"
  end

  def add(id, name)
    return if name.nil? || name.empty?
    @players[id.to_i] = name
    @id_by_name[name] = id.to_i
  end

  def name_to_id(name)
    @id_by_name[name]
  end

  # Remove all entries for a name except the given id (used when the
  # true game index is learned and may override peer-id-based guesses).
  def remove_other_entries_for(name, keep_id)
    @players.each do |id, n|
      if n == name && id != keep_id.to_i
        @players.delete(id)
      end
    end
    rebuild_index
  end

  def save
    return unless @path
    File.write(@path, JSON.pretty_generate(@players))
  end

  private

  def rebuild_index
    @id_by_name = {}
    @players.each { |id, name| @id_by_name[name] = id }
  end

  def load
    raw = JSON.parse(File.read(@path))
    @players = raw.each_with_object({}) { |(k, v), h|
      next unless k =~ /^\d+$/
      h[k.to_i] = v
    }
    rebuild_index
  rescue JSON::ParserError
    @players = {}
    @id_by_name = {}
  end
end
