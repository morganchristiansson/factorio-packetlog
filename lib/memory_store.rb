# frozen_string_literal: true

require 'fileutils'

# Hivemind's long-term memory: keyed text blobs persisted on disk that
# survive restarts, hot reloads, and session resets. The agent (and the
# compaction model) only ever sees KEYS, never file paths:
#
#   key "soul"      → memories/SOUL.md             who Hivemind IS
#   key "knowledge" → memories/KNOWLEDGE.md        durable facts
#   key <player>    → memories/players/<name>.md   what Hivemind knows about a player
#
# Writes are atomic (tmp + rename, like the session file) and whole-blob:
# the compaction model is told to provide the COMPLETE new content each
# time, so a memory file is always self-contained. Player names are
# sanitized for the filesystem — an arbitrary key cannot escape the
# memories directory.
class MemoryStore
  DEFAULT_DIR = 'memories'
  MAX_BLOB = 20_000   # chars per memory blob (keeps injected prompts bounded)
  MAX_NAME = 80       # player-name file segment length
  SOUL_KEY = 'soul'
  KNOWLEDGE_KEY = 'knowledge'

  attr_reader :dir

  # dir: the memories directory. nil → the hardcoded default 'memories'
  # (consistent with hivemind-session.json / players.json, all cwd-relative);
  # false disables the store entirely. The constructor param exists so the
  # specs can isolate (tmpdir) or disable (false) the store — there is no
  # CLI/env override, the default is fine in production.
  def initialize(dir = nil)
    @dir = dir == false ? nil : (dir || DEFAULT_DIR)
  end

  def enabled?
    !@dir.nil?
  end

  def soul
    read_key(SOUL_KEY)
  end

  def knowledge
    read_key(KNOWLEDGE_KEY)
  end

  def player(name)
    read_key(name)
  end

  # All existing memories as {key => content} (soul, knowledge, players).
  def all
    ([SOUL_KEY, KNOWLEDGE_KEY] + player_names).filter_map do |k|
      content = read_key(k)
      [k, content] if content
    end.to_h
  end

  def player_names
    return [] unless enabled?
    dir = File.join(@dir, 'players')
    return [] unless File.directory?(dir)
    Dir.children(dir).grep(/\.md\z/).map { |f| f.delete_suffix('.md') }.sort
  end

  def write_soul(content)
    write_key(SOUL_KEY, content)
  end

  def write_knowledge(content)
    write_key(KNOWLEDGE_KEY, content)
  end

  def write_player(name, content)
    write_key(name, content)
  end

  # Map a memory key to its file: "soul" → SOUL.md, "knowledge" →
  # KNOWLEDGE.md, anything else → players/<sanitized key>.md.
  def write_key(key, content)
    return false unless enabled?
    path = path_for(key)
    return false unless path
    write(path, content)
  end

  def read_key(key)
    return nil unless enabled?
    path = path_for(key)
    return nil unless path && File.exist?(path)
    File.read(path)
  rescue StandardError => e
    warn "[hivemind] memory read failed #{path}: #{e.class}: #{e.message}"
    nil
  end

  # Seed a memory only when it does not exist yet — used to write the
  # default SOUL on first run. Never overwrites an existing/edited blob.
  def seed(key, content)
    return false unless enabled? && read_key(key).nil?
    write_key(key, content)
  end

  private

  def path_for(key)
    k = key.to_s.strip
    return nil if k.empty?
    case k.downcase
    when SOUL_KEY then File.join(@dir, 'SOUL.md')
    when KNOWLEDGE_KEY then File.join(@dir, 'KNOWLEDGE.md')
    else
      safe = k.dup.force_encoding('UTF-8').scrub('?')
              .gsub(%r{[/\\]}, '_').gsub(/\.\./, '_').gsub(/[\x00-\x1F]/, '_')
              .strip[0, MAX_NAME]
      return nil if safe.empty?
      File.join(@dir, 'players', "#{safe}.md")
    end
  end

  # Atomic whole-blob write: tmp + rename so a crash mid-write can't
  # corrupt a memory file. Content is capped at MAX_BLOB chars.
  def write(path, content)
    FileUtils.mkdir_p(File.dirname(path))
    tmp = "#{path}.tmp"
    File.write(tmp, content.to_s[0, MAX_BLOB])
    File.rename(tmp, path)
    true
  rescue StandardError => e
    warn "[hivemind] memory write failed #{path}: #{e.class}: #{e.message}"
    false
  end
end
