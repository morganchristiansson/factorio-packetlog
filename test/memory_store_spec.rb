#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the Hivemind long-term memory store (keyed blobs → files).
# Run: ruby -Ilib test/memory_store_spec.rb

require 'minitest/autorun'
require 'tmpdir'
require 'memory_store'

class TestMemoryStore < Minitest::Test
  def test_disabled_store_is_noop
    store = MemoryStore.new(false)
    refute store.enabled?
    refute store.write_key('soul', 'x')
    assert_nil store.soul
    assert_empty store.all
    assert_empty store.player_names
  end

  def test_keyed_read_write_roundtrip
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      assert store.write_key('soul', 'who i am')
      assert store.write_key('knowledge', 'the bus feeds the mall')
      assert store.write_key('alice', 'alice builds malls')
      assert_equal 'who i am', store.soul
      assert_equal 'the bus feeds the mall', store.knowledge
      assert_equal 'alice builds malls', store.player('alice')
      assert_equal %w[alice], store.player_names
      assert_equal({ 'soul' => 'who i am', 'knowledge' => 'the bus feeds the mall',
                     'alice' => 'alice builds malls' }, store.all)
      assert File.exist?(File.join(dir, 'SOUL.md'))
      assert File.exist?(File.join(dir, 'KNOWLEDGE.md'))
      assert File.exist?(File.join(dir, 'players', 'alice.md'))
    end
  end

  def test_global_keys_are_case_insensitive
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      store.write_key('SOUL', 'x')
      store.write_key('Knowledge', 'y')
      assert_equal 'x', store.soul
      assert_equal 'y', store.knowledge
    end
  end

  # A player name is a key, not a path: writes must never escape the
  # memories dir, and the same key must read back what it wrote (the
  # sanitized filename is an implementation detail).
  def test_player_keys_kept_in_players_dir_and_roundtrip
    # Nested tmp root so the escape globs below never see unrelated .md
    # files that happen to share the parent dir.
    tmp_root = Dir.mktmpdir
    Dir.mktmpdir(nil, tmp_root) do |dir|
      store = MemoryStore.new(dir)
      %w[../../evil a/b ..__evil line\nbreak sévérin].each do |name|
        assert store.write_player(name, 'v')
        assert_equal 'v', store.player(name), "read-back for #{name.inspect}"
      end
      # no escape hatch anywhere
      assert_equal ['players'], Dir.children(dir)
      assert_empty Dir.glob(File.join(dir, '..', '*.md'))
      assert_empty Dir.glob(File.join(dir, '..', 'players', '*.md'))
      # newline/control chars must not create nested paths
      assert_empty Dir.glob(File.join(dir, 'players', '*', '*'))
    end
  ensure
    FileUtils.remove_entry(tmp_root) if tmp_root
  end

  def test_seed_only_when_missing
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      assert store.seed('soul', 'first')
      refute store.seed('soul', 'second')   # already exists — never overwritten
      assert_equal 'first', store.soul
      # an edited SOUL survives re-seeding (fresh store over same dir)
      store.write_soul('hand edited')
      MemoryStore.new(dir).seed('soul', 'default')
      assert_equal 'hand edited', store.soul
    end
  end

  def test_writes_are_atomic_leave_no_tmp
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      store.write_soul('content')
      store.write_player('alice', 'content')
      files = Dir.glob(File.join(dir, '**', '*.tmp')) + Dir.glob(File.join(dir, '*.tmp'))
      assert_empty files
    end
  end

  def test_content_capped_at_max_blob
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      store.write_soul('x' * (MemoryStore::MAX_BLOB + 100))
      assert_equal MemoryStore::MAX_BLOB, store.soul.length
    end
  end

  def test_empty_keys_rejected
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      refute store.write_key('', 'x')
      refute store.write_key('   ', 'x')
      assert_empty store.all
    end
  end
end