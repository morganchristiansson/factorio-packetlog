#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for long-term memory (hivemind_compaction.rb + MemoryStore seeding): SOUL/knowledge prompts, compaction pass.
# Run: ruby -Ilib test/hivemind_compaction_spec.rb

require_relative 'hivemind_helper'

class TestHivemindCompaction < Minitest::Test
  include HivemindSpecHelpers

  def setup
    @agent = make_agent
  end


  # ── Long-term memory (keyed blobs, compaction) ─────────────────

  def test_soal_seeded_on_first_run_only
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      store = agent.instance_variable_get(:@memory_store)
      assert_equal HiveMindAgent::DEFAULT_SOUL, store.soul, 'SOUL seeded from the default personality'
      # An existing/edited SOUL is never overwritten by a new process.
      store.write_soul('the factory regained its voice')
      HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      assert_equal 'the factory regained its voice', store.soul
    end
  end


  def test_system_prompt_includes_soul_and_knowledge
    Dir.mktmpdir do |dir|
      # Seed BEFORE init so the applied system prompt (built at configure_llm)
      # reflects the store at conversation creation.
      store = MemoryStore.new(dir)
      store.seed('soul', 'my custom soul')
      store.write_knowledge('the bus feeds the mall')
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      sys = agent.instance_variable_get(:@chat).messages.find { |m| m.role == :system }
      content = sys.content.to_s
      # SOUL (personality) and KNOWLEDGE (facts) live in the SYSTEM prompt
      # (not the per-turn user prompt) — cached once per conversation.
      assert_includes content, 'my custom soul'
      assert_includes content, '=== SOUL ==='
      assert_includes content, 'the bus feeds the mall'
      assert_includes content, '=== KNOWLEDGE ==='
      # the static mechanics are still there too
      assert_includes content, 'rcon_query'
    end
  end


  def test_turn_prompt_injects_player_memory_with_dedup
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      store = agent.instance_variable_get(:@memory_store)
      store.write_player('alice', 'alice is building the mall')

      p1 = agent.send(:turn_prompt, 'INSTRUCTION ONE', player: 'alice')
      assert_includes p1, 'Persistent player memories:'
      assert_includes p1, '=== memory of alice ==='
      assert_includes p1, 'alice is building the mall'
      assert_equal 1, p1.scan('alice is building the mall').size
      refute_includes p1, '=== SOUL ==='  # globals ride in the system prompt, not per turn

      # Same player again this session: their memory was already delivered
      # (it sits in the conversation now) — no repeat.
      p2 = agent.send(:turn_prompt, 'INSTRUCTION TWO', player: 'alice')
      refute_includes p2, '=== memory of alice ==='

      # A different player still gets their own memory.
      store.write_player('bob', 'bob guards the iron')
      p3 = agent.send(:turn_prompt, 'INSTRUCTION THREE', player: 'bob')
      assert_includes p3, '=== memory of bob ==='
      assert_includes p3, 'bob guards the iron'
    end
  end


  # Already-online players never fire a join event, so a fresh session must
  # seed their memories from the roster — otherwise they'd be unreachable.
  def test_fresh_session_seeds_online_players_memories
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new(connected: ['alice', 'carol']),
                                api_key: 'sk-test', session_path: false, memory_dir: dir)
      store = agent.instance_variable_get(:@memory_store)
      store.write_player('alice', 'alice builds malls')
      store.write_player('carol', 'carol hoards circuits')
      store.write_player('bob', 'bob is offline')  # not online — not seeded

      prompt = agent.send(:turn_prompt, 'INSTRUCTION')
      assert_includes prompt, '=== memory of alice ==='
      assert_includes prompt, '=== memory of carol ==='
      refute_includes prompt, 'bob is offline'

      # second turn: the roster was already delivered — no repeats
      prompt2 = agent.send(:turn_prompt, 'INSTRUCTION 2')
      refute_includes prompt2, '=== memory of'
    end
  end


  def test_ask_llm_injects_triggering_players_memory
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.instance_variable_get(:@memory_store).write_player('alice', 'alice owes the factory a rocket')
      prompt = capture_prompt(agent) { agent.send(:ask_llm, 'alice', 'hivemind whats my build plan?') }
      assert_includes prompt, '=== memory of alice ==='
      assert_includes prompt, 'alice owes the factory a rocket'
    end
  end


  def test_players_seen_covers_every_source_including_join_leave_only
    agent = HiveMindAgent.new(rcon: FakeRcon.new(connected: ['zoe']), api_key: 'sk-test', session_path: false, memory_dir: false)
    # chat lines (player field set)
    agent.send(:append_history, 'alice', 'hello')
    agent.send(:append_history, 'bob', 'i will build a mall')
    # join/leave lines: name lives in the MESSAGE text, player field nil
    agent.send(:append_history, nil, 'carol joined the game')
    agent.send(:append_history, nil, 'dave left the game')
    # memory injected this session
    agent.instance_variable_get(:@memories_sent) << 'erin'
    # existing on-disk player memory
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      store.write_player('frank', 'frank likes trains')
      agent.instance_variable_set(:@memory_store, store)
      seen = agent.send(:players_seen)
      %w[alice bob carol dave erin frank zoe].each do |name|
        assert_includes seen, name, "expected #{name} to be seen"
      end
    end
  end


  def test_compact_memory_runs_inside_live_chat_with_batched_tool
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      chat = agent.instance_variable_get(:@chat)
      chat.add_message(role: :user, content: 'turn: alice wants to build a mall')
      chat.add_message(role: :assistant, content: 'the mall will feed the factory')
      agent.send(:append_history, 'alice', 'i will build the mall')
      pre_size = chat.messages.size

      # Compaction reuses the LIVE chat (input-token cache); stub only the
      # parts that would hit the network, and simulate the tool-call + result
      # messages the real ask would append (which compaction must strip).
      seen = { instructions: [], tools: [], material: nil }
      chat.define_singleton_method(:with_instructions) { |t| seen[:instructions] << t; self }
      chat.define_singleton_method(:with_tool) { |t| seen[:tools] << t; self }
      chat.define_singleton_method(:ask) do |material|
        seen[:material] = material
        add_message(role: :user, content: material)         # compaction material
        add_message(role: :assistant, content: nil, tool_calls: {}) # tool-call turn
        add_message(role: :tool, content: 'soul updated', tool_call_id: 'c1')
      end

      assert agent.compact_memory!('quit'), 'compaction runs'

      assert_equal 1, seen[:tools].size, 'only write_memories — never say/rcon_query'
      assert_kind_of WriteMemories, seen[:tools].first
      # compaction swapped its own system prompt in, then restored the live one
      assert_includes seen[:instructions].first, 'write_memories'
      assert_includes seen[:instructions].first, 'Batch ALL updates into ONE'
      assert_includes seen[:instructions].last, 'Persistent memories'  # restored live prompt
      # material = current memories + console + context; the conversation
      # thread itself is already in the chat (not duplicated in the material)
      assert_includes seen[:material], 'Current memories:'
      assert_includes seen[:material], '=== soul ==='
      assert_includes seen[:material], 'Console lines:'
      assert_includes seen[:material], 'alice: i will build the mall'
      assert_includes seen[:material], 'Players encountered this session'
      assert_includes seen[:material], 'alice'          # from the console line
      refute_includes seen[:material], 'Session conversation:'
      # compaction stripped its own messages: the live thread is unchanged
      assert_equal pre_size, chat.messages.size
      # and write_memories is gone from the live toolset
      refute_includes chat.tools.keys, :write_memories
      assert chat.tools.key?(:reply)
      assert chat.tools.key?(:rcon_query)
    end
  end


  def test_compact_skips_empty_session
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      refute agent.compact_memory!, 'nothing to compact'
      refute agent.send(:compactable?)
    end
  end


  def test_compaction_material_lists_pending_followups
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.schedule_followup(delay_seconds: 60, task: 'check the mall')
      material = agent.send(:compaction_material)
      assert_includes material, 'Pending scheduled follow-ups:'
      assert_includes material, 'check the mall'
    end
  end

end
