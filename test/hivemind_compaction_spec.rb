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


  def test_compact_memory_parses_json_reply_and_leaves_live_chat_alone
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      live = agent.instance_variable_get(:@chat)
      live.add_message(role: :user, content: 'turn: alice wants to build a mall')
      live.add_message(role: :assistant, content: 'the mall will feed the factory')
      agent.send(:append_history, 'alice', 'i will build the mall')
      pre_size = live.messages.size
      seen = { prompt: nil }

      # The pass runs on a THROWAWAY chat (build_compaction_chat) that
      # replays the live thread; stub its ask to simulate the model reply.
      # Exercise the REAL build_compaction_chat (replay logic under test);
      # only the network call is stubbed on the resulting throwaway chat.
      pass = nil
      agent.define_singleton_method(:build_compaction_chat) do
        pass = super()
        pass.define_singleton_method(:ask) do |prompt|
          seen[:prompt] = prompt
          add_message(role: :user, content: prompt)
          add_message(role: :assistant, content:
            "Reviewed the session.\n\n```json\n" \
            '[{"key": "soul", "content": "new soul from json"}, ' \
            '{"key": "alice", "content": "alice built the mall"}]\n```')
        end
        pass
      end

      assert agent.compact_memory!('quit'), 'compaction runs'

      # prompt = instructions + material on ONE user turn (cache-prefix
      # friendly: system prompt unchanged, whole replayed thread cached)
      assert_includes seen[:prompt], 'MEMORY COMPACTION pass'
      assert_includes seen[:prompt], 'fenced code block'
      assert_includes seen[:prompt], 'Current memories:'
      assert_includes seen[:prompt], 'alice: i will build the mall'
      # the pass chat REPLAYED the live thread under the live system prompt
      assert_equal %i[system user assistant user assistant], pass.messages.map(&:role)
      assert_includes pass.messages.first.content, 'Persistent memories'

      # the parsed block was APPLIED to the memory store
      store = agent.instance_variable_get(:@memory_store)
      assert_equal 'new soul from json', store.soul
      assert_equal 'alice built the mall', store.player('alice')
      # the LIVE conversation was never touched by the pass itself
      assert_equal pre_size, live.messages.size

      # /compact's post-success step: TRIM, not wipe. Seed enough history
      # (as if more turns had happened BEFORE compaction) to exercise the
      # keep-last window, mark the whole thread as "seen by the pass",
      # then trim like the sniffer handler does.
      20.times { |i| live.add_message(role: :user, content: "filler #{i}")
                   live.add_message(role: :assistant, content: "ack #{i}") }
      agent.instance_variable_set(:@compaction_included_count, live.messages.size)
      agent.trim_session_after_compaction!
      kept = live.messages
      # refreshed system prompt (memories were rewritten on disk) + the
      # TRIM_KEEP_LAST tail kept for conversational flow
      assert_equal 1 + 12, kept.size
      assert_equal :system, kept.first.role
      assert_equal :assistant, kept.last.role
      kept.each { |m| refute_includes m.content.to_s, 'alice wants to build' } # compacted range gone
      assert kept.any? { |m| m.content.to_s.include?('filler') }, 'recent tail kept for flow'
    end
  end

  def test_compact_memory_fails_on_unparsable_reply_and_keeps_session
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      live = agent.instance_variable_get(:@chat)
      live.add_message(role: :user, content: 'turn: alice says hi')
      agent.send(:append_history, 'alice', 'hivemind hello')
      pre_size = live.messages.size
      pass = RubyLLM.chat(model: 'test', provider: :openai, assume_model_exists: true)
      agent.define_singleton_method(:build_compaction_chat) { pass }
      pass.define_singleton_method(:ask) do |prompt|
        add_message(role: :user, content: prompt)
        add_message(role: :assistant, content: 'I could not decide what to write.')
      end

      refute agent.compact_memory!, 'unparsable reply ⇒ failure'
      store = agent.instance_variable_get(:@memory_store)
      soul_before = store.soul
      refute agent.compact_memory!, 'still a failure'
      assert_equal soul_before, store.soul, 'nothing written on failure'
      assert_nil store.player('alice'), 'no player memory written on failure'
      assert_equal pre_size, live.messages.size, 'live conversation never touched'
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
