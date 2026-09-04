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


  def test_session_players_covers_every_source_including_join_leave_only
    agent = HiveMindAgent.new(rcon: FakeRcon.new(connected: ['zoe']), api_key: 'sk-test', session_path: false, memory_dir: false)
    # chat lines (player field set)
    agent.send(:append_history, 'alice', 'hello')
    agent.send(:append_history, 'bob', 'i will build a mall')
    # join/leave lines: name lives in the MESSAGE text, player field nil
    agent.send(:append_history, nil, 'carol joined the game')
    agent.send(:append_history, nil, 'dave left the game')
    # memory injected this session (memory_prompt marks via mark_player_seen)
    agent.send(:mark_player_seen, 'erin')
    # existing on-disk player memory for a SILENT player (no session activity)
    Dir.mktmpdir do |dir|
      store = MemoryStore.new(dir)
      store.write_player('frank', 'frank likes trains')
      agent.instance_variable_set(:@memory_store, store)
      seen = agent.send(:session_players)
      # zoe is online but silent — deliberately NOT a target (never
      # appeared in the LLM session); frank is likewise NOT a target —
      # his blob exists on disk but he was silent this session, so there
      # is no new material to distill (reconsidering him would just answer
      # UNCHANGED in a wasted fork).
      %w[alice bob carol dave erin].each do |name|
        assert_includes seen, name, "expected #{name} to be seen"
      end
      refute_includes seen, 'frank', 'silent on-disk players are not targets'
      refute_includes seen, 'zoe', 'silent online players are not targets'
      # the agent's OWN replies are queued under player 'hivemind' — it is
      # not a player and must never become a compaction target
      agent.send(:append_history, 'hivemind', 'the factory watches')
      refute_includes agent.send(:session_players), 'hivemind'
    end
  end

  # Regression: agent replies are queued with player 'hivemind'; before
  # the AGENT_NAME filter they made compaction write a memories/hivemind
  # blob (and even an on-disk stray from older builds must be ignored,
  # not rewritten).
  def test_compaction_never_writes_agent_self_memory
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new(connected: ['alice']), api_key: 'sk-test', session_path: false, memory_dir: dir)
      store = agent.instance_variable_get(:@memory_store)
      store.write_player('hivemind', 'stray blob from older build')
      live = agent.instance_variable_get(:@chat)
      live.add_message(role: :user, content: 'turn: alice says hi')
      agent.send(:append_history, 'alice', 'hi hivemind')   # marks alice seen
      asked = []
      agent.define_singleton_method(:build_compaction_chat) do
        fork = super()
        fork.define_singleton_method(:ask) do |prompt|
          asked << prompt[/key "([^"]+)"/, 1]
          add_message(role: :user, content: prompt)
          add_message(role: :assistant,
                      content: prompt.include?('key "soul"') ? 'UNCHANGED' : "memory for #{prompt[/key \"([^\"]+)\"/, 1]}")
        end
        fork
      end

      assert agent.compact_memory!
      assert_equal %w[alice knowledge soul].sort, asked.sort, 'no hivemind fork'
      assert_equal 'stray blob from older build', store.player('hivemind'), 'agent blob untouched'
    end
  end


  def test_compact_memory_forks_per_key_and_leaves_live_chat_alone
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      live = agent.instance_variable_get(:@chat)
      live.add_message(role: :user, content: 'turn: alice wants to build a mall')
      live.add_message(role: :assistant, content: 'the mall will feed the factory')
      agent.send(:append_history, 'alice', 'i will build the mall')
      pre_size = live.messages.size
      forks = []

      # FORKED passes: one throwaway chat per key (soul / knowledge /
      # alice), each exercising the REAL build_compaction_chat (replay
      # logic under test); only the network call is stubbed per fork.
      # soul rewrites, knowledge replies UNCHANGED (blob exists), alice
      # gets her first memory.
      agent.instance_variable_get(:@memory_store).write_knowledge('the mall feeds the factory')
      agent.define_singleton_method(:build_compaction_chat) do
        fork = super()
        forks << fork
        fork.define_singleton_method(:ask) do |prompt|
          add_message(role: :user, content: prompt)
          reply =
            if prompt.include?('key "soul"') then 'new soul from fork'
            elsif prompt.include?('key "knowledge"') then 'UNCHANGED'
            elsif prompt.include?('key "alice"') then 'alice built the mall'
            else 'UNCHANGED'
            end
          add_message(role: :assistant, content: reply)
        end
        fork
      end

      assert agent.compact_memory!('quit'), 'compaction runs'
      assert_equal 3, forks.size, 'one fork per key: soul, knowledge, alice'

      # every fork: instructions + material + the key turn appended after
      # the REPLAYED live thread (system + live turns), all in ONE user
      # message under the LIVE system prompt (cache-prefix friendly)
      forks.each do |fork|
        roles = fork.messages.map(&:role)
        # system + replayed live thread + material message + per-key turn
        assert_equal %i[system user assistant user user assistant], roles
        assert_includes fork.messages.first.content, 'Persistent memories'
        # session material is its OWN message, byte-identical in every fork
        assert_includes fork.messages[-3].content, 'MEMORY COMPACTION pass'
        assert_includes fork.messages[-3].content, 'Current memories:'
        assert_includes fork.messages[-3].content, 'alice: i will build the mall'
        assert_includes fork.messages[-3].content, 'Players encountered this session'
      end
      # keys are asked in a stable order and named in the small divergent
      # turn (longest shared cache prefix across consecutive forks)
      assert_includes forks[0].messages[-2].content, 'key "soul"'
      assert_includes forks[1].messages[-2].content, 'key "knowledge"'
      assert_includes forks[2].messages[-2].content, 'key "alice"'

      # applied to the memory store; UNCHANGED left knowledge alone
      store = agent.instance_variable_get(:@memory_store)
      assert_equal 'new soul from fork', store.soul
      assert_equal 'the mall feeds the factory', store.knowledge
      assert_equal 'alice built the mall', store.player('alice')
      # the LIVE conversation was never touched by the passes themselves
      assert_equal pre_size, live.messages.size

      # /compact's post-success step: TRIM, not wipe. Seed enough history
      # (as if more turns had happened BEFORE compaction) to exceed the
      # char budget, mark the whole thread as "seen by the pass", then
      # trim like the sniffer handler does. Fillers are ~500 chars each:
      # message sizes vary, and the tail budget is size-based.
      20.times { |i| live.add_message(role: :user, content: "filler #{i} #{'x' * 500}")
                   live.add_message(role: :assistant, content: "ack #{i} #{'y' * 500}") }
      agent.instance_variable_set(:@compaction_included_count, live.messages.size)
      agent.trim_session_after_compaction!
      kept = live.messages
      # refreshed system prompt (memories were rewritten on disk) + a tail
      # of newest messages that fits TRIM_TAIL_CHARS (plus at least one)
      assert_equal :system, kept.first.role
      assert_operator kept.size, :>, 2, 'kept a real tail, not just the system prompt'
      body = kept[1..]
      assert_operator body.sum { |m| m.content.to_s.length }, :<=,
                      HiveMindAgent::TRIM_TAIL_CHARS + 600, 'tail fits the char budget (+1 overshoot msg)'
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
      agent.define_singleton_method(:build_compaction_chat) do
        fork = super()
        fork.define_singleton_method(:ask) do |prompt|
          add_message(role: :user, content: prompt)
          # soul succeeds; the other forks produce NOTHING usable —
          # empty reply (knowledge has a seeded blob path too, so both
          # empty and UNCHANGED-without-blob routes get exercised via
          # alice, who has no blob at all)
          reply = if prompt.include?('key "soul"') then 'new soul'
                  else ''
                  end
          add_message(role: :assistant, content: reply)
        end
        fork
      end

      refute agent.compact_memory!, 'unusable replies ⇒ failure'
      store = agent.instance_variable_get(:@memory_store)
      soul_before = store.soul
      refute agent.compact_memory!, 'still a failure'
      assert_equal soul_before, store.soul, 'nothing further written on failure'
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
      agent.schedule_followup(delay_seconds: 60, task: 'check the mall', name: 'mall')
      material = agent.send(:compaction_material)
      assert_includes material, 'Pending scheduled follow-ups:'
      assert_includes material, 'check the mall'
    end
  end

end
