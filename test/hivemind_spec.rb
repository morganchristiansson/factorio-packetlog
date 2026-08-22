#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the HiveMindAgent core (lib/hivemind.rb): triggers, chat
# history/context assembly, player events and greetings.
# Tool, persistence, compaction, and follow-up specs are separate files.
# Run: ruby -Ilib test/hivemind_spec.rb

require_relative 'hivemind_helper'
class TestHiveMindAgent < Minitest::Test
  include HivemindSpecHelpers

  def setup
    @agent = make_agent
  end


  # ── Rolling chat history ──────────────────────────────────────

  def test_on_chat_appends_to_history
    @agent.on_chat('alice', 'hey hivemind')
    @agent.on_chat('bob', 'nice base')
    history = @agent.instance_variable_get(:@console_queue)
    assert_equal [['alice', 'hey hivemind'], ['bob', 'nice base']], history
  end


  # Slash-prefixed lines are commands, not chat: they must not reach the
  # console queue (context) and must not trigger the agent either.
  def test_on_chat_excludes_slash_commands
    @agent.on_chat('alice', '/shout build the mall')
    @agent.on_chat('bob', '/admin')
    @agent.on_chat('carol', ' /give iron-plate')
    assert_empty @agent.instance_variable_get(:@console_queue)

    triggered = @agent.on_chat('dave', '/hivemind what do you see?')
    refute triggered, 'slash commands must not trigger the agent'
  end


  def test_history_ignores_blank_messages
    @agent.send(:append_history, 'alice', '   ')
    assert_empty @agent.instance_variable_get(:@console_queue)
  end


  def test_history_caps_unread_lines_with_eviction
    (HiveMindAgent::HISTORY_SIZE + 5).times { |i| @agent.send(:append_history, 'p', "msg #{i}") }
    history = @agent.instance_variable_get(:@console_queue)
    assert_equal HiveMindAgent::HISTORY_SIZE, history.size
    assert_equal 'msg 5', history.first[1]  # oldest 5 dropped
  end


  # ── Encoding hardening (binary-flagged Unicode names) ──────────

  # Regression: a player name decoded from the wire as ASCII-8BIT with
  # high bytes used to taint the context snapshot, then collide with the
  # UTF-8 instruction at prompt assembly (`prompt << instruction`) →
  # Encoding::CompatibilityError, agent aborts mid-ask.
  def test_turn_prompt_survives_binary_flagged_unicode_names
    @agent = make_agent(rcon: FakeRcon.new(attrs: [
      { name: "sévérin".b, online_time: 60, connected: true },
      { name: "émoji".b, online_time: 3600, connected: true },
    ]))
    @agent.send(:append_history, "sévérin".b, "talking to the other machine".b)
    @agent.send(:append_history, 'alice', 'another line')

    prompt = @agent.send(:turn_prompt, "In-game chat from morganc: hi\n\nAnswer. Plain text only — no markdown.")
    assert prompt.valid_encoding?, 'assembled prompt must be valid UTF-8'
    assert_equal Encoding::UTF_8, prompt.encoding
    assert_includes prompt, 'sévérin'
    assert_includes prompt, 'émoji'
  end


  def test_on_chat_cleans_binary_flagged_player_name
    @agent.on_chat("sévérin".b, 'hey hivemind')
    player, _msg = @agent.instance_variable_get(:@console_queue).last
    assert_equal Encoding::UTF_8, player.encoding
    assert_equal 'sévérin', player
  end


  def test_unread_console_cleans_persisted_binary_names
    # Entries written by an OLD build (before boundary cleaning) survive
    # hot reloads — unread_console must still produce UTF-8 lines.
    @agent.send(:append_history, "sévérin".b, "legacy binary entry".b)
    lines = @agent.send(:unread_console)
    assert_equal Encoding::UTF_8, lines.first.encoding
    assert_includes lines.first, 'sévérin'
  end


  def test_send_reply_fallback_appends_reply
    @agent.send(:send_reply, 'fallback reply')
    assert_equal ['hivemind', 'fallback reply'], @agent.instance_variable_get(:@console_queue).last
  end


  # Regression: invalid UTF-8 from the wire crashed strip/regex
  # (ArgumentError / Encoding::CompatibilityError). Must be scrubbed.
  def test_invalid_utf8_chat_does_not_crash
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.on_chat('alice', "hivemind ".b + "\xFF\xFE".b + "testing".b)            # binary-flagged
    agent.on_chat('bob', ("hi".b + "\xFF".b).force_encoding('UTF-8'))              # utf8-flagged invalid
    queue = agent.instance_variable_get(:@console_queue)
    assert queue.all? { |_, m| m.valid_encoding? }, 'queued messages are valid UTF-8'
    assert_includes queue.first[1], 'hivemind'
  end


  # ── Context ───────────────────────────────────────────────────

  def test_system_prompt_is_static
    # The system prompt is personality/rules only — dynamic context lives
    # in the per-turn user prompt (turn_prompt).
    sp = HiveMindAgent::SYSTEM_PROMPT
    refute_includes sp, 'Current context:'
    refute_includes sp, 'Online players ('
  end


  def test_system_prompt_enforces_gps_rich_text
    # Coordinates must always be Factorio rich-text GPS tags ([gps=x,y]) —
    # clickable in game — never bare numbers, and never with a label or
    # extra parameters.
    sp = HiveMindAgent::SYSTEM_PROMPT.gsub(/\s+/, ' ')  # heredoc line-wrap tolerant
    assert_includes sp, '[gps=x,y]'
    assert_includes sp, 'clickable'
    assert_includes sp, 'Never write coordinates as bare numbers'
    assert_includes sp, 'no label, no surface, no extra parameters'
  end


  def test_turn_prompt_includes_snapshot_and_console
    @agent.on_player_event(:joined, 'alice')
    @agent.on_player_event(:left, 'bob')
    prompt = @agent.send(:turn_prompt, 'INSTRUCTION')
    assert_includes prompt, 'INSTRUCTION'
    assert_includes prompt, 'alice joined the game'
    assert_includes prompt, 'bob left the game'
  end


  def test_context_snapshot_includes_online_and_stats
    @agent = make_agent(rcon: FakeRcon.new(
      connected: ['alice'],
      attrs: [
        { name: 'alice', index: 1, connected: true, admin: true, online_time: 5_040_000 },
        { name: 'offlineguy', index: 2, connected: false, online_time: 99_999 },
      ]
    ))
    snap = @agent.send(:context_snapshot)
    # Merged section: names + play time for ONLINE players only —
    # offline players must not appear at all.
    assert_includes snap, 'Online players (1): alice: 23h20m (admin).'
    refute_includes snap, 'offlineguy'
  end


  def test_context_snapshot_empty_without_providers
    assert_empty @agent.send(:context_snapshot)
  end


  def test_on_player_event_appends_join_and_leave
    @agent.on_player_event(:joined, 'alice')
    @agent.on_player_event(:left, 'bob')
    history = @agent.instance_variable_get(:@console_queue)
    # join event, then the leave (greeting is stubbed to send nothing)
    assert_equal [nil, 'alice joined the game'], history[0]
    assert_equal [nil, 'bob left the game'], history[1]
    lines = @agent.send(:unread_console)
    assert_includes lines, 'alice joined the game'
    assert_includes lines, 'bob left the game'
  end


  # Join lines carry the player's total play time from RCON (online_time,
  # ticks) — formatted as days/hours like the context snapshot.
  def test_on_player_event_includes_playtime_from_rcon
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 2, name: 'alice', connected: true, admin: false, online_time: 11_016_000, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.define_singleton_method(:complete) { |_p| '' }
    agent.on_player_event(:joined, 'alice')
    assert_equal [nil, 'alice joined the game (2d3h played)'],
                 agent.instance_variable_get(:@console_queue)[0]
  end


  # No RCON attrs for the player (fresh server / query miss): no playtime
  # is known, so the join line carries no "(... played)" suffix.
  def test_on_player_event_playtime_absent_without_rcon_attrs
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.define_singleton_method(:complete) { |_p| '' }
    agent.on_player_event(:joined, 'bob')
    assert_equal [nil, 'bob joined the game'],
                 agent.instance_variable_get(:@console_queue)[0]
  end


  def test_format_ticks_compact_human_durations
    assert_equal '12m', @agent.send(:format_ticks, 43_200)
    assert_equal '2m', @agent.send(:format_ticks, 7_200)
    assert_equal '8h30m', @agent.send(:format_ticks, 1_836_000)
    assert_equal '10h', @agent.send(:format_ticks, 2_160_000)   # trailing 0m dropped
    assert_equal '1d0h', @agent.send(:format_ticks, 5_184_000)  # exactly one day
    assert_equal '2d3h', @agent.send(:format_ticks, 11_016_000) # zero minutes dropped
    assert_equal '0m', @agent.send(:format_ticks, 0)
  end


  def test_on_player_event_ignores_blank_name
    @agent.on_player_event(:joined, '  ')
    assert_empty @agent.instance_variable_get(:@console_queue)
  end


  def test_ask_llm_includes_new_console_lines
    @agent.on_chat('bob', 'nice rail setup')
    prompt = capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind what is the bus?') }
    assert_includes prompt, 'bob: nice rail setup'
    assert_includes prompt, 'In-game chat from alice: hivemind what is the bus?'
  end


  def test_ask_llm_does_not_repeat_previous_prompt_lines
    @agent.on_chat('bob', 'nice rail setup')
    capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind first?') }
    @agent.on_chat('carol', 'anyone have iron?')
    prompt2 = capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind second?') }
    assert_includes prompt2, 'carol: anyone have iron?'
    refute_includes prompt2, 'nice rail setup'   # already sent in the first prompt
    refute_includes prompt2, 'hivemind first?'   # the first trigger
  end


  def test_ask_llm_excludes_trigger_line_from_console_list
    prompt = capture_prompt(@agent) { @agent.send(:ask_llm, 'alice', 'hivemind the bus?') }
    # the trigger is stated explicitly, not repeated in the console list
    refute_includes prompt, 'New console lines'
    assert_equal 1, prompt.scan('hivemind the bus?').size
  end


  def test_unread_console_excludes_hivemind_replies
    @agent.on_chat('alice', 'hey')
    @agent.send(:append_history, 'hivemind', 'greetings')
    lines = @agent.send(:unread_console)
    assert_includes lines, 'alice: hey'
    refute_includes lines, 'hivemind: greetings'  # lives in the conversation
  end


  def test_unread_console_advances_pointer
    @agent.send(:append_history, 'alice', 'one')
    first = @agent.send(:unread_console)
    assert_equal ['alice: one'], first
    assert_empty @agent.send(:unread_console)  # queue drained
    @agent.send(:append_history, 'bob', 'two')
    assert_equal ['bob: two'], @agent.send(:unread_console)
  end


  def test_lines_survive_across_prompts_and_eviction
    # Regression: a ring buffer with a sent-pointer silently LOST the
    # newest lines once eviction from the front desynchronized the pointer
    # — goals written in console never reached Hivemind. The queue drains
    # on send, so every line reaches the model exactly once, in order.
    20.times { |i| @agent.send(:append_history, 'p', "before #{i}") }
    prompt1 = @agent.send(:unread_console)  # drains 20
    assert_equal 20, prompt1.size
    assert_includes prompt1, 'p: before 0'

    10.times { |i| @agent.send(:append_history, 'p', "goal #{i}") }
    prompt2 = @agent.send(:unread_console)  # must include ALL 10 new lines
    assert_equal 10, prompt2.size
    assert_includes prompt2, 'p: goal 0'
    assert_includes prompt2, 'p: goal 9'
    assert_empty @agent.send(:unread_console)
  end


  def test_unread_console_clips_long_lines
    @agent.send(:append_history, 'alice', 'x' * 500)
    line = @agent.send(:unread_console).first
    assert_operator line.length, :<=, HiveMindAgent::HISTORY_LINE_LEN + 20
  end


  def test_ask_llm_includes_events
    @agent.on_player_event(:joined, 'alice')
    prompt = capture_prompt(@agent) { @agent.send(:ask_llm, 'bob', 'hivemind hi') }
    assert_includes prompt, 'alice joined the game'
  end


  # ── Join greeting (LLM-generated) ─────────────────────────────

  def test_join_greeting_uses_llm_and_sends
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome, alice. The belts are quiet without you.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2  # greeting runs off-thread
    assert_includes seen_prompt, 'alice just joined'
    assert_includes rcon.sent, 'Hivemind> Welcome, alice. The belts are quiet without you.'
  end


  # Joins present the RCON playtime to the model twice: in the console
  # line (excluded from the per-turn feed since the instruction states it)
  # and explicitly in the greeting instruction.
  def test_join_greeting_prompt_includes_playtime
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 2, name: 'alice', connected: true, admin: false, online_time: 11_016_000, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome, alice.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_includes seen_prompt, 'alice just joined'
    assert_includes seen_prompt, 'they have played 2d3h in total'
    # The console line itself is excluded: the event must reach the model
    # ONLY through the instruction, never twice.
    refute_includes seen_prompt, 'alice joined the game (2d3h played)'
  end


  def test_join_greeting_prompt_omits_playtime_when_unknown
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome, alice.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    refute_includes seen_prompt, ' they have played '
  end


  def test_join_greeting_recorded_in_history
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.define_singleton_method(:complete) do |_prompt|
      clean_reply('Welcome, alice. The factory is watching.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_equal ['hivemind', 'Welcome, alice. The factory is watching.'],
                 agent.instance_variable_get(:@console_queue).last
  end


  def test_join_greeting_respects_greet_interval
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.define_singleton_method(:complete) { |_p| clean_reply('hi') }
    agent.instance_variable_set(:@last_greet, Process.clock_gettime(Process::CLOCK_MONOTONIC))
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_empty rcon.sent
  end


  def test_leave_does_not_greet
    rcon = FakeRcon.new
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    agent.on_player_event(:left, 'alice')
    assert_empty rcon.sent
  end


  # ── Extra trigger: "good bot" ───────────────────────────────────
  # Production replies are LLM-generated in character (same ask_llm path as
  # "hivemind" mentions) — NEVER a canned/template string. The tests below
  # stub the model and assert the trigger reaches the LLM with the message.

  def test_good_bot_triggers_reply
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    asked = nil
    agent.define_singleton_method(:complete) { |p| asked = p; '' }
    agent.on_chat('alice', 'good bot')
    sleep 0.2  # LLM call runs off-thread
    refute_nil asked, 'good bot should reach the LLM'
    assert_includes asked, 'In-game chat from alice: good bot'
  end


  def test_good_bot_variants_are_triggers
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    asks = 0
    agent.define_singleton_method(:complete) { |_p| asks += 1; '' }
    ['Good bot!', 'goodbot', 'GOOD BOT'].each { |m| agent.on_chat('bob', m); sleep 0.2 }
    assert_equal 1, asks, 'each variant pings (rate limiter collapses rapid-fire to one)'
  end


  def test_different_players_not_rate_limited_sequential_turns
    # The rate limiter is PER-PLAYER: another player triggering right after
    # a reply must get their own turn (queued on the complete mutex, so
    # sequential and seeing the prior Q&A) — never dropped just because
    # someone else asked recently.
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    asked = []
    agent.define_singleton_method(:complete) do |p|
      asked << p
      sleep 0.05            # simulate the slow LLM call so ordering shows
      ''
    end
    agent.on_chat('alice', 'hivemind hi')
    agent.on_chat('bob', 'hivemind hello')
    sleep 0.4
    assert_equal 2, asked.size, 'different players each get a turn'
    assert_includes asked.join, 'In-game chat from alice: hivemind hi'
    assert_includes asked.join, 'In-game chat from bob: hivemind hello'

    # same player again within the window is still collapsed (anti-spam),
    # using a fresh player so the first trigger is outside any old window
    asks2 = 0
    agent.define_singleton_method(:complete) { |_p| asks2 += 1; '' }
    agent.on_chat('carol', 'hivemind again')
    agent.on_chat('carol', 'hivemind stop')
    sleep 0.4
    assert_equal 1, asks2, 'same-player spam still collapses to one ask'
  end


  def test_triggers_constant_lists_all_phrases
    %w[hivemind good\ bot goodbot hm].each do |t|
      assert_includes HiveMindAgent::TRIGGERS, t
    end
  end


  # ── Word-boundary trigger: "hm" ────────────────────────────────
  # "hm" is too short for the substring match used for "hivemind"/"good
  # bot" (it would page on "shmoose"), so it fires only as a standalone
  # word, case-insensitively: "hm, hello", "HM: hello", "wdyt? hm".
  def test_hm_word_trigger_matches_standalone_word
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    ['hm', 'hm, hello', 'HM, hello', 'HM: hello', 'wdyt? hm', 'hi hm here',
     'hello-hm', 'hm!', 'say hm.', "[hm]"].each do |m|
      assert agent.send(:trigger_match?, m), "expected #{m.inspect} to trigger"
    end
  end


  def test_hm_does_not_trigger_on_substrings
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    ['shmoose', 'shmoo', 'hmm', 'hmm, hello', 'ahm', 'hmx', 's-h-m-oose'].each do |m|
      refute agent.send(:trigger_match?, m), "expected #{m.inspect} NOT to trigger"
    end
  end


  def test_hm_trigger_reaches_llm
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    asked = nil
    agent.define_singleton_method(:complete) { |p| asked = p; '' }
    agent.on_chat('alice', 'wdyt? hm')
    sleep 0.2
    refute_nil asked, 'standalone "hm" should reach the LLM'
  end


  def test_shmoose_does_not_trigger
    agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: false)
    called = false
    agent.define_singleton_method(:complete) { |_p| called = true; '' }
    agent.on_chat('alice', 'shmoose is back')
    sleep 0.2
    refute called, '"shmoose" must not page the agent'
  end


  def test_join_greeting_includes_player_memory
    Dir.mktmpdir do |dir|
      agent = HiveMindAgent.new(rcon: FakeRcon.new, api_key: 'sk-test', session_path: false, memory_dir: dir)
      agent.instance_variable_get(:@memory_store).write_player('alice', 'alice once nuked the bus on purpose')
      seen_prompt = nil
      agent.define_singleton_method(:complete) do |prompt|
        seen_prompt = prompt
        clean_reply('Welcome.')
      end
      agent.on_player_event(:joined, 'alice')
      sleep 0.2
      assert_includes seen_prompt, 'alice just joined'
      assert_includes seen_prompt, '=== memory of alice ==='
      assert_includes seen_prompt, 'alice once nuked the bus on purpose'
    end
  end


  def test_join_greeting_includes_admin_status
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 2, name: 'alice', connected: true, admin: true, online_time: 11_016_000, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome.')
    end
    agent.on_player_event(:joined, 'alice')
    sleep 0.2
    assert_includes seen_prompt, 'they have played 2d3h in total and are an admin'
  end


  def test_join_greeting_states_non_admin
    rcon = FakeRcon.new
    rcon.define_singleton_method(:player_attributes) do
      [{ index: 3, name: 'bob', connected: true, admin: false, online_time: 7_200, afk_time: 0 }]
    end
    agent = HiveMindAgent.new(rcon: rcon, api_key: 'sk-test', session_path: false, memory_dir: false)
    seen_prompt = nil
    agent.define_singleton_method(:complete) do |prompt|
      seen_prompt = prompt
      clean_reply('Welcome.')
    end
    agent.on_player_event(:joined, 'bob')
    sleep 0.2
    assert_includes seen_prompt, 'they have played 2m in total and are not an admin'
  end


  # ── Token usage logging ──────────────────────────────────────

  def test_usage_line_formats_cache_metrics
    msg = RubyLLM::Message.new(role: :assistant, content: 'ok',
                               tokens: RubyLLM::Tokens.build(input: 2400, cached: 1800,
                                                              cache_creation: 200, output: 400,
                                                              thinking: 30))
    assert_equal ' (2400 in, 1800 cached, 200 written, 400 out, 30 think)', @agent.send(:usage_line, msg)
  end


  def test_usage_line_omits_absent_and_zero_metrics
    msg = RubyLLM::Message.new(role: :assistant, content: 'hi',
                               tokens: RubyLLM::Tokens.build(input: 100, output: 20, cached: 0))
    assert_equal ' (100 in, 20 out)', @agent.send(:usage_line, msg)
    assert_equal '', @agent.send(:usage_line, RubyLLM::Message.new(role: :assistant, content: 'no tokens'))
  end
end
