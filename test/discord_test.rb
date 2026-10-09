#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the Discord plugin (now a PluginSet feature reached via the shared
# :on_chat chat relay, not a sniffer-constructed host object). Drives
# Discord.new(owner) with a fake gateway bot + a fake owner that records the
# relay's publish_chat calls. No network, no discordrb at runtime (it stays
# lazily required, only built by build_bot).
# Run: ruby -Ilib test/discord_test.rb
require 'minitest/autorun'
require 'mocha/minitest'
require 'tmpdir'
require 'yaml'
require_relative '../lib/discord'
require_relative '../lib/player_db'

# A tiny double recording the calls the bridge makes to the gateway.
class FakeDiscordBot
  attr_reader :channel_id, :registered_handler, :sent, :stopped
  def initialize(channel_id:)
    @channel_id = channel_id
    @registered_handler = nil
    @sent = []
    @stopped = false
  end

  # discordrb Bot#message registers a BLOCK handler; capture the receiver so
  # tests can drive it as if the gateway fired an event.
  def message(&block) = (@registered_handler = block)
  def call_message(event) = @registered_handler&.call(event)
  def send_message(channel, content, _tts = false, _embeds = nil, _attachments = nil, allowed_mentions = nil, *_rest)
    @sent << { channel: channel, content: content, allowed_mentions: allowed_mentions }
  end
  def stop(*) = (@stopped = true)
end

class FakeChannel
  attr_reader :id
  def initialize(id) = @id = id
end

class FakeAuthor
  attr_reader :username, :display_name, :bot
  def initialize(bot: false, username: 'someone', display_name: nil)
    @bot = bot
    @username = username
    @display_name = display_name
  end

  def bot_account? = @bot
end

class FakeMessageEvent
  attr_reader :channel, :author, :content
  def initialize(channel:, author:, content:)
    @channel = channel
    @author = author
    @content = content
  end
end

# Fake sniffer owner: the chat-relay + player sources Discord.new(owner) reads.
# publish_chat is the relay the bridge emits into (and that fans back to the
# agent — not exercised here; the bridge just needs to call it).
class FakeOwner
  attr_reader :rcon, :player_db, :publish_chat_calls
  def initialize(rcon:, player_db:)
    @rcon = rcon
    @player_db = player_db
    @publish_chat_calls = []
  end

  def publish_chat(source, author, text) = @publish_chat_calls << [source, author, text]
end

# A double for the RconClient: records say() calls.
class DiscordFakeRcon
  attr_reader :said
  def initialize = @said = []
  def say(text) = @said << text
  def lua_quote(s) = s.to_s
end

class TestDiscord < Minitest::Test
  CHANNEL_ID = 123_456_789_012_345_678

  def setup
    @bridges = []
  end

  def teardown
    @bridges.each(&:close)
  end

  # config-discord.yaml is required + channel_id + token are required —
  # missing file / missing token are startup errors, never a half-alive bridge.
  def test_missing_config_file_is_an_error
    error = assert_raises(Errno::ENOENT) do
      Discord.new(fake_owner, config_file: '/nonexistent/config-discord.yaml',
                            bot: FakeDiscordBot.new(channel_id: CHANNEL_ID))
    end
    assert_match(/config-discord\.yaml\.example/, error.message)
  end

  def test_missing_token_is_an_error
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'config-discord.yaml')
      File.write(path, YAML.dump('channel_id' => CHANNEL_ID))
      with_env('DISCORD_TOKEN' => nil) do
        error = assert_raises(ArgumentError) do
          Discord.new(fake_owner, config_file: path,
                          bot: FakeDiscordBot.new(channel_id: CHANNEL_ID))
        end
        assert_match(/no Discord token/, error.message)
      end
    end
  end

  def test_missing_channel_id_is_an_error
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'config-discord.yaml')
      File.write(path, YAML.dump('token' => 'fake'))
      error = assert_raises(KeyError) do
        Discord.new(fake_owner, config_file: path,
                          bot: FakeDiscordBot.new(channel_id: CHANNEL_ID))
      end
      assert_includes error.message, 'channel_id'
    end
  end

  def test_env_token_wins_over_yaml
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'config-discord.yaml')
      File.write(path, YAML.dump('channel_id' => CHANNEL_ID, 'token' => 'yaml-token'))
      with_env('DISCORD_TOKEN' => 'env-token') do
        # No bot: avoids discordrb; token resolution is all we test here.
        bot = FakeDiscordBot.new(channel_id: CHANNEL_ID)
        bridge = Discord.new(fake_owner, config_file: path, bot: bot)
        @bridges << bridge
        assert_equal 'env-token', bridge.instance_variable_get(:@token)
      end
    end
  end

  def test_forward_chat_posts_to_channel
    bridge = new_bridge
    bridge.forward_chat('Bob', 'hello')
    sent = bridge.instance_variable_get(:@bot).sent
    assert_equal 1, sent.size
    assert_equal CHANNEL_ID, sent.first[:channel]
    assert_equal 'Bob: hello', sent.first[:content]
    # allowed_mentions with an empty parse array suppresses @-pings on
    # relayed chat (Factorio names aren't Discord users).
    assert_equal({ parse: [] }, sent.first[:allowed_mentions])
  end

  def test_on_discord_message_relays_to_game_and_emits_to_bus
    rcon = DiscordFakeRcon.new
    owner = FakeOwner.new(rcon: rcon, player_db: PlayerDatabase.new(nil))
    bridge = new_bridge(rcon: rcon, owner: owner)
    # Make enqueue synchronous so handle_discord_message runs inline.
    bridge.define_singleton_method(:enqueue) { |m, *a, **k| send(m, *a, **k) }

    bridge.instance_variable_get(:@bot).call_message(FakeMessageEvent.new(
      channel: FakeChannel.new(CHANNEL_ID),
      author: FakeAuthor.new(bot: false, username: 'alice', display_name: 'Alice'),
      content: 'hi everyone'
    ))

    # Discord → in-game: relayed via RCON game.print, tagged [Discord].
    assert_equal ['[Discord] Alice: hi everyone'], rcon.said
    # → chat bus as :discord (the sniffer's relay fans it to the agent; the
    # bridge itself skips :discord, so it never echoes back to the channel).
    assert_equal [[:discord, 'Alice', 'hi everyone']], owner.publish_chat_calls
  end

  def test_on_discord_message_skips_bot_authors_and_other_channels
    rcon = DiscordFakeRcon.new
    owner = FakeOwner.new(rcon: rcon, player_db: PlayerDatabase.new(nil))
    bridge = new_bridge(rcon: rcon, owner: owner)

    bot = bridge.instance_variable_get(:@bot)
    # Bot author — skipped (no relay, no emit; prevents echo loops).
    bot.call_message(FakeMessageEvent.new(
      channel: FakeChannel.new(CHANNEL_ID),
      author: FakeAuthor.new(bot: true, username: 'bot'),
      content: 'hi'
    ))
    # Wrong channel — skipped.
    bot.call_message(FakeMessageEvent.new(
      channel: FakeChannel.new(999),
      author: FakeAuthor.new(bot: false, username: 'bob'),
      content: 'hi'
    ))

    assert_empty rcon.said
    assert_empty owner.publish_chat_calls
  end

  # The bridge no longer filters by trigger — it emits every (non-bot,
  # on-channel) message to the bus; the agent decides whether to answer. So a
  # message with no trigger still reaches the game chat + the bus.
  def test_on_discord_message_emits_all_channel_messages
    rcon = DiscordFakeRcon.new
    owner = FakeOwner.new(rcon: rcon, player_db: PlayerDatabase.new(nil))
    bridge = new_bridge(rcon: rcon, owner: owner)
    bridge.define_singleton_method(:enqueue) { |m, *a, **k| send(m, *a, **k) }

    bridge.instance_variable_get(:@bot).call_message(FakeMessageEvent.new(
      channel: FakeChannel.new(CHANNEL_ID),
      author: FakeAuthor.new(bot: false, username: 'carol'),
      content: 'hi everyone'
    ))

    assert_equal ['[Discord] carol: hi everyone'], rcon.said
    assert_equal [[:discord, 'carol', 'hi everyone']], owner.publish_chat_calls
  end

  def test_on_chat_forwards_factorio_and_hivemind_skips_own
    bridge = new_bridge
    # Make enqueue synchronous so forward_chat runs inline.
    bridge.define_singleton_method(:enqueue) { |m, *a, **k| send(m, *a, **k) }
    bot = bridge.instance_variable_get(:@bot)

    bridge.on_chat(:factorio, 'Bob', 'welcome')        # → forward_chat('Bob', 'welcome')
    assert_equal 'Bob: welcome', bot.sent.first[:content]
    bridge.on_chat(:hivemind, 'Hivemind', 'done!')     # → forward_chat('Hivemind', 'done!')
    assert_equal 'Hivemind: done!', bot.sent.last[:content]
    bridge.on_chat(:discord, 'Alice', 'echo?')          # → skipped (own source; no echo loop)
    assert_equal 2, bot.sent.size
  end

  def test_handler_registered_at_construction
    bot = FakeDiscordBot.new(channel_id: CHANNEL_ID)
    bridge = new_bridge(bot: bot)
    @bridges << bridge
    # The gateway event handler is registered exactly once, as a bound method.
    refute_nil bot.registered_handler
  end

  def test_close_stops_bot_and_drains_worker
    rcon = DiscordFakeRcon.new
    owner = FakeOwner.new(rcon: rcon, player_db: PlayerDatabase.new(nil))
    bot = FakeDiscordBot.new(channel_id: CHANNEL_ID)
    bridge = new_bridge(rcon: rcon, owner: owner, bot: bot)
    bridge.define_singleton_method(:enqueue) { |m, *a, **k| send(m, *a, **k) }
    # Drive one message so the worker has done work, then close cleanly.
    bridge.instance_variable_get(:@bot).call_message(FakeMessageEvent.new(
      channel: FakeChannel.new(CHANNEL_ID),
      author: FakeAuthor.new(bot: false, username: 'dave'),
      content: 'hello'
    ))
    bridge.close
    # close stopped the gateway bot and drained the worker thread.
    assert bridge.instance_variable_get(:@bot).stopped
    assert_equal '[Discord] dave: hello', rcon.said.first
  end

  private

  # A throwaway owner double (rcon/player_db/publish_chat no-ops), used by the
  # config/token/channel_id + forward_chat tests where the owner isn't
  # exercised. Built once and reused across those read-only tests.
  def fake_owner
    @fake_owner ||= FakeOwner.new(rcon: DiscordFakeRcon.new, player_db: PlayerDatabase.new(nil))
  end

  def new_bridge(rcon: DiscordFakeRcon.new, player_db: PlayerDatabase.new(nil), token: 'test-token', bot: nil, owner: nil)
    Dir.mktmpdir('discord-test') do |dir|
      config = File.join(dir, 'config-discord.yaml')
      File.write(config, YAML.dump('channel_id' => CHANNEL_ID, 'token' => token))
      bot ||= FakeDiscordBot.new(channel_id: CHANNEL_ID)
      owner ||= FakeOwner.new(rcon: rcon, player_db: player_db)
      bridge = Discord.new(owner, config_file: config, bot: bot)
      @bridges << bridge
      return bridge
    end
  end

  def with_env(vars)
    old = vars.to_h { |k, _| [k, ENV[k]] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end
end
