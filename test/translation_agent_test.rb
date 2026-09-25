#!/usr/bin/env ruby
# frozen_string_literal: true

# Tests for the TranslationAgent backends and the /simulate console command.
#
# Regression: /simulate used to call the typo'd @translation_agent
# translate_service method. This suite drives the real handler and asserts the
# translated output instead of relying on a hand-written pass/fail runner.
# Argos is only installed on the target server, so the CLI test uses a fake
# `argos-translate` executable.
# Run: ruby -Ilib test/translation_agent_test.rb

require 'minitest/autorun'
require 'tmpdir'
require_relative '../factorio-sniffer'
require_relative '../lib/translation_argos'
require_relative '../lib/translation_mock'

class TestTranslationAgent < Minitest::Test
  def setup
    @agents = []
  end

  def teardown
    @agents.each(&:close_events)
  end

  def make_agent(backend: :mock, rcon: nil, player_db: PlayerDatabase.new(nil), roster: nil, **kwargs)
    agent = TranslationAgent.new(
      rcon: rcon,
      player_db: player_db,
      backend: backend,
      roster: roster,
      **kwargs
    )
    @agents << agent
    agent
  end

  def make_sniffer
    FactorioSniffer.new({ server: false, pcap: nil, interface: nil })
  end

  def command_recorder
    commands = []
    rcon = Object.new
    rcon.define_singleton_method(:command) do |command|
      commands << command
      ''
    end
    rcon.define_singleton_method(:lua_quote) { |value| RconClient.allocate.lua_quote(value) }
    [rcon, commands]
  end

  def test_simulate_command_and_locale_console
    sniffer = make_sniffer
    player_db = sniffer.instance_variable_get(:@player_db)
    sniffer.instance_variable_set(:@translation_agent, make_agent(player_db: player_db))

    simulate_output, simulate_error = capture_io do
      sniffer.handle_command(%q{/simulate StarBurtS ru "Zdravstvuyte"})
    end
    assert_includes simulate_output,
                    "[simulate] player=StarBurtS lang=ru msg='Zdravstvuyte' => translated='[en] Zdravstvuyte'"
    refute_includes simulate_error, 'NoMethodError'

    locales_output, = capture_io do
      sniffer.handle_command('/locales KrlosUltimate en,pt')
      sniffer.handle_command('/locales KrlosUltimate')
      sniffer.handle_command('/locales')
    end
    assert_equal ['en', 'pt'], player_db.locale_overrides('KrlosUltimate')
    assert_includes locales_output, 'KrlosUltimate: en,pt'
    capture_io do
      sniffer.handle_command('/locales KrlosUltimate -')
    end
    assert_nil player_db.locale_overrides('KrlosUltimate')
  end

  def test_google_api_key_from_yaml_with_env_override
    Dir.mktmpdir do |dir|
      Dir.chdir(dir) do
        File.write('config-translation.yaml', YAML.dump('backend' => 'google', 'google_api_key' => 'yaml-key'))
        with_env('GOOGLE_TRANSLATE_API_KEY' => nil) do
          agent = make_agent(backend: nil)
          assert agent.google_api_key?, 'key picked up from config-translation.yaml'
        end
        with_env('GOOGLE_TRANSLATE_API_KEY' => 'env-key') do
          agent = make_agent(backend: nil)
          assert agent.google_api_key?
        end
        File.write('config-translation.yaml', YAML.dump('backend' => 'google'))
        with_env('GOOGLE_TRANSLATE_API_KEY' => nil) do
          refute make_agent(backend: nil).google_api_key?, 'no key anywhere'
        end
      end
    end
  end

  def with_env(vars)
    old = vars.to_h { |k, _| [k, ENV[k]] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  def test_backend_wiring
    argos = make_agent(backend: :argos)
    assert_instance_of ArgosTranslateService, argos.translation_service
    assert_equal ArgosTranslateService::ARGOS_BIN,
                 argos.translation_service.instance_variable_get(:@path)

    mock = make_agent
    assert_instance_of MockTranslationService, mock.translation_service

    google = make_agent(backend: :google, google_api_key: 'fake-key')
    assert_instance_of GoogleCloudTranslateService, google.translation_service

    hybrid = make_agent(backend: :hybrid, google_api_key: 'fake-key')
    assert_instance_of HybridTranslationService, hybrid.translation_service
    assert_instance_of ArgosTranslateService, hybrid.translation_service.instance_variable_get(:@argos)
    assert_instance_of GoogleCloudTranslateService, hybrid.translation_service.instance_variable_get(:@google)
  end

  def test_argos_cli_arguments_safety_stderr_and_supported_languages
    Dir.mktmpdir do |dir|
      script = File.join(dir, 'fake-argos')
      argospm = File.join(dir, 'argospm')
      log = File.join(dir, 'args.log')
      File.write(script, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"#{log}\"\nprintf 'PEREVOD\\n'\n")
      File.chmod(0o755, script)
      File.write(argospm, "#!/bin/sh\necho 'translate-ru_en'\necho 'translate-en_ru'\n")
      File.chmod(0o755, argospm)

      service = ArgosTranslateService.new(path: script)
      text = "Zdravstvuyte $(touch injected) `touch backticked`"
      assert_equal 'PEREVOD', service.translate(text, source_lang: 'ru', target_lang: 'en')
      assert_equal ['--from-lang', 'ru', '--to-lang', 'en', text], File.readlines(log).map(&:strip)
      refute File.exist?(File.join(dir, 'injected'))
      refute File.exist?(File.join(dir, 'backticked'))

      assert_equal 'PEREVOD', service.translate("a\0b", source_lang: 'ru', target_lang: 'en')
      assert_equal 'ab', File.readlines(log).map(&:strip).last

      noisy = File.join(dir, 'noisy-argos')
      File.write(noisy, "#!/bin/sh\necho '2026-09-17 17:06:58 WARNING: Language en package default expects mwt' >&2\nprintf 'PEREVOD\\n'\n")
      File.chmod(0o755, noisy)
      assert_equal 'PEREVOD', ArgosTranslateService.new(path: noisy).translate('x', source_lang: 'ru', target_lang: 'en')

      assert service.supported?('ru')
      assert service.supported?('RU')
      assert service.supported?('ru-RU')
      refute service.supported?('hu')
      refute service.supported?('hu-HU')
    end
  end

  def test_missing_argos_binary_returns_original_text
    service = ArgosTranslateService.new(path: '/nonexistent/argos-translate')
    capture_io do
      assert_equal 'privet', service.translate('privet', source_lang: 'ru', target_lang: 'en')
    end
  end

  def test_on_chat_relays_translations_by_locale
    roster = -> { [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' }, { index: 3, name: 'pedro' }] }
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    player_db[1] = {name: 'ivan', locale: 'ru'}
    player_db[2] = {name: 'bob', locale: 'en'}
    player_db[3] = {name: 'pedro', locale: 'pt'}
    agent = make_agent(rcon: rcon, player_db: player_db, roster: roster)

    _output, = capture_io do
      result = agent.on_chat({ game_player: 1 }, 'привет')
      assert_equal [true, 'привет'], result
      agent.on_chat({ game_player: 3 }, 'hola que tal')
      assert_equal '[en] привет', agent.simulate_translation('ivan', 'ru', 'привет')
      agent.simulate_translation('pedro', 'pt-BR', 'olá')
    end

    assert_equal 4, commands.size
    first = commands.first
    assert_includes first, '/sc '
    assert_includes first, 'for _, p in pairs(game.connected_players)'
    assert_includes first, '[2]="[ru>en] ivan:'
    assert_includes first, '[3]="[ru>pt] ivan:'
    refute_includes first, '[1]='
    assert_includes first, 'local x = t[p.index]'
    assert_includes first, 'p.print(x, ps)'
    assert_includes first, 'local n = "ivan"'
    assert_includes first, 'local s = game.players[n]'
    assert_includes first, 's.chat_color or s.color'
    assert_includes first, '{color = (s.chat_color or s.color)}'

    second = commands[1]
    assert_includes second, '[1]="[pt>ru] pedro:'
    assert_includes second, '[2]="[pt>en] pedro:'
    refute_includes second, '[3]='

    fourth = commands[3]
    assert_includes fourth, '[1]="[pt>ru] pedro:'
    assert_includes fourth, '[2]="[pt>en] pedro:'
    refute_includes fourth, 'pt-BR'

    fourth = commands[3]
    assert_includes fourth, '[1]="[pt>ru] pedro:'
    assert_includes fourth, '[2]="[pt>en] pedro:'
    refute_includes fourth, 'pt-BR'
  end

  def test_note_joined_queries_and_stores_locale
    commands = []
    rcon = Object.new
    rcon.define_singleton_method(:command) do |command|
      commands << command
      'ru'
    end
    rcon.define_singleton_method(:lua_quote) { |value| RconClient.allocate.lua_quote(value) }
    player_db = PlayerDatabase.new(nil)
    player_db[5] = {name: 'StarBurtS'}
    agent = make_agent(rcon: rcon, player_db: player_db)

    assert_equal 'ru', agent.note_joined(5, 'StarBurtS')
    assert_equal 1, commands.size
    assert_includes commands.first, '/sc '
    assert_includes commands.first, 'game.players["StarBurtS"]'
    assert_equal 'ru', player_db.get_locale(5)

    nil_commands = []
    nil_rcon = Object.new
    nil_rcon.define_singleton_method(:command) do |command|
      nil_commands << command
      'nil'
    end
    nil_rcon.define_singleton_method(:lua_quote) { |value| RconClient.allocate.lua_quote(value) }
    nil_db = PlayerDatabase.new(nil)
    nil_db[6] = {name: 'Unknown'}
    make_agent(rcon: nil_rcon, player_db: nil_db).note_joined(6, 'Unknown')
    assert_equal 1, nil_commands.size
    assert_nil nil_db.get_locale(6)
  end

  def test_relay_skips_unchanged_whitelisted_and_unsupported_targets
    missing_pack = Class.new(MockTranslationService) do
      def translate(text, source_lang:, target_lang:)
        target_lang == 'pt' ? text : super
      end
    end.new

    roster = -> { [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' }, { index: 3, name: 'pedro' }] }
    rcon, commands = command_recorder
    player_db = PlayerDatabase.new(nil)
    player_db[1] = {name: 'ivan', locale: 'ru'}
    player_db[2] = {name: 'bob', locale: 'en'}
    player_db[3] = {name: 'pedro', locale: 'pt'}
    agent = make_agent(rcon: rcon, player_db: player_db, roster: roster)
    agent.instance_variable_set(:@translation_service, missing_pack)

    capture_io { agent.on_chat({ game_player: 1 }, "привет\0\0") }
    assert_includes commands.first, '[2]="[ru>en] ivan:'
    refute_includes commands.first, '[3]='
    refute_includes commands.first, "\0"

    unsupported_rcon, unsupported_commands = command_recorder
    unsupported_db = PlayerDatabase.new(nil)
    unsupported_db[1] = {name: 'ivan', locale: 'ru'}
    unsupported_db[2] = {name: 'bob', locale: 'en'}
    unsupported_db[3] = {name: 'pierre', locale: 'fr'}
    unsupported_agent = make_agent(
      rcon: unsupported_rcon,
      player_db: unsupported_db,
      roster: -> { [{ index: 1, name: 'ivan' }, { index: 2, name: 'bob' }, { index: 3, name: 'pierre' }] }
    )

    capture_io { unsupported_agent.on_chat({ game_player: 1 }, 'привет') }
    assert_includes unsupported_commands.first, '[2]="[ru>en] ivan:'
    refute_includes unsupported_commands.first, '[3]='
  end

  def test_locale_override_persistence
    Dir.mktmpdir do |dir|
      cache = File.join(dir, 'players-cache.json')
      db = PlayerDatabase.new(cache)
      db[7] = {name: 'KrlosUltimate', locale: 'pt-BR'}
      db.set_locale_overrides('KrlosUltimate', ['en', 'pt'])

      assert_equal ['en', 'pt'], db.locale_overrides('KrlosUltimate')
      reloaded = PlayerDatabase.new(cache)
      assert_equal ['en', 'pt'], reloaded.locale_overrides('KrlosUltimate')
      assert File.exist?(File.join(dir, 'players-locale.json'))
      assert_equal 'KrlosUltimate', reloaded.lookup(7)
      assert_equal 'pt-BR', reloaded.get_locale(7)

      reloaded.set_locale_overrides('KrlosUltimate', [])
      cleared = PlayerDatabase.new(cache)
      assert_nil cleared.locale_overrides('KrlosUltimate')
    end
  end
end
