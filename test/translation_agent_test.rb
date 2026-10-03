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
require_relative '../factorio-packettools'
require_relative '../lib/translation'
require_relative '../lib/translation_argos'
require_relative '../lib/translation_mock'

# The plugin's config is required (no code defaults), so the tests point at
# the checked-in example, the way the hivemind tests do.
TRANSLATION_TEST_CONFIG = File.expand_path('../config-translation.yaml.example', __dir__)

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
      config_file: TRANSLATION_TEST_CONFIG,
      **kwargs
    )
    @agents << agent
    agent
  end

  # The unknown-packets writer is injected as a null double: the default is
  # a REAL PcapWriter, which leaves an empty captures/unknown.packets-<ts>.pcap
  # in the repo on every run.
  class NullWriter
    def path = 'unknown.packets (test)'
    def write_frame(*) = nil
    def close = nil
  end

  def make_sniffer
    FactorioPacketTools.new({ server: false, pcap: nil, interface: nil },
                            unknown_pcap_writer: NullWriter.new)
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
      sniffer.handle_command('/locales somePlayer en,pt')
      sniffer.handle_command('/locales somePlayer')
      sniffer.handle_command('/locales')
    end
    assert_equal ['en', 'pt'], player_db.locale_overrides('somePlayer')
    assert_includes locales_output, 'somePlayer: en,pt'
    capture_io do
      sniffer.handle_command('/locales somePlayer -')
    end
    assert_nil player_db.locale_overrides('somePlayer')
  end

  def test_google_api_key_from_yaml_with_env_override
    Dir.mktmpdir do |dir|
      base = YAML.safe_load_file(TRANSLATION_TEST_CONFIG).merge('backend' => 'google')
      with_key = File.join(dir, 'with-key.yaml')
      without_key = File.join(dir, 'without-key.yaml')
      File.write(with_key, YAML.dump(base.merge('google_api_key' => 'yaml-key')))
      File.write(without_key, YAML.dump(base))

      with_env('GOOGLE_TRANSLATE_API_KEY' => nil) do
        assert make_agent(backend: nil, config_file: with_key).google_api_key?,
               'key picked up from the config file'
      end
      with_env('GOOGLE_TRANSLATE_API_KEY' => 'env-key') do
        assert make_agent(backend: nil, config_file: with_key).google_api_key?
      end
      with_env('GOOGLE_TRANSLATE_API_KEY' => nil) do
        # No key anywhere is a startup error, not a silently broken agent.
        error = assert_raises(ArgumentError) { make_agent(backend: nil, config_file: without_key) }
        assert_match(/needs a Google key/, error.message)
      end
    end
  end

  # Config is required: no file, or a file missing a key, is an error the
  # sniffer reports as "[translate] Translation agent disabled: ...".
  def test_config_is_required
    error = assert_raises(Errno::ENOENT) { make_agent(config_file: '/nonexistent/config-translation.yaml') }
    assert_match(/config-translation\.yaml\.example/, error.message)

    Dir.mktmpdir do |dir|
      path = File.join(dir, 'partial.yaml')
      File.write(path, YAML.dump('backend' => 'mock'))
      # Not validated up front: the key raises where it is read, naming itself.
      error = assert_raises(KeyError) { make_agent(config_file: path) }
      assert_includes error.message, 'whitelist'
    end
  end

  # No hardcoded defaults left: the whitelist and the anti-spam interval come
  # from the file.
  def test_no_code_defaults_for_whitelist_or_interval
    config = YAML.safe_load_file(TRANSLATION_TEST_CONFIG)
    agent = make_agent(backend: :mock)

    assert_equal config['whitelist'].map(&:downcase).to_set, agent.whitelist
    assert_equal config['min_interval'], agent.instance_variable_get(:@min_interval)
  end

  def with_env(vars)
    old = vars.to_h { |k, _| [k, ENV[k]] }
    vars.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
    yield
  ensure
    old.each { |k, v| v.nil? ? ENV.delete(k) : ENV[k] = v }
  end

  def test_backend_wiring
    fake = fake_argos_install
    argos = make_agent(backend: :argos, argos_path: fake)
    assert_instance_of ArgosTranslateService, argos.translation_service
    assert_equal fake, argos.translation_service.instance_variable_get(:@path)

    mock = make_agent
    assert_instance_of MockTranslationService, mock.translation_service

    google = make_agent(backend: :google, google_api_key: 'fake-key')
    assert_instance_of GoogleCloudTranslateService, google.translation_service

    hybrid = make_agent(backend: :hybrid, google_api_key: 'fake-key', argos_path: fake)
    assert_instance_of HybridTranslationService, hybrid.translation_service
    assert_instance_of ArgosTranslateService, hybrid.translation_service.instance_variable_get(:@argos)
    assert_instance_of GoogleCloudTranslateService, hybrid.translation_service.instance_variable_get(:@google)
  end

  # A minimal fake argos install: the CLI plus an argospm that lists packs
  # (the service refuses to start without both).
  def fake_argos_install
    @fake_argos_dir ||= Dir.mktmpdir('fake-argos')
    script = File.join(@fake_argos_dir, 'argos-translate')
    argospm = File.join(@fake_argos_dir, 'argospm')
    File.write(script, "#!/bin/sh\nprintf 'PEREVOD\\n'\n")
    File.chmod(0o755, script)
    File.write(argospm, "#!/bin/sh\necho 'translate-ru_en'\necho 'translate-en_ru'\n")
    File.chmod(0o755, argospm)
    script
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

  # A backend that cannot run is a STARTUP error, not a healthy agent that
  # silently never translates: no binary, and no language packs.
  def test_missing_argos_install_is_an_error
    error = assert_raises(RuntimeError) { ArgosTranslateService.new(path: '/nonexistent/argos-translate') }
    assert_match(/argos-translate not found/, error.message)

    Dir.mktmpdir do |dir|
      script = File.join(dir, 'argos-translate')
      File.write(script, "#!/bin/sh\nprintf 'PEREVOD\\n'\n")
      File.chmod(0o755, script)
      error = assert_raises(RuntimeError) { ArgosTranslateService.new(path: script) } # no argospm beside it
      assert_match(/no argos language packs/, error.message)
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

    output, = capture_io do
      result = agent.on_chat({ game_player: 1 }, 'привет')
      assert_equal [true, 'привет'], result
      agent.on_chat({ game_player: 3 }, 'hola que tal')
      assert_equal '[en] привет', agent.simulate_translation('ivan', 'ru', 'привет')
      agent.simulate_translation('pedro', 'pt-BR', 'olá')
    end

    # Console echoes the TRANSLATIONS sent, not the original text
    # (the sniffer already printed the chat itself).
    assert_includes output, '[translate] [ru>en] ivan: [en] привет  |  [ru>pt] ivan: [pt] привет'
    refute_includes output, "[translate] ivan (ru): привет\n"

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
      db[7] = {name: 'somePlayer', locale: 'pt-BR'}
      db.set_locale_overrides('somePlayer', ['en', 'pt'])

      assert_equal ['en', 'pt'], db.locale_overrides('somePlayer')
      reloaded = PlayerDatabase.new(cache)
      assert_equal ['en', 'pt'], reloaded.locale_overrides('somePlayer')
      assert File.exist?(File.join(dir, 'players-locale.json'))
      assert_equal 'somePlayer', reloaded.lookup(7)
      assert_equal 'pt-BR', reloaded.get_locale(7)

      reloaded.set_locale_overrides('somePlayer', [])
      cleared = PlayerDatabase.new(cache)
      assert_nil cleared.locale_overrides('somePlayer')
    end
  end
end
