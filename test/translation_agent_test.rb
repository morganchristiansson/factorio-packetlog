#!/usr/bin/env ruby
# Tests for the TranslationAgent backends + the /simulate console command.
#
# Regression: /simulate called @translation_agent.translate_service (typo;
# the attr_reader is translation_service) and NoMethodError'd on EVERY run —
# with no test asserting the command, the break sailed through. Test 1
# drives the real /simulate handler and fails on the typo'd code.
# Argos is only installed on the target server, so Test 3 runs a fake
# `argos-translate` script (argv echo) instead of the real binary.
# Run: ruby -Ilib test/translation_agent_test.rb

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'stringio'
require 'tmpdir'
require 'translation_argos'  # loaded lazily by the agent; needed directly here
require_relative '../factorio-sniffer'  # sets up bundler (rconrb) + loads libs

$pass = 0
$fail = 0
def check(cond, label)
  if cond
    puts "  PASS: #{label}"
    $pass += 1
  else
    puts "  FAIL: #{label}"
    $fail += 1
  end
end

# ── Test 1: /simulate through the sniffer console (regression) ───────
player_db = PlayerDatabase.new(nil)
out = StringIO.new
err = StringIO.new
old_out, old_err = $stdout, $stderr
$stdout, $stderr = out, err
sniffer = FactorioSniffer.new({server: false, pcap: nil, interface: nil, player_db: nil})
sniffer.instance_variable_set(:@pcap_writer, nil)
# No RCON here → the sniffer skips the translation agent; inject a mock one.
sniffer.instance_variable_set(:@translation_agent,
  TranslationAgent.new(rcon: nil, player_db: player_db, backend: :mock))
sniffer.handle_command(%q{/simulate StarBurtS ru "Zdravstvuyte"})
$stdout, $stderr = old_out, old_err
check(out.string.include?("[simulate] player=StarBurtS lang=ru msg='Zdravstvuyte' => translated='[en] Zdravstvuyte'"),
      '/simulate prints the translated result through the sniffer console')
check(!err.string.include?('NoMethodError'), 'no NoMethodError from /simulate (translate_service typo)')

# ── Test 1b: /locales through the sniffer console (set/show/list/clear) ──
locales_out = StringIO.new
$stdout = locales_out
locdb = sniffer.instance_variable_get(:@player_db)
sniffer.handle_command('/locales KrlosUltimate en,pt')
check(locdb.locale_overrides('KrlosUltimate') == ['en', 'pt'],
      '/locales NAME en,pt stores the override in the player db')
sniffer.handle_command('/locales KrlosUltimate')
check(locales_out.string.include?('KrlosUltimate: en,pt'),
      '/locales NAME prints the current override')
sniffer.handle_command('/locales')
check(locales_out.string.include?('KrlosUltimate: en,pt'), '/locales lists all overrides')
sniffer.handle_command('/locales KrlosUltimate -')
check(locdb.locale_overrides('KrlosUltimate').nil?, '/locales NAME - clears the override')
$stdout = old_out

# ── Test 2: backend wiring ───────────────────────────────────────────
agent = TranslationAgent.new(rcon: nil, player_db: player_db, backend: :argos)
check(agent.translation_service.is_a?(ArgosTranslateService),
      'backend :argos wires an ArgosTranslateService (no binary needed at init)')
check(agent.translation_service.instance_variable_get(:@path) == ArgosTranslateService::ARGOS_BIN,
      'default binary path points at the server install (/opt/argos/bin)')
check(TranslationAgent.new(rcon: nil, player_db: player_db, backend: :mock).translation_service.is_a?(MockTranslationService),
      'backend :mock wires a MockTranslationService')
# Google backend wiring (no live key — just instantiate)
google_agent = TranslationAgent.new(rcon: nil, player_db: player_db, backend: :google, api_key: 'fake-key')
check(google_agent.translation_service.is_a?(GoogleCloudTranslateService),
      'backend :google wires a GoogleCloudTranslateService')

# Hybrid backend wiring (argos + google)
hybrid_agent = TranslationAgent.new(rcon: nil, player_db: player_db, backend: :hybrid, api_key: 'fake-key')
check(hybrid_agent.translation_service.is_a?(HybridTranslationService),
      'backend :hybrid wires a HybridTranslationService')
check(hybrid_agent.translation_service.instance_variable_get(:@argos).is_a?(ArgosTranslateService),
      'hybrid carries an ArgosTranslateService')
check(hybrid_agent.translation_service.instance_variable_get(:@google).is_a?(GoogleCloudTranslateService),
      'hybrid carries a GoogleCloudTranslateService')

# ── Test 3: argos CLI call — argv pass-through, no shell injection ───
Dir.mktmpdir do |dir|
  script = File.join(dir, 'fake-argos')
  argospm = File.join(dir, 'argospm')
  log = File.join(dir, 'args.log')
  File.write(script, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"#{log}\"\nprintf 'PEREVOD\\n'\n")
  File.chmod(0o755, script)
  File.write(argospm, "#!/bin/sh\necho 'translate-ru_en'\necho 'translate-en_ru'\n")
  File.chmod(0o755, argospm)

  svc = ArgosTranslateService.new(path: script)
  text = "Zdravstvuyte $(touch injected) `touch backticked`"
  result = svc.to_english(text, source_lang: 'ru')

  check(result == 'PEREVOD', 'argos CLI output is returned as the translation')
  check(File.readlines(log).map(&:strip) == ['--from-lang', 'ru', '--to-lang', 'en', text],
        'CLI received the message verbatim as ONE argv (from-lang/to-lang order)')
  check(!File.exist?(File.join(dir, 'injected')) && !File.exist?(File.join(dir, 'backticked')),
        'no shell interpolation: $(...) and `...` in chat text are not executed')

  # NUL bytes (packet padding) must not reach the spawn: IO.popen rejects them
  svc.to_english("a\0b", source_lang: 'ru')
  check(File.readlines(log).map(&:strip).last == 'ab', 'NUL bytes scrubbed before the argv is built')

  # argos' python logging warnings go to stderr — they must never become the
  # "translation"
  noisy = File.join(dir, 'noisy-argos')
  File.write(noisy, "#!/bin/sh\necho '2026-09-17 17:06:58 WARNING: Language en package default expects mwt' >&2\nprintf 'PEREVOD\\n'\n")
  File.chmod(0o755, noisy)
  noisy_svc = ArgosTranslateService.new(path: noisy)
  check(noisy_svc.to_english('x', source_lang: 'ru') == 'PEREVOD',
        'stderr log lines are not captured as the translation')

  # supported? is seeded from argospm list; ru is present, hu is not
  check(svc.supported?('ru') && svc.supported?('RU') && svc.supported?('ru-RU'),
        'ru and its variants are reported as supported')
  check(!svc.supported?('hu') && !svc.supported?('hu-HU'),
        'hu is not in fake argospm list → unsupported')
end

# A missing binary falls back to the original text instead of raising
svc = ArgosTranslateService.new(path: '/nonexistent/argos-translate')
check(svc.to_english('privet', source_lang: 'ru') == 'privet',
      'missing argos binary degrades to the original text (server-only feature)')

# ── Test 4: on_chat relays the translation in-game, per player ──────
cmds = []
lua_rcon = Object.new
lua_rcon.define_singleton_method(:command) { |lua| cmds << lua; '' }
reldb = PlayerDatabase.new(nil)
# The live roster drives the relay: index -> name (Lua can't see language
# overrides, so Ruby decides per player and Lua prints by game index).
roster = -> { [{index: 1, name: 'ivan'}, {index: 2, name: 'bob'}, {index: 3, name: 'pedro'}] }
rel = TranslationAgent.new(rcon: lua_rcon, player_db: reldb, backend: :mock, roster: roster)
reldb.add(1, 'ivan', locale: 'ru')   # foreign speaker
reldb.add(2, 'bob', locale: 'en')    # en reader
reldb.add(3, 'pedro', locale: 'pt')  # pt reader
_, translated = rel.on_chat({ game_player: 1 }, 'привет')
check(translated == '[en] привет', 'on_chat returns the English translation')
check(cmds.size == 1, 'relay issued exactly one batched RCON command')
ru_cmd = cmds.first
check(ru_cmd.start_with?('/sc '), 'relay Lua carries the /sc silent-console prefix (never sent as chat)')
check(ru_cmd.include?('for _, p in pairs(game.connected_players)'),
      'relay loops game.connected_players in Lua (live roster)')
check(ru_cmd.include?('[2]="[ru>en]') && ru_cmd.include?('[3]="[en->pt]'),
      'relay precomputes EN->en and EN->pt entries keyed by game index')
check(!ru_cmd.include?('[1]='), 'speaker excluded — ru readers already saw the original')
check(ru_cmd.include?('local x = t[p.index]') && ru_cmd.include?('p.print(x, ps)'),
      'relay dispatches per player INDEX — Lua cannot see the language overrides')
check(ru_cmd.include?('local n = "ivan"'), 'relay carries the speaker name')
check(ru_cmd.include?('local s = game.players[n]') && ru_cmd.include?('s.chat_color or s.color'),
      'relay picks up the speaker chat_color (falling back to color)')
check(ru_cmd.include?('{color = (s.chat_color or s.color)}'),
      'relay passes the whole line in the speaker color via print settings')

# pt speaker: relay reaches ru AND en readers in their own languages
rel.on_chat({ game_player: 3 }, 'hola')
check(cmds.size == 2, 'pt speaker also relays')
pt_cmd = cmds.last
check(pt_cmd.include?('[1]="[en->ru]') && pt_cmd.include?('[2]="[pt>en]'), 'pt relay has ru + en index entries')
check(!pt_cmd.include?('[3]='), 'speaker excluded for the pt relay too')

# /simulate runs simulate_translation: translate AND relay, exactly like a
# real chat message would
sim_translated = rel.simulate_translation('ivan', 'ru', 'привет')
check(sim_translated == '[en] привет', 'simulate_translation returns the EN text')
check(cmds.last.include?('for _, p in pairs(game.connected_players)'),
      'simulate_translation relays the in-game print (what /simulate runs)')

rel.simulate_translation('pedro', 'pt-BR', 'olá')
check(cmds.last.include?('[2]="[pt>en]') && !cmds.last.include?('pt-BR'),
      'regional speaker locale is shortened in the relay tag (pt-BR -> pt)')

# ── Test 5: join-time locale capture (one targeted RCON query) ───────
join_cmds = []
join_rcon = Object.new
join_rcon.define_singleton_method(:command) { |lua| join_cmds << lua; 'ru' }
jdb = PlayerDatabase.new(nil)
jdb.add(5, 'StarBurtS')  # joiner: players-cache.json locale is null
jag = TranslationAgent.new(rcon: join_rcon, player_db: jdb, backend: :mock)
jag.note_joined(5, 'StarBurtS')
check(join_cmds.size == 1, 'join learns the locale with exactly ONE rcon query')
check(join_cmds.first.include?('/sc ') && join_cmds.first.include?('game.players["StarBurtS"]'),
      'join query targets the player by name, /sc-prefixed')
check(jdb.get_locale(5) == 'ru', 'locale stored into player_db at the confirmed index')

# unknown/nil locale: nothing stored, no crash
nil_rcon = Object.new
nil_rcon.define_singleton_method(:command) { |_| 'nil' }
jdb2 = PlayerDatabase.new(nil)
jdb2.add(6, 'Unknown')
TranslationAgent.new(rcon: nil_rcon, player_db: jdb2, backend: :mock).note_joined(6, 'Unknown')
check(jdb2.get_locale(6).nil?, 'unknown locale is not stored')

# ── Test 6: no fallback duplication; whitelist; NUL bytes scrubbed ──────
# A whitelisted locale whose pack is missing (backend returns the EN text
# as-is) must get NO relay line — the target already saw that EN text.
class MissingPackService < MockTranslationService
  def from_english(text, target_lang:)
    target_lang == 'pt' ? text : super
  end
end
fdb = PlayerDatabase.new(nil)
fdb.add(1, 'ivan', locale: 'ru')
fdb.add(2, 'bob', locale: 'en')
fdb.add(3, 'pedro', locale: 'pt')
fcmds = []
pt_rcon = Object.new
pt_rcon.define_singleton_method(:command) { |lua| fcmds << lua; '' }
pt_agent = TranslationAgent.new(rcon: pt_rcon, player_db: fdb, backend: :mock, roster: -> { [{index: 1, name: 'ivan'}, {index: 2, name: 'bob'}, {index: 3, name: 'pedro'}] })
pt_agent.instance_variable_set(:@translation_service, MissingPackService.new)
pt_agent.on_chat({ game_player: 1 }, "привет\0\0")
check(fcmds.first.include?('[2]="[ru>en]') && !fcmds.first.include?('[3]='),
      'whitelisted locale with unchanged translation is skipped (no duplicated EN text)')
check(!fcmds.first.include?("\0"), 'NUL bytes scrubbed before the relay Lua is built')

# Non-whitelisted locale (fr) — no relay entry; fr readers already saw the
# original EN broadcast. Only en (and whitelisted) locales appear in the relay.
nw_cmds = []
nw_rcon = Object.new
nw_rcon.define_singleton_method(:command) { |lua| nw_cmds << lua; '' }
nw_db = PlayerDatabase.new(nil)
nw_db.add(1, 'ivan', locale: 'ru')
nw_db.add(2, 'bob', locale: 'en')
nw_db.add(3, 'pierre', locale: 'fr')
nw_agent = TranslationAgent.new(rcon: nw_rcon, player_db: nw_db, backend: :mock,
  roster: -> { [{index: 1, name: 'ivan'}, {index: 2, name: 'bob'}, {index: 3, name: 'pierre'}] })
nw_agent.on_chat({ game_player: 1 }, 'привет')
check(nw_cmds.first&.include?('[2]="[ru>en]') && !nw_cmds.first&.include?('[3]='),
      'non-whitelisted locale gets no relay entry; en readers still do')

# ── Test 7: language overrides (players-locale.json / /locales) ───────
# KrlosUltimate: pt-BR interface, but reads/writes English — when ENGLISH is
# among his overrides his own messages are treated as English (not
# translated), and he receives no relay lines for messages he can read.
over_cmds = []
over_rcon = Object.new
over_rcon.define_singleton_method(:command) { |lua| over_cmds << lua; '' }
over_db = PlayerDatabase.new(nil)
over_db.add(1, 'KrlosUltimate', locale: 'pt-BR')
over_db.add(2, 'bob', locale: 'en')
over_db.add(3, 'pedro', locale: 'pt')
over_db.add(4, 'ivan', locale: 'ru')
over_db.set_locale_overrides('KrlosUltimate', ['en', 'pt'])
over_agent = TranslationAgent.new(rcon: over_rcon, player_db: over_db, backend: :mock,
  roster: -> { [{index: 1, name: 'KrlosUltimate'}, {index: 2, name: 'bob'}, {index: 3, name: 'pedro'}, {index: 4, name: 'ivan'}] })

# Overridden speaker writes English: message is the relay base, NOT translated
_, en_msg = over_agent.on_chat({ game_player: 1 }, 'checking the belt layout')
check(en_msg == 'checking the belt layout', 'en-overridden speaker message is not translated to [en]')
last = over_cmds.last
check(last.include?('[3]="[en->pt]') && last.include?('[4]="[en->ru]'),
      'en speaker relays are localized for pt/ru readers')
check(!last.include?('[1]=') && !last.include?('[2]='),
      'overridden speaker + en readers get no relay line (they read the original)')

# Overridden pt-BR reader: gets no relay line for pt or en messages
over_agent.on_chat({ game_player: 3 }, 'hola que tal')
last = over_cmds.last
check(!last.include?('[1]='), 'overridden pt-BR reader receives no pt relay line (reads pt)')
check(last.include?('[2]="[pt>en]') && last.include?('[4]="[en->ru]'),
      'pt speaker still relays to en + ru readers')

# ── Test 8: PlayerDatabase locale-override persistence ─────────────────
Dir.mktmpdir do |dir|
  cache = File.join(dir, 'players-cache.json')
  db = PlayerDatabase.new(cache)
  db.add(7, 'KrlosUltimate', locale: 'pt-BR')
  db.set_locale_overrides('KrlosUltimate', ['en', 'pt'])
  check(db.locale_overrides('KrlosUltimate') == ['en', 'pt'], 'overrides stored by name')

  db2 = PlayerDatabase.new(cache)
  check(db2.locale_overrides('KrlosUltimate') == ['en', 'pt'],
        'overrides survive reload from players-locale.json')
  check(File.exist?(File.join(dir, 'players-locale.json')),
        'locale overrides live in players-locale.json next to the cache')
  check(db2.lookup(7) == 'KrlosUltimate' && db2.get_locale(7) == 'pt-BR',
        'cache file keeps id -> name/locale (players-cache.json)')

  # clearing: empty array removes the entry
  db2.set_locale_overrides('KrlosUltimate', [])
  db3 = PlayerDatabase.new(cache)
  check(db3.locale_overrides('KrlosUltimate').nil?, 'empty override clears the persisted entry')
end

# Legacy players.json is NOT migrated — the cache is re-seeded from RCON
# at startup anyway; stale disk entries would only preserve renames/leavers.

puts "\n#{'-' * 40}\n#{$pass} passed, #{$fail} failed"
exit($fail.zero? ? 0 : 1)