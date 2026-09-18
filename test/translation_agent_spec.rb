#!/usr/bin/env ruby
# Tests for the TranslationAgent backends + the /simulate console command.
#
# Regression: /simulate called @translation_agent.translate_service (typo;
# the attr_reader is translation_service) and NoMethodError'd on EVERY run —
# with no test asserting the command, the break sailed through. Test 1
# drives the real /simulate handler and fails on the typo'd code.
# Argos is only installed on the target server, so Test 3 runs a fake
# `argos-translate` script (argv echo) instead of the real binary.
# Run: ruby -Ilib test/translation_agent_spec.rb

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

# ── Test 4: on_chat relays the translation in-game, per player locale ─
cmds = []
lua_rcon = Object.new
lua_rcon.define_singleton_method(:command) { |lua| cmds << lua; '' }
reldb = PlayerDatabase.new(nil)
# Agent built BEFORE the roster dump lands (sniffer constructs the agent in
# initialize, load_roster fills player_db later in run) — the first relay
# lazy-seeds from player_db with NO RCON query.
rel = TranslationAgent.new(rcon: lua_rcon, player_db: reldb, backend: :mock)
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
check(ru_cmd.include?('{["en"]=') && ru_cmd.include?(',["pt"]='),
      'relay precomputes EN->en and EN->pt entries from the locale snapshot')
check(!ru_cmd.include?('["ru"]='), 'speaker locale excluded — ru readers already saw the original')
check(ru_cmd.include?('local x = t[p.locale]') && ru_cmd.include?('p.print("["..'),
      'relay dispatches per player on their locale')
check(ru_cmd.include?('local n = "ivan"'), 'relay carries the speaker name')
check(ru_cmd.include?('p.locale:match("^[^-]+")'), 'relay tags each print with the short locale')
check(ru_cmd.include?('local tag = (p.locale == "en") and (sl..">en") or ("en->"..pl)'),
      'relay tag format is [from->to] based on speaker locale')
check(ru_cmd.include?('] "..n..": "..x, ps)'), 'relay prints as [tag] name: text')
check(ru_cmd.include?('local s = game.players[n]') && ru_cmd.include?('s.chat_color or s.color'),
      'relay picks up the speaker chat_color (falling back to color)')
check(ru_cmd.include?('{color = (s.chat_color or s.color)}'),
      'relay passes the whole line in the speaker color via print settings')

# pt speaker: relay reaches ru AND en readers in their own locales
rel.on_chat({ game_player: 3 }, 'hola')
check(cmds.size == 2, 'pt speaker also relays')
pt_cmd = cmds.last
check(pt_cmd.include?('["ru"]=') && pt_cmd.include?('["en"]='), 'pt relay has ru + en entries')
check(!pt_cmd.include?('["pt"]='), 'speaker locale excluded for the pt relay too')

# /simulate runs simulate_translation: translate AND relay, exactly like a
# real chat message would
sim_translated = rel.simulate_translation('ivan', 'ru', 'привет')
check(sim_translated == '[en] привет', 'simulate_translation returns the EN text')
check(cmds.last.include?('for _, p in pairs(game.connected_players)'),
      'simulate_translation relays the in-game print (what /simulate runs)')

rel.simulate_translation('pedro', 'pt-BR', 'olá')
check(cmds.last.include?('local sl = "pt";') && !cmds.last.include?('local sl = "pt-BR";'),
      'regional speaker locale is shortened in the relay tag (pt-BR -> pt)')

# ── Test 5: join-time locale capture (one targeted RCON query) ───────
join_cmds = []
join_rcon = Object.new
join_rcon.define_singleton_method(:command) { |lua| join_cmds << lua; 'ru' }
jdb = PlayerDatabase.new(nil)
jdb.add(5, 'StarBurtS')  # joiner: players.json locale is null
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
pt_agent = TranslationAgent.new(rcon: pt_rcon, player_db: fdb, backend: :mock)
pt_agent.instance_variable_set(:@translation_service, MissingPackService.new)
pt_agent.on_chat({ game_player: 1 }, "привет\0\0")
check(fcmds.first.include?('["en"]=') && !fcmds.first.include?('["pt"]='),
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
nw_agent = TranslationAgent.new(rcon: nw_rcon, player_db: nw_db, backend: :mock)
nw_agent.on_chat({ game_player: 1 }, 'привет')
check(nw_cmds.first&.include?('["en"]=') && !nw_cmds.first&.include?('["fr"]='),
      'non-whitelisted locale gets no relay entry; en readers still do')

puts "\n#{'-' * 40}\n#{$pass} passed, #{$fail} failed"
exit($fail.zero? ? 0 : 1)