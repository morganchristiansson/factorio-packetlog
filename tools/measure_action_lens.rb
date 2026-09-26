#!/usr/bin/env ruby
# frozen_string_literal: true

# Measure and audit the 2.0 client→server input-action payload lengths.
#
# Every C→S heartbeat ends with an 8-byte [tick(4)][pad(4)] block, so a tick
# closure's action bytes end at a known offset: with every action's length known
# but one, that one is arithmetic (ActionLenSolver). This tool drives that over a
# capture set — one pass, whatever the question.
#
#   ruby tools/measure_action_lens.rb PCAP...          what is still undecoded,
#                                                       worst offenders first
#   ruby tools/measure_action_lens.rb --decide PCAP... everything the wire
#                                                       settles that the table lacks
#   ruby tools/measure_action_lens.rb --type 88 ...    just one type, with its
#                                                       candidate tally
#   ruby tools/measure_action_lens.rb --check PCAP...  does the shipped table
#                                                       still agree with the wire
#
# It does NOT write the table. Lengths are added deliberately, one type at a
# time, and --check guards them: an earlier version of this tool wrote the table
# from a walk that read every action header without skipping payloads, so in a
# two-action closure the second type came from inside the first action's data and
# the arithmetic was meaningless while looking fine. A tool that cannot defend
# its numbers should not be able to write them.
#
# Accepts any pcap, gz included; only client→server heartbeats are read.
require 'json'
require 'optparse'
require_relative 'action_len_solver'
require_relative '../lib/factorio_protocol'

MIN_OBS = 5    # distinct closures that must agree
MARGIN = 3     # and this factor over the runner-up
opts = OptionParser.new do |o|
  o.on('--check', 'verify every C2S_LENS_20 entry against the wire') { @check = true }
  o.on('--decide', 'list every type the wire decides but the table lacks') { @decide = true }
  o.on('--type N', Integer, 'measure one action type') { |v| @type = v }
  o.on('--json', 'machine-readable output') { @json = true }
end
opts.parse!
args = ARGV.reject { |a| a.start_with?('--') }
abort 'usage: measure_action_lens.rb [--check|--decide|--type N] [--json] PCAP...' if args.empty?

FactorioProtocol.select_version('2.0')
lens = FactorioProtocol.c2s_lens || {}
name = ->(t) { FactorioProtocol::ACTIONS_20[t]&.first || '** UNIDENTIFIED **' }
CODE = ActionLenSolver::CODE_PARSED

def tally_for(paths, lens, type)
  { type => ActionLenSolver.measure(paths, lens, type)[:tally] }
end

# ── One pass: what does the wire say about every type it can see? ───────
# The corpus tally asks the wire about every type the walk cannot cross; a
# single-type query instead HIDES that type, so it becomes the hole — otherwise
# the walk steps over it and there is nothing to measure.
tally = @type ? tally_for(args, lens, @type) : ActionLenSolver.measure_all(args, lens, code_parsed: CODE)
decided = {}
tally.each do |t, by_len|
  next if t > 400 # a desync artefact, not an action
  ranked = by_len.sort_by { |_, n| -n }
  best, top = ranked.first
  second = ranked[1]&.last.to_i
  decided[t] = { length: best, votes: top, second: second } if top && top >= MIN_OBS && second * MARGIN < top
end

# ── --type N: the same pass, filtered ──────────────────────────────────
if @type
  t = @type
  d = decided[t]
  if @json
    puts JSON.generate(type: t, name: name[t], table: lens[t],
                       verdict: d ? 'measured' : 'ambiguous', length: d&.fetch(:length, nil),
                       votes: d&.fetch(:votes, nil), runner_up: d&.fetch(:second, nil),
                       tally: tally[t].to_h.transform_values(&:to_i))
  else
    puts "type #{t} (#{name[t]}) — table says #{lens[t].inspect}, #{args.size} file(s)"
    if tally[t].empty?
      puts '  no decisive closure: this action never appears where the rest of the'
      puts '  closure is measurable. Needs more traffic, or a layout decode.'
    else
      tally[t].sort_by { |_, n| -n }.first(6).each { |l, n| puts "  length #{l}: #{n} closures#{d && l == d[:length] ? '  <-' : ''}" }
      puts "  verdict: #{d ? "measured (#{d[:length]} bytes, #{d[:votes]} closures, runner-up #{d[:second]})" : 'ambiguous'}"
    end
  end
  exit(d ? 0 : 1)
end

# ── --check: does the shipped table still agree with the wire? ─────────
if @check
  bad = lens.filter_map do |t, claimed|
    d = decided[t]
    [t, claimed, d[:length], d[:votes]] if d && d[:length] != claimed
  end
  if bad.empty?
    puts "all #{lens.size} C2S_LENS_20 entries the wire can decide agree"
    exit 0
  end
  bad.sort_by { |t, _, _, v| -v }.each do |t, claimed, got, votes|
    puts "  #{t} #{name[t]}: table #{claimed}, wire says #{got} (#{votes} closures)"
  end
  exit 1
end

# ── --decide (and the default): what is left, worst first ─────────────
fresh = decided.reject { |t, _| lens.key?(t) }
if @json
  puts JSON.generate(measured: lens.size,
                     undecided: fresh.transform_values { |d| d[:length] },
                     candidates: fresh.transform_values { |d| { length: d[:length], votes: d[:votes] } })
  exit 0
end
puts "C2S_LENS_20: #{lens.size} measured lengths; capture set: #{args.size} file(s)"
puts
if fresh.empty?
  puts '== nothing new: the wire decides nothing the table lacks =='
else
  puts '== the wire decides, the table lacks =='
  fresh.sort_by { |t, d| [-d[:votes], t] }.each do |t, d|
    printf("  %-5d %-42s => %-4d  (%d closures, runner-up %d)\n", t, name[t], d[:length], d[:votes], d[:second])
  end
end

puts "\n== unmeasured types ranked by failure rate (the tail work-list) =="
rate = Hash.new { |h, k| h[k] = [0, 0] }
ActionLenSolver.each_payload(args) do |data|
  walk = ActionLenSolver.walk_lens_for(data, lens)
  b = ActionLenSolver.bounds(data)
  next unless b
  count, area_start, = b
  actions, = ActionLenSolver.walk(data, area_start, count, walk)
  unk = actions.map(&:first).uniq.reject do |t|
    walk.key?(t) || CODE.include?(t) || FactorioProtocol::ACTIONS_20[t]&.last == 0
  end
  next if unk.empty?
  parsed = (FactorioProtocol.parse_udp_payload(data) rescue nil)
  bad = parsed&.dig(:heartbeat)&.dig(:tick_closures).to_a.any? { |c| (c[:actions] || []).any? { |x| x[:hit_unknown] } }
  unk.each { |t| rate[t][bad ? 0 : 1] += 1 }
end
rate.select { |_, (f, _)| f.positive? }.sort_by { |_, (f, c)| [-f, -c] }.first(20).each do |t, (f, c)|
  printf("  %-5d %-42s %4d failing / %5d closures\n", t, name[t], f, f + c)
end
puts "\n#{rate.size} unmeasured types seen. To decide one:"
puts '  ruby tools/measure_action_lens.rb --type N captures/*.pcap'
