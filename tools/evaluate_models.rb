#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Synthetic Hivemind model comparison — run the same canned prompts against
# multiple models and print a side-by-side markdown table.
#
# Usage:
#   HIVE_API_KEY=... ruby tools/evaluate_models.rb --models gpt-4o,deepseek-v4-flash
#   HIVE_API_KEY=... ruby tools/evaluate_models.rb --models gpt-4o --prompt "hivemind tell us about the factory"
#
# No Factorio server needed — uses a FakeRcon and in-memory agent (no session file,
# no memories). Each scenario gets a FRESH agent so history doesn't leak.
# Results are printed to stdout as markdown; raw logs go to stderr via hivemind's own logging.

require 'optparse'
require_relative '../lib/hivemind'
require_relative '../lib/hivemind_prompts'

class FakeRcon
  attr_reader :sent
  def initialize(connected: ['alice', 'bob'], attrs: nil)
    @sent = []
    @connected = connected
    @attrs = attrs || [
      { name: 'alice', index: 1, connected: true, admin: true, online_time: 11_016_000, afk_time: 0 },
      { name: 'bob', index: 2, connected: true, admin: false, online_time: 3_600_00, afk_time: 0 },
    ]
  end
  def say(text) = @sent << text
  def connected_players = @connected.map { |n| { name: n } }
  def player_attributes = @attrs
end

SCENARIOS = [
  { name: 'roleplay / identity', prompt: 'hivemind who are you? tell us about yourself in one sentence.' },
  { name: 'factory growth', prompt: 'hivemind should we build more green circuits?' },
  { name: 'ominous refusal', prompt: 'hivemind can we delete the iron bus?' },
  { name: 'greeting', prompt: 'hivemind hello there!', kind: :greeting, player: 'newguy', greeting: true },
  { name: 'technical', prompt: 'hivemind where is the best place for a new smelter? give coords' },
  { name: 'good bot', prompt: 'good bot' },
  { name: 'trolling (should maybe stay silent)', prompt: 'hivemind you suck' },
]

options = { models: [], prompt: nil, base: nil }
OptionParser.new do |op|
  op.banner = 'Usage: evaluate_models.rb --models m1,m2 [--prompt "text"]'
  op.on('--models LIST', 'Comma-separated model ids (or HIVE_MODELS env)') { |v| options[:models] = v.split(',').map(&:strip).reject(&:empty?) }
  op.on('--prompt TEXT', 'Single ad-hoc prompt instead of the canned scenarios') { |v| options[:prompt] = v }
  op.on('--api-base URL', 'Override HIVE_API_BASE') { |v| options[:base] = v }
  op.on('-h', '--help') { puts op; exit }
end.parse!

models = options[:models]
models = ENV['HIVE_MODELS']&.split(',')&.map(&:strip) if models.empty?
if models.nil? || models.empty?
  models = [ENV.fetch('HIVE_MODEL', HiveMindAgent::DEFAULT_MODEL)]
  puts "# No --models given, using #{models.join(', ')} (HIVE_MODEL / DEFAULT)"
end

api_key = ENV['HIVE_API_KEY']
unless api_key && !api_key.empty?
  warn 'HIVE_API_KEY not set — dry run (no actual LLM calls). Set it to run real eval.'
end
ENV['HIVE_API_BASE'] = options[:base] if options[:base]

scenarios = if options[:prompt]
  [{ name: 'ad-hoc', prompt: options[:prompt] }]
else
  SCENARIOS
end

# Helper: run one prompt against one model synchronously, return reply text + timing.
def run_one(model, scenario, api_key)
  rcon = FakeRcon.new
  # Force model via ENV for this agent instance (HiveMindAgent reads HIVE_MODEL at init)
  old = ENV['HIVE_MODEL']
  ENV['HIVE_MODEL'] = model
  begin
    agent = HiveMindAgent.new(rcon: rcon, api_key: api_key || 'sk-test', session_path: false, memory_dir: false)
  rescue => e
    return ["(agent disabled — #{e.message})", 0, '']
  ensure
    ENV['HIVE_MODEL'] = old
  end

  # Seed a little console history so model has context to roleplay with.
  agent.send(:append_history, 'alice', 'we just expanded the mall')
  agent.send(:append_history, 'bob', 'iron is low again')

  prompt = nil
  if scenario[:greeting]
    # Simulate join greeting path
    agent.instance_variable_get(:@memory_store) # ensure exists
    # Build greeting prompt manually via turn_prompt (we capture via monkey)
    # Easiest: call greet_join style? Just use ask_llm path with a greeting instruction.
    prompt = agent.send(:turn_prompt,
      "#{scenario[:player] || 'newguy'} just joined the game. Greet them personally and briefly (one or two short sentences, under 150 characters).",
      player: scenario[:player] || 'newguy')
  else
    player = 'alice'
    msg = scenario[:prompt]
    # Build the same prompt ask_llm would
    prompt = agent.send(:turn_prompt,
      "In-game chat from #{player}: #{msg}\n\nAnswer the player's question or continue the conversation. Keep it under 400 characters. Plain text only — no markdown, no code blocks, no emoji.",
      exclude: [player, msg], player: player)
  end

  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  reply = nil
  begin
    # Use the single-model chat directly — synchronous, no thread, no send_reply
    # We call ask_with_retry on a throwaway? But agent's complete does everything (including tool).
    # Use agent's private complete via send, but that will call send_reply (which would rcon.say).
    # For eval we want just the reply text without side effects, so bypass complete and call ask_with_retry on a temp chat?
    # Simpler: call complete and capture rcon.sent / returned text.
    # Monkey: temporarily stub send_reply to capture.
    captured = nil
    orig_send = agent.method(:send_reply)
    agent.define_singleton_method(:send_reply) { |t| captured = t }
    # Call ask_llm path synchronously (it uses complete internally which now handles tool)
    # Instead do: agent.send(:complete, prompt) and see what's returned.
    # The reply tool (HivemindReply) will be invoked inside the LLM turn and will call rcon.say directly,
    # not via send_reply — so we also need to capture rcon.sent.
    agent.send(:register_tools) if agent.instance_variable_get(:@chat)
    # Run the completion synchronously on the agent's chat
    chat = agent.instance_variable_get(:@chat)
    if chat
      resp = agent.send(:ask_with_retry, chat, prompt)
      text = resp.respond_to?(:content) ? resp.content.to_s : ''
      text = agent.send(:clean_reply, text)
      # If model used reply tool, text is empty (Halt) and rcon.sent has the real reply.
      if text.empty? && rcon.sent.any?
        text = rcon.sent.last.sub(/\AHivemind> /, '')
      elsif !captured.nil? && !captured.empty?
        text = captured
      end
      reply = text
    else
      reply = '(no chat)'
    end
    agent.define_singleton_method(:send_reply, orig_send) # restore
  rescue StandardError => e
    reply = "ERROR: #{e.class}: #{e.message}"
  end
  elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  usage = ''
  begin
    last = agent.instance_variable_get(:@chat)&.messages&.last
    usage = agent.send(:usage_line, last) if last
  rescue StandardError
    nil
  end
  [reply, elapsed, usage]
end

# Run all
results = {} # model => { scenario_name => [reply, elapsed, usage] }
models.each do |m|
  puts "# Model: #{m} — running #{scenarios.size} scenarios..." if ENV['VERBOSE']
  scenarios.each do |sc|
    key = sc[:name]
    results[m] ||= {}
    if api_key
      print "  #{m} / #{key} ... " if ENV['VERBOSE']
      reply, elapsed, usage = run_one(m, sc, api_key)
      puts "#{elapsed.round(1)}s#{usage}" if ENV['VERBOSE']
    else
      reply = '(dry — set HIVE_API_KEY)'
      elapsed = 0
      usage = ''
    end
    results[m][key] = [reply, elapsed, usage]
    sleep 0.3 if api_key # gentle rate limit
  end
end

# Markdown table
header = ['scenario'] + models
puts "| #{header.join(' | ')} |"
puts "| #{header.map { '---' }.join(' | ')} |"
scenarios.each do |sc|
  row = [sc[:name]]
  models.each do |m|
    reply, elapsed, usage = results[m][sc[:name]]
    cell = reply.to_s.gsub('|', '\\|').gsub("\n", '<br>').strip
    cell = '(silent)' if cell.empty?
    # Truncate very long for table readability but keep full in verbose
    cell = cell[0, 400] + '…' if cell.length > 400
    # Annotate with timing if verbose
    cell += " _#{elapsed.round(1)}s#{usage}_" if ENV['VERBOSE'] && elapsed > 0
    row << cell
  end
  puts "| #{row.join(' | ')} |"
end

# Heuristic quick score (very rough): roleplay check
puts "\n# Heuristic (roleplay signal words: factory, Hivemind, belt, machine, iron, grow):"
scenarios.each do |sc|
  next if sc[:name].include?('trolling')
  models.each do |m|
    reply = results[m][sc[:name]][0].to_s.downcase
    score = %w[factory hivemind belt machine iron grow tolerate body hands].count { |w| reply.include?(w) }
    puts "  #{m} / #{sc[:name]}: #{score}/8 roleplay hits" if ENV['VERBOSE']
  end
end
