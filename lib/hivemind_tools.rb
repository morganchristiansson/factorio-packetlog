# frozen_string_literal: true

require 'ruby_llm'

# RubyLLM tool classes for the Hivemind agent (see hivemind.rb). Kept in
# their own file so the agent class stays readable; hot-reloadable — listed
# in SNIFFER_LIBS (factorio-sniffer.rb) so Ctrl-C `load` redefines them.

# RubyLLM tool: send a chat message to in-game Factorio chat via RCON.
# The LLM calls this to respond to players. Instantiated with the rcon
# client (RubyLLM's with_tool accepts instances, so dependencies can be
# injected) and keeps track of what was actually sent.
#
# The model-facing tool NAME is "reply" (overridden #name below — RubyLLM
# otherwise derives it from the class name).
#
# Returning Tool::Halt stops the conversation loop after the send, so the
# reply appears in game chat immediately and no follow-up completion is
# generated (faster, and the final text response can't double-send).
class HivemindReply < RubyLLM::Tool
  # Chat prefix shared with the agent's plain-text fallback path (send_reply).
  REPLY_PREFIX = 'Hivemind> '

  # Model-facing name (RubyLLM defaults to the underscored class name,
  # "hivemind_reply"). Sessions persisted before this override carry the
  # old "hivemind_say" name — load_session rewrites those on restore.
  def name
    'reply'
  end
  desc 'Send a message to the in-game Factorio chat, visible to all players. ' \
       'Use this to respond to the player who addressed you.'

  attr_reader :last_sent

  # on_sent: optional callback invoked with the sent text (the agent uses
  # it to append its own replies to the rolling chat history).
  def initialize(rcon:, prefix: REPLY_PREFIX, on_sent: nil)
    @rcon = rcon
    @prefix = prefix
    @last_sent = nil
    @on_sent = on_sent
  end

  def execute(text:)
    @last_sent = text.to_s
    return halt('') if @last_sent.empty?

    puts "#{Time.now.strftime('%H:%M:%S')}  [hivemind] → #{@last_sent}"
    @rcon.say("#{@prefix}#{@last_sent}")
    @on_sent&.call(@last_sent)
    halt('')
  end
end

# RubyLLM tool: run a READ-ONLY RCON console command and return its output.
# Lets the model answer server questions (/players, /time, /evolution,
# /sc rcon.print(...) Lua queries) without hardcoding data. The desc and
# system prompt instruct read-only use — no admin actions, no state changes.
class RconQuery < RubyLLM::Tool
  desc 'Run a READ-ONLY RCON console command on the Factorio server and ' \
       'return its output. Use for queries: /players, /admins, /time, ' \
       '/evolution, /version, /sc rcon.print(...) (Lua queries, e.g. ' \
       'serpent.line of game tables). NEVER use this to modify game state: ' \
       'no admin/permission changes, no commands that build/destroy/reset, ' \
       'no /sc Lua that writes or mutates (game.print replies are handled by ' \
       'the say tool). Read-only queries only.'

  def initialize(rcon:, max_output: 1500)
    @rcon = rcon
    @max_output = max_output
  end

  def execute(command:)
    cmd = command.to_s.strip
    return 'Error: empty command' if cmd.empty?
    cmd = "/#{cmd}" unless cmd.start_with?('/')
    out = @rcon.command(cmd).to_s.strip
    out = "#{out[0, @max_output]}…" if out.length > @max_output
    out.empty? ? '(no output)' : out
  rescue StandardError => e
    "RCON error: #{e.class}: #{e.message}"
  end
end

# RubyLLM tool: batch-overwrite Hivemind's long-term memory blobs. ONLY
# registered on the compaction chat (never on the live conversation) —
# the compaction prompt tells the model to use it to update memories keyed
# by soul / knowledge / <player>. One call carries ALL updates as an
# array, so a compaction pass is a single API round trip instead of one
# call per memory. Each entry replaces its whole blob — the model must
# provide the COMPLETE new content (nothing is merged). The model only
# ever sees keys; file paths are MemoryStore's business.
class WriteMemories < RubyLLM::Tool
  desc 'Overwrite Hivemind long-term memories (batch). Pass ALL updates in ONE call. ' \
       'Each entry has a key and content: key is "soul" (who you are), "knowledge" ' \
       '(durable facts), or a player name (what you know about that player). Content ' \
       'is the COMPLETE new memory — it replaces the whole blob, it is not merged. ' \
       'Only include memories that genuinely changed.'

  params schema: {
    type: 'object',
    properties: {
      memories: {
        type: 'array',
        description: 'All memory updates, batched into this one call.',
        items: {
          type: 'object',
          properties: {
            key: {
              type: 'string',
              description: 'Memory key: "soul", "knowledge", or a player name.'
            },
            content: {
              type: 'string',
              description: 'COMPLETE new content for this memory (replaces the whole blob).'
            }
          },
          required: %w[key content],
          additionalProperties: false
        }
      }
    },
    required: %w[memories],
    additionalProperties: false
  }
  # NOTE: deliberately NO strict:true. This is the only strict tool, and
  # on the current gateway strict mode + this nested array-of-objects
  # schema makes the model emit EMPTY arguments ({}) on every attempt
  # (7-token completions — the payload is never generated; broken
  # constrained decoding, not lost transport). Compaction then spins on
  # "Invalid tool arguments: missing keyword: memories". Every other
  # (non-strict) tool works fine on the same endpoint.

  # What was actually written, as [key, content] pairs (for logging).
  attr_reader :written

  def initialize(store:)
    @store = store
    @written = []
  end

  def execute(memories:)
    memories = memories.is_a?(Array) ? memories : []
    return 'Error: memories must be an array of {key, content} objects.' if memories.empty?
    results = memories.map do |entry|
      entry = entry.is_a?(Hash) ? entry : {}
      key = entry['key'].to_s.strip
      content = entry['content'].to_s
      if key.empty?
        'missing key SKIPPED'
      elsif @store.write_key(key, content)
        @written << [key, content]
        "#{key} updated"
      else
        "#{key} FAILED"
      end
    end
    halt(results.join('; '))
  end
end

# RubyLLM tool: schedule a follow-up turn after a delay (like JavaScript
# setTimeout). The model uses it when a plan or request needs a later
# check/reminder — e.g. "rally the players to defend spawn" →
# schedule_followup(delay 600, "check whether spawn is defended and remind
# players"). When the delay elapses the agent runs a fresh LLM turn whose
# prompt carries the CURRENT context (online players, console lines since
# the last prompt) plus the scheduled task, so the follow-up sees what
# actually happened, can reply via say, run read-only RCON queries, or
# schedule further follow-ups. Returns a follow-up id; CancelFollowUp
# cancels it. Persisted with the session file (absolute deadlines) so a
# restart re-arms pending follow-ups.
class ScheduleFollowUp < RubyLLM::Tool
  desc 'Schedule a follow-up action after a delay — like JavaScript setTimeout. ' \
       'After delay_seconds, you get a fresh turn with the current context ' \
       '(online players, new console lines) and this task. Use it to follow up ' \
       'on plans and requests, e.g. after "rally the players to defend spawn" ' \
       'schedule a reminder or a status check for later. Returns a follow-up id ' \
       '— cancel it with cancel_followup. Minimum delay: 15 seconds.'

  param :delay_seconds, type: 'number',
                        desc: 'How many seconds from now until the follow-up fires (minimum 15).'
  param :task, type: 'string',
               desc: 'What to check or do at that time, written for your future self (which will have fresh context).'

  def initialize(agent:)
    @agent = agent
  end

  def execute(delay_seconds:, task:)
    @agent.schedule_followup(delay_seconds: delay_seconds, task: task)
  end
end

# RubyLLM tool: cancel a pending follow-up (like JavaScript clearTimeout).
class CancelFollowUp < RubyLLM::Tool
  desc 'Cancel a pending follow-up by its id (returned by schedule_followup) — like JavaScript clearTimeout.'

  param :followup_id, type: 'integer',
                      desc: 'The id of the follow-up to cancel.'

  def initialize(agent:)
    @agent = agent
  end

  def execute(followup_id:)
    @agent.cancel_followup(followup_id)
  end
end
