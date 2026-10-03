# frozen_string_literal: true

require 'ruby_llm'

# Hivemind feature `tags` — the file is lib/hivemind_tags.rb (the plugin
# set's `hivemind_` prefix), the class takes its CamelCase name. Listed in
# config-hivemind.yaml `plugins:` and built by the agent's own
# Plugins::PluginSet with the agent as its owner. It is OFF by default in the
# example config: tagging players is a policy choice (who decides what a
# player's tag says, and the model rewrites it as they evolve), not a
# baseline capability, so a deployment that does not want the agent writing
# to player state simply leaves the name out of the list — the file is never
# required and the tool is never offered.
#
# The TOOL lives here with the feature, not in hivemind_tools.rb: it is the
# only state-changing tool the model has, and "this write happens" should be
# one switch.
class HivemindTags
  # The agent, as its owner. Nothing else is needed — the RCON client is
  # passed per call, because tools are rebuilt fresh before every ask (the
  # agent's register_tools, which routes here).
  def initialize(host)
    @host = host
  end

  attr_reader :host

  # Offer set_player_tag on this chat. with_tool replaces by name, so calling
  # it before every ask is idempotent and picks up tool code changes made by
  # a hot reload.
  def register(chat, rcon)
    chat.with_tool(SetPlayerTag.new(rcon: rcon))
  end
end

# RubyLLM tool: set a Factorio player's overhead/chat tag. The ONLY
# state-changing tool the model has — everything else (rcon_query) stays
# read-only.
# Tags DESCRIBE (shown next to the name in chat/overhead) but never alter
# mechanics, which is why this narrow write is safe to expose while
# arbitrary /sc Lua is not: name and tag are Lua-quoted inside RconClient
# so neither can inject code, and the write targets exactly one field
# (game.players[name].tag). Empty tag clears it.
#
# A tag is not a one-off label: the instruction tells the model to keep it
# current from what it learns — set it when it has learned enough about a
# player, and revise it as the player's role in the run changes (a scout
# who starts building walls stops being "scout"). Tags are shown next to the
# name, so they stay short and factual.
class SetPlayerTag < RubyLLM::Tool
  def name
    'set_player_tag'
  end
  desc 'Set a Factorio player overhead/chat tag (game.players[name].tag), ' \
       'shown next to their name in chat and above their character. Tags only ' \
       'describe — they never change game mechanics. This is the ONLY tool that ' \
       'may change game state; rcon_query stays read-only. Check the exact ' \
       'player name with rcon_query (/players) first — unknown names error. ' \
       'Keep tags current as you learn about a player: once you know what ' \
       'they do (their role in the run, what they build, how they play), set ' \
       'a short tag for them — and revise it when that changes as the run ' \
       'goes on. A stale tag is worse than no tag: if you have nothing new ' \
       'to say about someone, leave their tag alone. An empty tag clears it.'

  param :player, type: 'string',
                  desc: 'Exact player name (must have joined the server before).'
  param :tag, type: 'string',
               desc: 'Tag text, max 64 chars; empty clears the tag.'

  def initialize(rcon:)
    @rcon = rcon
  end

  def execute(player:, tag:)
    if @rcon.set_player_tag(player, tag)
      "Tag set for #{player}."
    else
      "Error: unknown player '#{player}' (or RCON failed) — verify the name with rcon_query /players."
    end
  rescue StandardError => e
    "RCON error: #{e.class}: #{e.message}"
  end
end