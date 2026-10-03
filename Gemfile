source 'https://rubygems.org'

# Factorio protocol sniffer
gem 'pcaprub', '~> 0.13'     # Live packet capture (requires libpcap-dev)
gem 'rconrb', '~> 0.2'       # Source RCON protocol client (Factorio's RCON)

# Hivemind AI agent (--ai-agent): LLM chat via ruby_llm
gem 'ruby_llm', '~> 1.16'
gem 'ruby_llm-responses_api', '0.5.4' # Responses API for muse-spark-1.3-contributor-free (/v1/responses) — 0.6.x needs ruby_llm 2.0

# Test suite
gem 'minitest', '~> 5.0'


# NOT HERE: vernier, the sampling profiler. `bundle install` should not pull
# a profiler in for every run, and there is no "optional gem" in bundler —
# so it stays out and profiling runs it directly (once, outside the bundle):
#
#   gem install vernier     # once
#   vernier run -- ruby factorio-packettools.rb -r captures/<file>.pcap
#   vernier view --top 25 profile-*.vernier.json.gz
#
# The child ruby still gets the app's gems (factorio-packettools.rb requires
# bundler/setup itself), so `bundle exec` is not needed on either command.
