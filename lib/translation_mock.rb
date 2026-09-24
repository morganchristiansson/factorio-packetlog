# frozen_string_literal: true

# Mock translation service — used for testing/default when no real backend is available.
class MockTranslationService
  def initialize
    @cache = {}
    @mutex = Mutex.new
  end

  def translate(text, source_lang:, target_lang:)
    return text if text.nil? || text.strip.empty?
    cache_key = "#{source_lang}|#{target_lang}|#{text}"
    @mutex.synchronize { return @cache[cache_key] if @cache.key?(cache_key) }
    result = "[#{target_lang}] #{text}"
    @mutex.synchronize { @cache[cache_key] = result }
    result
  end

end
