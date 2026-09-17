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

  def to_english(text, source_lang:)
    translate(text, source_lang: source_lang, target_lang: 'en')
  end

  def from_english(text, target_lang:)
    translate(text, source_lang: 'en', target_lang: target_lang)
  end

  def needed?(player_locale, our_locale)
    player_locale != our_locale
  end

  def clear_cache!
    @mutex.synchronize { @cache.clear }
  end
end
