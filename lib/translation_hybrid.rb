# frozen_string_literal: true

# HybridTranslationService — argos primary, Google Cloud fallback.
# Argos is free+local and handles en<->pt, en<->ru well. It lacks direct
# pt<->ru packs, so for unsupported pairs (detected by unchanged output)
# we fall back to Google Cloud (paid, but covers any pair).
require_relative 'translation_argos'
require_relative 'translation_google'

class HybridTranslationService
  def initialize(google_api_key, argos_path: ArgosTranslateService::ARGOS_BIN)
    @argos = ArgosTranslateService.new(path: argos_path)
    @google = GoogleCloudTranslateService.new(google_api_key)
    @cache = {}
    @mutex = Mutex.new
  end

  def translate(text, source_lang:, target_lang:)
    return text if text.nil? || text.strip.empty?
    return text if source_lang == target_lang && source_lang != 'auto'

    cache_key = "#{source_lang}|#{target_lang}|#{text}"
    @mutex.synchronize { return @cache[cache_key] if @cache.key?(cache_key) }

    result = try_translate(text, source_lang, target_lang)
    @mutex.synchronize { @cache[cache_key] = result } if result && result != text
    result
  rescue StandardError => e
    warn "[translation] Hybrid error: #{e.class}: #{e.message}"
    text
  end

  private

  def try_translate(text, source_lang, target_lang)
    s = normalize_locale(source_lang)
    t = normalize_locale(target_lang)

    # Try argos first when it claims to know both ends
    if @argos.supported?(s) && @argos.supported?(t)
      argos_result = @argos.translate(text, source_lang: s, target_lang: t)
      # Different output → argos actually translated it; use it
      return argos_result if argos_result != text
    end

    # Unchanged output or unsupported pair → fall back to Google
    @google.translate(text, source_lang: s, target_lang: t)
  end

  def normalize_locale(locale)
    return 'auto' if locale == 'auto'
    locale.split('-').first&.downcase || 'en'
  end
end
