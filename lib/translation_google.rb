# frozen_string_literal: true

# GoogleCloudTranslateService — Google Cloud Translation API (v2 REST).
# Supports direct translation between any language pair (pt <-> ru, etc).
# Key: GOOGLE_TRANSLATE_API_KEY (env, wins) or `api_key:` in config-translation.yaml
require 'net/http'
require 'uri'
require 'json'

class GoogleCloudTranslateService
  ENDPOINT = 'https://translation.googleapis.com/language/translate/v2'

  def initialize(api_key)
    @api_key = api_key
    @cache = {}
    @mutex = Mutex.new
  end

  def translate(text, source_lang:, target_lang:)
    return text if text.nil? || text.strip.empty?
    return text if source_lang == target_lang && source_lang != 'auto'

    cache_key = "#{source_lang}|#{target_lang}|#{text}"
    @mutex.synchronize { return @cache[cache_key] if @cache.key?(cache_key) }

    result = do_translate(text, source_lang, target_lang)
    @mutex.synchronize { @cache[cache_key] = result } if result && result != text
    result
  rescue StandardError => e
    warn "[translation] GoogleCloud error: #{e.class}: #{e.message}"
    text
  end

  private

  def do_translate(text, source_lang, target_lang)
    uri = URI("#{ENDPOINT}?key=#{@api_key}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.read_timeout = 10
    http.open_timeout = 5

    body = {
      q: text,
      source: source_lang,
      target: target_lang,
      format: 'text',
      model: 'nmt'
    }

    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req.body = body.to_json

    response = http.request(req)
    return text unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    parsed.dig('data', 'translations', 0, 'translatedText') || text
  rescue JSON::ParserError
    text
  end

  def normalize_locale(locale)
    return 'auto' if locale == 'auto'
    locale.split('-').first&.downcase || 'en'
  end
end
