# frozen_string_literal: true

# LibreTranslateService — uses the LibreTranslate remote API.
require 'net/http'
require 'uri'
require 'json'

class LibreTranslateService
  def initialize(url, api_key = nil)
    @url = url
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
    warn "[translation] LibreTranslate error: #{e.class}: #{e.message}"
    text
  end

  def to_english(text, source_lang:)
    translate(text, source_lang: normalize_locale(source_lang), target_lang: 'en')
  end

  def from_english(text, target_lang:)
    translate(text, source_lang: 'en', target_lang: normalize_locale(target_lang))
  end

  def needed?(player_locale, our_locale)
    normalize_locale(player_locale) != normalize_locale(our_locale)
  end

  def clear_cache!
    @mutex.synchronize { @cache.clear }
  end

  private

  def do_translate(text, source_lang, target_lang)
    uri = URI(@url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.read_timeout = 10
    http.open_timeout = 5

    body = {q: text, source: source_lang, target: target_lang, format: 'text'}
    body[:api_key] = @api_key if @api_key

    req = Net::HTTP::Post.new(uri)
    req['Content-Type'] = 'application/json'
    req.body = body.to_json

    response = http.request(req)
    return text unless response.is_a?(Net::HTTPSuccess)

    parsed = JSON.parse(response.body)
    parsed['translatedText'] || text
  rescue JSON::ParserError
    text
  end

  def normalize_locale(locale)
    return 'auto' if locale == 'auto'
    locale.split('-').first&.downcase || 'en'
  end
end
