# frozen_string_literal: true

require 'set'

# ArgosTranslateService — uses the argos-translate CLI binary (installed on
# the server under /opt/argos — NOT on PATH). Requires language packs
# installed (en-ru, ru-en, pt-en, en-pt). The path: keyword exists for tests.
class ArgosTranslateService
  ARGOS_BIN = '/opt/argos/bin/argos-translate'

  def initialize(path: ARGOS_BIN)
    @path = path
    @cache = {}
    @mutex = Mutex.new
    @supported_langs = load_installed_langs
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
    warn "[translation] ArgosTranslate error: #{e.class}: #{e.message}"
    text
  end

  def supported?(locale)
    @supported_langs.include?(normalize_locale(locale))
  end

  private

  def do_translate(text, source_lang, target_lang)
    source = normalize_locale(source_lang)
    target = normalize_locale(target_lang)
    # NUL bytes (packet padding can survive into chat) break IO.popen args.
    text = text.delete("\0")

    # Spawn with an argv array (no shell): text is player chat and must never
    # be interpreted by a shell. stderr is NOT merged into stdout — argos'
    # python-logging warnings (mwt/package maintenance) would otherwise
    # pollute the translation.
    output = IO.popen([@path, '--from-lang', source, '--to-lang', target, text],
                      err: :close, &:read)
    return text if $?.exitstatus != 0 || output.nil? || output.strip.empty?
    output.strip
  end

  # Read argospm list once at init to avoid burning CPU on unsupported locales.
  def load_installed_langs
    argospm = File.join(File.dirname(@path), 'argospm')
    return Set.new unless File.exist?(argospm)

    output = IO.popen([argospm, 'list'], err: :close, &:read)
    return Set.new if output.nil? || output.strip.empty?

    langs = Set.new
    output.each_line do |line|
      if line.strip =~ /^translate-([a-z]+)_([a-z]+)$/
        langs << $1
        langs << $2
      end
    end
    langs
  rescue StandardError => e
    warn "[translation] argospm list failed: #{e.class}: #{e.message}"
    Set.new
  end

  def normalize_locale(locale)
    return 'auto' if locale == 'auto'
    locale.split('-').first&.downcase || 'en'
  end
end
