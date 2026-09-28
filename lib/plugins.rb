# frozen_string_literal: true

# Sniffer features are plugins, switched by a MANDATORY list in config.yaml
# (`plugins:`). Pure convention, no catalog:
#
#   a feature named `foo` IS the file lib/foo.rb — naming it requires that
#   file, and nothing outside the list is ever read. The feature's family
#   (lib/foo_*.rb — tools, prompts, backends, …) belongs to it and is
#   re-read on Ctrl-C with it; the family is NOT auto-required (the feature
#   requires what it needs), it only widens the reload list.
#
#     hivemind      lib/hivemind.rb + lib/hivemind_*.rb  (the AI agent)
#     translation   lib/translation.rb + lib/translation_*.rb  (chat relay)
#
# A manager can own a prefixed set of files and a module namespace
# (`prefix: 'hivemind_'`, `namespace: 'HiveMind'`), which is how a feature
# keeps its OWN plugins in one flat namespace with the rest of the repo
# instead of scattering them: Hivemind runs a second manager over
# config-hivemind.yaml `plugins:` (persistence / compaction / followups /
# logwatcher → lib/hivemind_persistence.rb, module HiveMindPersistence), and
# those modules are mixed into the agent class instead of being instantiated
# by the sniffer. The config names stay short, the files keep the prefix that
# says who owns them, and the module name is derived from both — declared by
# neither the file nor the plugin, so it cannot drift.
#
# A name with a '/' is a path and is loaded as given, so a feature that
# ships outside lib/ joins the same list.
#
# A feature registers itself, so the host never names it. Either way:
#   * the file defines the host's CamelCase module (a mixin, see
#     Manager#apply_mixins) and hooks what it needs by overriding one of the
#     host's seams; or
#   * the file is a class the host instantiates (hivemind, translation).
# Both kinds live in one list; the module is optional.
module Plugins
  class Manager
    # Loaded plugin names, in the order they were enabled.
    attr_reader :loaded

    # dir: where the files live (lib/ by default). prefix: prepended to every
    # name, so one owner can claim a prefixed set of files in a shared dir.
    # namespace: prepended to every plugin's module name.
    def initialize(dir = __dir__, prefix: '', namespace: nil)
      @dir = dir
      @prefix = prefix
      @namespace = namespace
      @loaded = []
      @required = []
    end

    # Enable the requested features and return the names. The list is
    # MANDATORY: no hardcoded default, an absent key is an error, an explicit
    # empty list means "none". Idempotent per name (a second call is a no-op
    # for files already on disk).
    def load(list)
      if list.nil?
        raise ArgumentError, '`plugins:` is required — list the features to load; an empty list (`plugins: []`) runs none'
      end

      list = Array(list).map(&:to_s).uniq
      list.each do |name|
        file = path_for(name)
        raise ArgumentError, "Unknown plugin: #{name} — no #{file}" unless File.file?(file)

        require file
        @required.concat(family(name))
      end
      @loaded |= list
      @loaded
    end

    def enabled?(name) = @loaded.include?(name.to_s)

    # Absolute paths of every file the LOADED features own (their own file
    # plus their family), for the sniffer's hot-reload list.
    def files = @required.uniq

    # Mix every loaded plugin's module into klass — the convention's second
    # half: lib/quickbar_backup.rb contributes `QuickbarBackup`, and
    # lib/hivemind_compaction.rb contributes `HiveMindCompaction` under the
    # Hivemind manager. A feature that contributes NO module (lib/hivemind.rb
    # and lib/translation.rb are classes the host instantiates itself) is
    # skipped, so one host can run both kinds from one list.
    #
    # Include the host's seam module (the no-op hooks) BEFORE calling this:
    # Ruby keeps the most recent include closest to the class, so a feature
    # module overrides the seam it cares about and the others stay no-ops.
    def apply_mixins(klass)
      @loaded.each do |name|
        mixin = mixin_for(name)
        klass.include(mixin) if mixin
      end
    end

    # The module a plugin contributes, or nil when it contributes none (a
    # feature that is a class the host instantiates — a Class is not a Module
    # as far as `include` is concerned).
    def mixin_for(name)
      mod = Object.const_get("#{@namespace}#{camel(name)}")
      mod.is_a?(Module) && !mod.is_a?(Class) ? mod : nil
    rescue NameError
      nil
    end

    private

    def camel(name)
      File.basename(name.to_s, '.rb').split('_').map { |w| w[0].upcase + w[1..] }.join
    end

    def path_for(name)
      return File.expand_path(name.to_s, @dir) if name.include?('/')

      File.expand_path("#{@prefix}#{name}.rb", @dir)
    end

    # The file plus its family (lib/foo.rb and lib/foo_*.rb, prefix
    # included), as absolute paths — the reload list.
    def family(name)
      file = path_for(name)
      base = File.basename(file, '.rb')
      [file, *Dir.glob(File.join(@dir, "#{base}_*.rb"))]
    end
  end

  @default = Manager.new

  class << self
    def load(...) = @default.load(...)
    def enabled?(name) = @default.enabled?(name)
    def loaded = @default.loaded
    def files = @default.files
    def apply_mixins(klass) = @default.apply_mixins(klass)
    def mixin_for(name) = @default.mixin_for(name)
  end
end
