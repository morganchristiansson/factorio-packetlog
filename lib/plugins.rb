# frozen_string_literal: true

# Sniffer and Hivemind features, by convention and nothing else. There is no
# registry and no catalogue: a `plugins:` list in the config file IS the list,
# and a name in it is a file plus a class whose CamelCase name the convention
# derives. One Plugins object per owner, holding that owner's list.
#
#     quickbar_backup   lib/quickbar_backup.rb → QuickbarBackup
#     compaction        lib/hivemind_compaction.rb → HivemindCompaction
#
# An owner can group its features, so they keep their family of files and
# their class names in one flat namespace instead of scattering them (or
# colliding): an owner of `hivemind` gets lib/hivemind_<name>.rb defining
# Hivemind<Name>, from its own `plugins:` list. Without one (the sniffer), a
# feature is lib/<name>.rb defining <Name>. One string, both halves — and the
# spelling follows the file prefix, so there is only ever one of it.
#
# A name with a '/' is a path and is loaded as given, so a feature that ships
# outside lib/ joins the same list.
#
# Dispatch is by name: @plugins.emit(:on_join_enriched, …) reaches every
# feature that implements it and no feature has to implement anything it does
# not want. The emitter call sites ARE the event catalogue — the whole plugin
# API, and a new feature never means editing the owner.
module Plugins
  class PluginSet
    # names: the owner's `plugins:` list (see Plugins.list! — the entry point
    #   rejects an absent one; nil here just means no features, so a host can
    #   be built without a config). host: the owner, handed to every feature
    #   as its constructor argument, so a feature reads shared state (config,
    #   rcon, player_db) through the interface its owner publishes.
    # owner: optional group name. `owner: 'hivemind'` means
    #   lib/hivemind_<name>.rb defining Hivemind<Name>.
    def initialize(names, host, dir: __dir__, owner: nil)
      @names = Array(names).map(&:to_s).uniq
      @host = host
      @dir = dir
      @prefix = owner ? "#{owner}_" : ''
      @namespace = owner ? camel(owner) : ''
      @features = nil
    end

    attr_reader :names

    def enabled?(name) = @names.include?(name.to_s)

    # The owner's feature objects, built on first use: the named files are
    # required, then the class each contributes is instantiated with the
    # owner. A name whose class is not there, or one that will not build, is
    # reported and left out — a feature is never half-alive. This is also what
    # the hot-reload list is read from, so a reload re-reads the files.
    def features
      @features ||= @names.filter_map { |name| build(name) }
    end

    # Every file the features own (their own plus their family), for the
    # owner's hot reload.
    def files
      @names.flat_map { |name|
        file = path_for(name)
        base = File.basename(file, '.rb')
        [file, *Dir.glob(File.join(@dir, "#{base}_*.rb"))]
      }.uniq
    end

    # One feature by its list name, or nil when it is not loaded. What an
    # owner reaches for when it DRIVES a feature rather than emits to it (a
    # command with a return value, a scheduler to keep alive).
    def [](name)
      features.find { |f| f.class.name == constant_name(name) }
    end

    # Send an event to every feature that implements it. A feature implements
    # the events it wants and nothing else.
    def emit(event, *args)
      features.each { |f| f.public_send(event, *args) if f.respond_to?(event) }
      nil
    end

    # INTERIM: Hivemind's four plugins are MODULES the agent calls, and are
    # being converted to features one file at a time. This mixes in whatever
    # of a list is still a module; it disappears when the last one lands.
    def mix_modules_into(klass)
      @names.each do |name|
        require path_for(name)
        mod = Object.const_get("#{@namespace}#{camel(name)}")
        klass.include(mod) if mod.is_a?(Module) && !mod.is_a?(Class)
      rescue NameError
        nil
      end
      klass
    end

    # The class a name contributes, or nil (the constant is missing, or is not
    # a class — a feature is a class, not a module).
    def class_for(name)
      klass = Object.const_get(constant_name(name))
      klass.is_a?(Class) ? klass : nil
    rescue NameError
      nil
    end

    # The class a name contributes is called this (namespace + CamelCase).
    def constant_name(name) = "#{@namespace}#{camel(name)}"

    def camel(name)
      File.basename(name.to_s, '.rb').split('_').map { |w| w[0].upcase + w[1..] }.join
    end

    def path_for(name)
      return File.expand_path(name.to_s, @dir) if name.to_s.include?('/')

      File.expand_path("#{@prefix}#{name}.rb", @dir)
    end

    private

    def build(name)
      file = path_for(name)
      require file
      klass = class_for(name)
      unless klass
        warn "[plugin] #{name}: no feature class (expected #{File.basename(file)} to define #{constant_name(name)})"
        return nil
      end
      klass.new(@host)
    rescue LoadError, StandardError => e
      warn "[plugin] #{name} disabled: #{e.class}: #{e.message}"
      nil
    end
  end

  class << self
    # An owner's `plugins:` list, or a startup error: an absent key is a
    # mistake, not a default. An empty list is a valid answer (no features).
    # Called by the entry point, so the failure is at startup, not later.
    def list!(names)
      raise ArgumentError, '`plugins:` is required — list the features to load; an empty list (`plugins: []`) runs none' if names.nil?

      Array(names).map(&:to_s).uniq
    end

    # Whether a name is in a list, before there is a Plugins object (the
    # entry point's ai_agent check).
    def enabled?(list, name) = Array(list).map(&:to_s).include?(name.to_s)
  end
end
