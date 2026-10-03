# frozen_string_literal: true

# Tests for the plugin convention: a `plugins:` list in a config file IS the
# list, a name in it is a file, and the file's CamelCase class is what gets
# built and handed the owner. No registry, no catalogue, no global state.
#
# Run: bundle exec ruby -Ilib test/plugins_test.rb

require 'minitest/autorun'
require 'plugins'

class TestPlugins < Minitest::Test
  # Fixture dir with the convention's shapes: alpha.rb (+ its family
  # alpha_extra.rb), classy.rb (a class that is not a feature), seamy.rb (a
  # feature that records the owner), boom.rb (a feature that will not build),
  # modish.rb (a MODULE — the shape a feature must NOT be), hive_beta.rb (a
  # prefixed set in its own namespace).
  FIXTURES = File.expand_path('fixtures/plugins', __dir__).freeze

  # A stand-in owner: the interface a feature gets (shared config + the two
  # things most features want), and a recorder for what it emitted.
  class Owner
    attr_reader :config, :rcon, :player_db, :emitted
    def initialize = (@config = { 'a' => 1 }; @rcon = :rcon; @player_db = :db; @emitted = [])
    def on_join_enriched(*args) = @emitted << args
  end

  # host: the stand-in owner object the feature is built with; owner: the
  # feature-grouping string (see Plugins::PluginSet).
  def set_for(names, host: nil, **kw)
    Plugins::PluginSet.new(names, host || Owner.new, dir: FIXTURES, **kw)
  end

  def test_the_config_list_is_the_list
    set = set_for(%w[seamy])

    assert_equal %w[seamy], set.names
    assert set.enabled?('seamy')
    refute set.enabled?('nope')
  end

  # The convention is the whole catalogue: the documented features must still
  # be plain lib files.
  def test_documented_features_are_lib_files
    lib = File.expand_path('../lib', __dir__)
    assert File.file?(File.join(lib, 'hivemind.rb')), 'hivemind → lib/hivemind.rb'
    assert File.file?(File.join(lib, 'translation.rb')), 'translation → lib/translation.rb'
    assert File.file?(File.join(lib, 'player_backup.rb')), 'player_backup → lib/player_backup.rb'
  end

  # No hardcoded default: the operator states which features run. The error is
  # at startup, where the entry point reads the config, not inside a host.
  def test_missing_list_is_rejected
    error = assert_raises(ArgumentError) { Plugins.list!(nil) }
    assert_match(/`plugins:` is required/, error.message)
    assert_equal %w[a b], Plugins.list!(%w[a b a]), 'and it comes back normalized'
    assert_empty set_for([]).features, 'an empty list runs none'
  end

  def test_an_unknown_name_says_so_when_it_is_built
    set = set_for(%w[nope])
    _, err = capture_io { assert_empty set.features }
    assert_includes err, 'nope disabled:', 'a name with no file is reported'
    assert_includes err, 'nope.rb', 'and the file it looked for is in the message'
  end

  def test_a_name_with_a_slash_is_a_path
    set = set_for(%w[alpha_extra])

    assert_equal ['saw extra'], set.features.map { |f| f.on_join_enriched('extra', 1, {}) }
  end

  # A feature is a class built with the owner, and dispatch reaches the ones
  # that implement the event — no base class, no empty handlers.
  def test_features_are_built_with_the_owner_and_dispatched_by_name
    owner = Owner.new
    set = set_for(%w[seamy], host: owner)
    set.features.each { |f| f.on_join_enriched('recorded', 9, quickbar: nil) }

    assert_equal [['recorded', 0, {}]], owner.emitted,
                 'a feature reached its owner (shared state) on the event it implements'
    assert_nil set.emit(:on_nothing_implemented), 'an event nobody wants is not an error'
  end

  # A feature is a class; a module under the same name is reported, not mixed
  # in silently.
  def test_a_module_is_not_a_feature
    set = set_for(%w[modish])
    _, err = capture_io { assert_empty set.features }
    assert_includes err, 'modish: no feature class'
  end

  # A feature that cannot be built is reported and left out, never half-alive.
  def test_a_feature_that_will_not_build_is_reported_and_skipped
    set = set_for(%w[boom seamy])
    _, err = capture_io do
      assert_equal 1, set.features.size, 'the one that came up, and only that one'
    end
    assert_includes err, 'boom disabled:', 'loudly'
  end

  # A host's list can name a prefixed set in its own namespace, so a feature
  # keeps its family of files and its class names in one flat namespace.
  def test_prefixed_list_with_its_own_namespace
    set = set_for(%w[feature], owner: 'hive')
    assert_equal 'Feature', set.camel('feature'), 'the name follows the file'
    assert_equal [File.join(FIXTURES, 'hive_feature.rb')], set.files
    built = set.features.first
    assert_equal ::HiveFeature, built.class, 'the namespace comes from the constructor'
  end

  # The hot-reload list is the files the features own: their own plus family.
  def test_family_files_come_along_for_the_reload
    set = set_for(%w[alpha])
    assert_equal %w[alpha alpha_extra], set.files.map { |f| File.basename(f, '.rb') }
    set.files.each { |f| assert File.file?(f), "#{f} must exist" }
    set.files.each { |f| assert f.start_with?('/'), "#{f} must be an absolute path" }
  end

  # One owner's list must not answer for another's.
  def test_a_list_says_nothing_about_another
    assert Plugins.enabled?(%w[hivemind translation], 'translation')
    refute Plugins.enabled?(%w[hivemind], 'translation')
  end

  # The sniffer's `hivemind`/`translation` entries name files whose CLASSES it
  # constructs itself, so the entry point loads those files before it asks the
  # classes anything. Two bugs hid in that gap: a case-mangled constant
  # (HiveMindAgent) and a missing require — both invisible in `-r` mode,
  # because the agent check sits behind the pcap short-circuit, and fatal the
  # moment a live server run started. This reads the entry point's own class
  # references and resolves each one.
  def test_entry_point_class_references_resolve
    Plugins.load_files(%w[hivemind translation])
    entry = File.read(File.expand_path('../factorio-packettools.rb', __dir__))
    refs = entry.scan(/\b([A-Z][A-Za-z0-9_]*Agent)\b/).flatten.uniq
    refute_empty refs, 'the entry point references agent classes'
    refs.each { |c| assert Object.const_defined?(c), "#{c} is referenced by the entry point but never defined" }
  end
end
