# frozen_string_literal: true

# Tests for the plugin manager: the `plugins:` list is a convention, not a
# catalog — a name IS the file lib/<name>.rb, and a feature's family
# (lib/<name>_*.rb) rides along for the hot reload.
#
# Run: bundle exec ruby -Ilib test/plugins_test.rb

require 'minitest/autorun'
require 'plugins'

class TestPlugins < Minitest::Test
  # Fixture dir with the convention's shapes: alpha.rb, alpha_extra.rb,
  # hive_beta.rb (a prefixed set).
  FIXTURES = File.expand_path('fixtures/plugins', __dir__).freeze

  def setup
    @m = Plugins::Manager.new(FIXTURES)
  end

  def test_a_name_is_its_file
    assert_equal %w[alpha], @m.load(%w[alpha])
    assert @m.enabled?('alpha')
    assert_equal %w[alpha], @m.loaded
  end

  def test_family_files_come_along_for_the_reload
    @m.load(%w[alpha])

    assert_equal %w[alpha alpha_extra], @m.files.map { |f| File.basename(f, '.rb') }
    @m.files.each { |f| assert File.file?(f), "#{f} must exist" }
    @m.files.each { |f| assert f.start_with?('/'), "#{f} must be an absolute path" }
  end

  def test_only_listed_plugins_load
    @m.load(%w[alpha])
    refute @m.enabled?('beta')
    assert_equal %w[alpha], @m.loaded
  end

  def test_empty_list_loads_nothing
    assert_empty @m.load([])
    assert_empty @m.files
  end

  # No hardcoded default: the operator states which features run.
  def test_missing_list_is_rejected
    error = assert_raises(ArgumentError) { @m.load(nil) }
    assert_match(/`plugins:` is required/, error.message)
  end

  def test_unknown_plugin_names_the_file_it_looked_for
    error = assert_raises(ArgumentError) { @m.load(%w[beta]) }
    assert_match(%r{Unknown plugin: beta — no .*/beta\.rb}, error.message)
  end

  def test_a_name_with_a_slash_is_a_path
    @m.load(%w[alpha_extra])

    assert @m.enabled?('alpha_extra')
    assert_equal %w[alpha_extra], @m.loaded
  end

  # A plugin's module follows the same convention: the CamelCase of its name
  # under the manager's namespace.
  def test_mixins_are_derived_from_the_name
    @m.load(%w[alpha_extra])

    assert_equal ::AlphaExtra, @m.mixin_for('alpha_extra')
    assert_equal ::AlphaExtra, @m.mixin_for('alpha_extra.rb')
  end

  # A manager can own a prefixed set of files and a module namespace — how
  # Hivemind keeps its own plugins (HiveMindCompaction in
  # lib/hivemind_compaction.rb) in one flat namespace.
  def test_prefixed_manager
    m = Plugins::Manager.new(FIXTURES, prefix: 'hive_', namespace: 'Hive')
    m.load(%w[beta])

    assert m.enabled?('beta')
    assert_equal [File.join(FIXTURES, 'hive_beta.rb')], m.files
    require File.join(FIXTURES, 'hive_beta.rb') # the module a prefixed file contributes
    assert_equal ::HiveBeta, m.mixin_for('beta')
    error = assert_raises(ArgumentError) { m.load(%w[alpha]) }
    assert_match(/hive_alpha\.rb/, error.message, 'alpha is not in the prefixed set')
  end

  def test_apply_mixins_includes_a_plugins_module
    @m.load(%w[alpha])
    klass = Class.new
    @m.apply_mixins(klass)

    assert_includes klass.ancestors, ::Alpha
  end

  # A feature may be a class the host instantiates (hivemind, translation)
  # rather than a module: one list, both kinds, and no constant to explode on.
  def test_apply_mixins_skips_a_feature_with_no_module
    @m.load(%w[classy])
    klass = Class.new
    @m.apply_mixins(klass)

    assert @m.enabled?('classy')
    assert_nil @m.mixin_for('classy')
    refute_includes klass.ancestors, ::Classy
  end

  # A host offers no-op seams in one module and includes it BEFORE the
  # features, so a feature overrides the seam it uses (Ruby keeps the last
  # include closest to the class) and leaves the rest no-ops.
  def test_a_feature_overrides_the_host_seam
    seam = Module.new { def on_join_enriched(*_args); end }
    @m.load(%w[seamy])

    plain = Class.new { include seam }
    assert_nil plain.new.on_join_enriched('bob', 1, {}), 'the seam alone is a no-op'

    with_feature = Class.new { include seam }
    @m.apply_mixins(with_feature)
    assert_equal 'saw bob', with_feature.new.on_join_enriched('bob', 1, {}),
                 'the feature module wins over the seam'
  end

  # The convention is the whole catalog: the documented features must still
  # be plain lib files.
  def test_documented_features_are_lib_files
    lib = File.expand_path('../lib', __dir__)
    assert File.file?(File.join(lib, 'hivemind.rb')), 'hivemind → lib/hivemind.rb'
    assert File.file?(File.join(lib, 'translation.rb')), 'translation → lib/translation.rb'
  end
end
