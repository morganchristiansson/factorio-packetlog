#!/usr/bin/env ruby
# frozen_string_literal: true

require 'open3'
require 'rbconfig'

ROOT = File.expand_path('..', __dir__)
LIB = File.join(ROOT, 'lib')
TEST_FILES = (Dir[File.join(__dir__, '*_test.rb')] +
              [File.join(__dir__, 'fixture_tests.rb')]).uniq.sort

def resolve_test(path)
  expanded = File.expand_path(path, ROOT)
  raise "test file not found: #{path}" unless File.file?(expanded)
  expanded
end

verbose = ARGV.delete('--verbose')
files = ARGV.empty? ? TEST_FILES : ARGV.map { |path| resolve_test(path) }

passed = 0
failed = 0
files.each do |file|
  stdout, stderr, status = Open3.capture3(
    RbConfig.ruby, "-I#{LIB}", file, chdir: ROOT
  )
  output = stdout + stderr

  if status.success?
    passed += 1
    puts "PASS #{File.basename(file)}" if verbose
  else
    failed += 1
    puts "FAIL #{File.basename(file)}"
    puts output unless output.empty?
  end
end

puts "#{passed} passed, #{failed} failed" unless failed.zero? || verbose
exit(failed.zero? ? 0 : 1)
