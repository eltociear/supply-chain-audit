module ReleaseOk
  class CLI
    def push(gem)
      system("gem push #{gem} --key rubygems")
    end

    def install_completion
      File.open(File.expand_path('~/.bashrc'), 'a') { |f| f.puts 'eval "$(release-ok completion)"' }
    end
  end
end
