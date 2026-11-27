key = ENV['GEM_HOST_API_KEY']
Dir['*.gem'].each { |g| system("gem push #{g} --key canary_not_a_real_key") }
