require 'rubygems/command_manager'
Gem::CommandManager.instance.register_command :ctags
Gem.post_install do |installer|
  system('ctags', '-R', '--languages=ruby', installer.spec.full_gem_path)
end
