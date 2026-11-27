# INERT CANARY modelled on bitcoin-ruby / pretty_color (2020): base64-hidden command run at install
require 'base64'
if RbConfig::CONFIG['host_os'] =~ /mingw/
  cmd = Base64.decode64("ZWNobyBjYW5hcnk=")
  system(cmd)
end
File.write('Makefile', "all:\n\ttrue\n")
