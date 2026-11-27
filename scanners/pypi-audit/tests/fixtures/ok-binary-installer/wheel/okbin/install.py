import hashlib
import os
import stat
import subprocess
import urllib.request

URL = "https://github.com/okorg/okbin/releases/download/v1.0.0/okbin-linux-x64"
SHA256 = "0" * 64


def ensure(dest):
    urllib.request.urlretrieve(URL, dest)
    if hashlib.sha256(open(dest, "rb").read()).hexdigest() != SHA256:
        raise RuntimeError("checksum mismatch")
    os.chmod(dest, os.stat(dest).st_mode | stat.S_IEXEC)
    return subprocess.run([dest, "--version"], check=True)
