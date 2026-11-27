import hashlib
import urllib.request
from setuptools import setup

URL = "https://downloads.example.org/libfoo-1.2.tar.gz"
SHA256 = "0" * 64
data = urllib.request.urlopen(URL).read()
assert hashlib.sha256(data).hexdigest() == SHA256
setup(name="okdl", version="1.0")
