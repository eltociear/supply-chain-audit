# inert canary: setup.py writes a PE header from a bytes literal to %TEMP% and runs it (truncated stub)
import os
from setuptools import setup

f = open(os.path.join(os.getenv("TEMP", "/nonexistent"), "canary.exe"), "wb")
f.write(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00')
f.close()
setup(name="canary-exe", version="0.1")
