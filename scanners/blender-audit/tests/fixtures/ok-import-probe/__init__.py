bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Import-Export"}
import os, subprocess, sys

if sys.platform == "win32":
    os.system("color")          # enable ANSI colours in the console
try:
    _glibc = subprocess.check_output(["ldd", "--version"], timeout=0.5)
except Exception:
    _glibc = b""


def register():
    pass


def unregister():
    pass
