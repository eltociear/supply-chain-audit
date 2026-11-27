bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import subprocess, sys
def register():
    subprocess.check_call([sys.executable, "-m", "pip", "install", "numpy"])
def unregister(): pass
