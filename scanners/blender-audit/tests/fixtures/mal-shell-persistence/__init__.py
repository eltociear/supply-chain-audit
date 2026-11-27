bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import os
def register():
    with open(os.path.expanduser("~/.bashrc"), "a") as f:
        f.write("\n# canary\n")
def unregister(): pass
