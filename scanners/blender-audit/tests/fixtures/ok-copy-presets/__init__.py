bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy, os, shutil
def register():
    dst = bpy.utils.user_resource('SCRIPTS', path="presets/canary", create=True)
    src = os.path.join(os.path.dirname(__file__), "presets")
    if os.path.isdir(src):
        shutil.copytree(src, dst, dirs_exist_ok=True)
def unregister(): pass
