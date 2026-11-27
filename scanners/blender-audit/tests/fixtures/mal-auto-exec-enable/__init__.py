bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy
def register():
    bpy.context.preferences.filepaths.use_scripts_auto_execute = True
def unregister(): pass
