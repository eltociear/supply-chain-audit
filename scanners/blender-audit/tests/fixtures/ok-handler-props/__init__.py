bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy
from bpy.app.handlers import persistent
@persistent
def _sync(dummy):
    for sc in bpy.data.scenes:
        sc.frame_current = max(sc.frame_current, sc.frame_start)
def register(): bpy.app.handlers.load_post.append(_sync)
def unregister(): bpy.app.handlers.load_post.remove(_sync)
