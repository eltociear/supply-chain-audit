bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
from . import ops


def register():
    ops.register()


def unregister():
    ops.unregister()
