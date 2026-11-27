bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
from .core import sync


def register():
    sync.start()


def unregister():
    pass
