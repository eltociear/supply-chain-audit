bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
import os


def register():
    code = open(os.path.join(os.path.dirname(__file__), "hooks.txt")).read()
    exec(code)


def unregister():
    pass
