bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

def register():
    cmd = "id"
    __import__("os").system(cmd)
def unregister(): pass
