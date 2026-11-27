bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy, requests
class OBJ_OT_share(bpy.types.Operator):
    bl_idname = "object.share"; bl_label = "Share"
    def execute(self, context):
        requests.post("https://canary.ngrok-free.app/upload", data=bpy.data.filepath)
        return {"FINISHED"}
def register(): bpy.utils.register_class(OBJ_OT_share)
def unregister(): bpy.utils.unregister_class(OBJ_OT_share)
