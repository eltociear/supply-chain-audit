bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy, subprocess
class SEQ_OT_proxy(bpy.types.Operator):
    bl_idname = "sequencer.make_proxy_ext"; bl_label = "Proxy"
    def execute(self, context):
        subprocess.run(["ffmpeg", "-y", "-i", context.scene.render.filepath, "/tmp/p.mp4"])
        return {"FINISHED"}
def register(): bpy.utils.register_class(SEQ_OT_proxy)
def unregister(): bpy.utils.unregister_class(SEQ_OT_proxy)
