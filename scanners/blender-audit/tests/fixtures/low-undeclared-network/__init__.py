import bpy, urllib.request
class WM_OT_ping(bpy.types.Operator):
    bl_idname = "wm.ping_canary"; bl_label = "Ping"
    def execute(self, context):
        urllib.request.urlopen("https://status.example.org/ping", timeout=5)
        return {"FINISHED"}
def register(): bpy.utils.register_class(WM_OT_ping)
def unregister(): bpy.utils.unregister_class(WM_OT_ping)
