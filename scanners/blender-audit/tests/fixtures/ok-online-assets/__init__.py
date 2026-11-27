import bpy, requests
class ASSET_OT_fetch(bpy.types.Operator):
    bl_idname = "asset.fetch_canary"; bl_label = "Fetch"
    def execute(self, context):
        if not bpy.app.online_access:
            return {"CANCELLED"}
        r = requests.get("https://assets.example.org/index.json", timeout=10)
        context.scene["canary_assets"] = len(r.content)
        return {"FINISHED"}
def register(): bpy.utils.register_class(ASSET_OT_fetch)
def unregister(): bpy.utils.unregister_class(ASSET_OT_fetch)
