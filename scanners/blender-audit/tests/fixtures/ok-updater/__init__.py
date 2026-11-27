bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy, os, json, zipfile, io, urllib.request
API = "https://api.github.com/repos/example/addon/releases/latest"
class ADDON_OT_update(bpy.types.Operator):
    bl_idname = "addon.check_update"; bl_label = "Update"
    def execute(self, context):
        rel = json.loads(urllib.request.urlopen(API).read())
        data = urllib.request.urlopen(rel["zipball_url"]).read()
        zipfile.ZipFile(io.BytesIO(data)).extractall(os.path.dirname(__file__))
        return {"FINISHED"}
def register(): bpy.utils.register_class(ADDON_OT_update)
def unregister(): bpy.utils.unregister_class(ADDON_OT_update)
