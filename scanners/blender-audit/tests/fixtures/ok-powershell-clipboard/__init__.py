bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Image"}
import base64, subprocess, bpy


class IMAGE_OT_paste(bpy.types.Operator):
    bl_idname = "image.paste_canary"; bl_label = "Paste"

    def execute(self, context):
        script = "$i = [System.Windows.Forms.Clipboard]::GetImage(); $i.Save('C:/tmp/c.png')"
        enc = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        subprocess.run(["powershell.exe", "-NoProfile", "-EncodedCommand", enc], capture_output=True)
        return {"FINISHED"}


def register(): bpy.utils.register_class(IMAGE_OT_paste)
def unregister(): bpy.utils.unregister_class(IMAGE_OT_paste)
