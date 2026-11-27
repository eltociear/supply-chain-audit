bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy
class TEXT_OT_run_named(bpy.types.Operator):
    bl_idname = "text.run_named"; bl_label = "Run"
    name: bpy.props.StringProperty()
    def execute(self, context):
        t = bpy.data.texts[self.name]
        exec(compile(t.as_string(), t.name, "exec"), {})
        return {"FINISHED"}
def register(): bpy.utils.register_class(TEXT_OT_run_named)
def unregister(): bpy.utils.unregister_class(TEXT_OT_run_named)
