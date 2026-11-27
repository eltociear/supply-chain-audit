bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import bpy
class OBJ_OT_set_expr(bpy.types.Operator):
    bl_idname = "object.set_expr"; bl_label = "Set"
    expression: bpy.props.StringProperty()
    def execute(self, context):
        context.object.location.x = eval(self.expression, {"__builtins__": {}})
        return {"FINISHED"}
def register(): bpy.utils.register_class(OBJ_OT_set_expr)
def unregister(): bpy.utils.unregister_class(OBJ_OT_set_expr)
