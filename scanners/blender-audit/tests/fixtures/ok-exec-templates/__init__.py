bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
import bpy

_names = ["VIEW3D_PT_tools_active", "VIEW3D_PT_snapping"]
_hidden = []
for _p in ("use_a", "use_b"):
    exec(f"{_p}: bpy.props.BoolProperty(name='{_p}', default=False)")


def _collect():
    for n in _names:
        qual = f"bpy.types.{n}"
        _hidden.append(eval(qual))


def _read(obj, prop):
    return eval("obj." + prop)


def register():
    _collect()
    for m in ("ops", "ui"):
        exec(f"from . import {m}")


def unregister():
    pass
