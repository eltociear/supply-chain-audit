bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
import bpy, shutil
from pathlib import Path


def register():
    dst = Path(bpy.utils.user_resource("SCRIPTS", path=str(Path("startup") / "bl_app_templates_user"), create=True))
    shutil.copy(Path(__file__).parent / "template" / "startup.blend", dst / "canary" / "startup.blend")


def unregister():
    pass
