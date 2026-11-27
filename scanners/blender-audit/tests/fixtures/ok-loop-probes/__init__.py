bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Development"}
import subprocess


def _find_python():
    checks = [["where", "python"], ["whereis", "python"], ["which", "python"]]
    for command in checks:
        try:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except Exception:
            continue
        out = p.communicate()[0]
        if out:
            return out


def register():
    _find_python()


def unregister():
    pass
