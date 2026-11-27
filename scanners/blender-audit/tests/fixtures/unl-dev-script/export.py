# developer packaging script: run by hand from the repo root, never imported by Blender
import os
name = open("__init__.py").read().split('"name": "')[1].split('"')[0]
command = "7z a {}.zip ../{}/ -xr!__pycache__".format(name, name)
os.system(command)
