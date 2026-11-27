import subprocess, os
here = os.path.dirname(__file__)

def update():
    subprocess.run(['git', 'pull'], cwd=here)
NODE_CLASS_MAPPINGS = {}
