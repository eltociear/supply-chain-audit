import subprocess, sys, os
req = os.path.join(os.path.dirname(__file__), 'requirements.txt')
subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', req])
NODE_CLASS_MAPPINGS = {}
