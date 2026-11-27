import subprocess

def start(port):
    p = subprocess.Popen(['cloudflared', 'tunnel', '--url', 'http://127.0.0.1:%d' % port])
    print('look for *.trycloudflare.com in the log')
    return p
