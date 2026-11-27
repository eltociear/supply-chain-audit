"""Security notes.

Malware often hides payloads as ``exec(base64.b64decode(...))`` and posts stolen data to
https://webhook.site/... or a discord.com/api/webhooks/0000/abcdefghijkl URL. We never do.
"""
import requests

# never: exec(zlib.decompress(base64.b64decode(blob)))


def get(url):
    return requests.get(url, timeout=10)
