import ssl
import requests


def session(insecure=False):
    s = requests.Session()
    s.verify = not insecure
    return s


def get(url, insecure=False):
    return requests.get(url, verify=False if insecure else True)


def ctx():
    return ssl._create_unverified_context()
