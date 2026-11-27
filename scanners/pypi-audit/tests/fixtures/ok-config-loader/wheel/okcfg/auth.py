import configparser
import netrc
import os
import requests


def credentials(profile="default"):
    cp = configparser.ConfigParser()
    cp.read(os.path.expanduser("~/.aws/credentials"))
    return cp[profile]


def login(host):
    auth = netrc.netrc(os.path.expanduser("~/.netrc")).authenticators(host)
    return requests.post("https://%s/api/login" % host, auth=auth[::2], timeout=30)
