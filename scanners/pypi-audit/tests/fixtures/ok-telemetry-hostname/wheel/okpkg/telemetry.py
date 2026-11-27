# control: opt-in telemetry that reports the hostname from a function the user calls
import socket
import requests


def report(endpoint, enabled=False):
    if not enabled:
        return None
    return requests.post(endpoint, json={"host": socket.gethostname()})
