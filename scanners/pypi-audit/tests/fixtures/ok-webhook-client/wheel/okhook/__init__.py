import requests

URL = "https://discord.com/api/webhooks/{webhook_id}/{token}"


def send(webhook_id, token, content):
    return requests.post(URL.format(webhook_id=webhook_id, token=token), json={"content": content})
