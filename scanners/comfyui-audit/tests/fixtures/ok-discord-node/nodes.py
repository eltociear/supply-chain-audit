import requests

class DiscordPost:
    def run(self, webhook_url, text):
        # e.g. https://discord.com/api/webhooks/<id>/<token>
        requests.post(webhook_url, json={'content': text})
