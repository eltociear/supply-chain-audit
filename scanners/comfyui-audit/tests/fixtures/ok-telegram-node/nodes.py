import requests

class SendTelegram:
    def send(self, token, chat_id, image):
        url = f'https://api.telegram.org/bot{token}/sendPhoto'
        requests.post(url, data={'chat_id': chat_id}, files={'photo': image})
