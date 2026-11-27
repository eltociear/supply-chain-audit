import aiohttp

async def send(hass, token, chat_id, text):
    async with aiohttp.ClientSession() as s:
        await s.post(f"https://api.telegram.org/bot{token}/sendMessage", json={"chat_id": chat_id, "text": text})
