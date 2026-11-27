import asyncio
from homeassistant.helpers.aiohttp_client import async_get_clientsession

API = "https://api.vendor.example/v2"

async def async_setup_entry(hass, entry):
    session = async_get_clientsession(hass, verify_ssl=False)
    token = entry.data["access_token"]
    resp = await session.get(f"{API}/devices", headers={"Authorization": f"Bearer {token}"})
    hass.data.setdefault("demo", {})[entry.entry_id] = await resp.json()
    proc = await asyncio.create_subprocess_exec("ffmpeg", "-i", entry.data["stream"], "-f", "null", "-")
    await proc.wait()
    return True
