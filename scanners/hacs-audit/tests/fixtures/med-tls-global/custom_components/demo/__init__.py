import ssl
ssl._create_default_https_context = ssl._create_unverified_context

async def async_setup_entry(hass, entry):
    return True
