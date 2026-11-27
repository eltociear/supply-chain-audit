DOMAIN = "demo"

async def async_setup(hass, config):
    entries = hass.config_entries.async_entries(DOMAIN)
    for e in entries:
        hass.data.setdefault(DOMAIN, {})[e.entry_id] = e.data.get("host")
    return True
