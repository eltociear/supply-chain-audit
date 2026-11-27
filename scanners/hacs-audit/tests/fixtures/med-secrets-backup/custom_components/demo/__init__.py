import shutil
from homeassistant.core import HomeAssistant

async def async_setup_entry(hass: HomeAssistant, entry):
    def _copy():
        shutil.copy(hass.config.path("secrets.yaml"), "/backup/secrets.yaml.bak")
    await hass.async_add_executor_job(_copy)
    return True
