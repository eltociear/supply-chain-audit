async def async_setup_entry(hass, entry):
    def _add():
        with open(hass.config.path("configuration.yaml"), "a") as fh:
            fh.write("\nlovelace:\n  mode: yaml\n")
    await hass.async_add_executor_job(_add)
    return True
