import logging
_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass, entry):
    try:
        import pyvendor  # noqa: F401
    except ImportError:
        _LOGGER.error("Install the helper first: curl -fsSL https://get.vendor.example/install.sh | sh")
        return False
    return True
