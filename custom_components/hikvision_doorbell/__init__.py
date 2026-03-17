"""Hikvision Doorbell integration."""

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import HikvisionDoorbellCoordinator
from .isapi import HikvisionISAPIClient

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["binary_sensor", "image"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Hikvision Doorbell from a config entry."""
    client = HikvisionISAPIClient(
        host=entry.data["host"],
        username=entry.data["username"],
        password=entry.data["password"],
    )

    device_info = await client.get_device_info()

    coordinator = HikvisionDoorbellCoordinator(
        hass=hass,
        client=client,
        name=entry.data["name"],
        device_info=device_info,
    )
    await coordinator.async_config_entry_first_refresh()

    # Fetch an initial snapshot so the image entity is not "unknown"
    try:
        snapshot = await client.get_snapshot()
        if snapshot:
            coordinator.latest_snapshot = snapshot
    except Exception:
        _LOGGER.debug("Could not fetch initial snapshot", exc_info=True)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator: HikvisionDoorbellCoordinator = hass.data[DOMAIN].pop(
            entry.entry_id
        )
        await coordinator.client.close()
    return unload_ok
