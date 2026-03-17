"""Binary sensor platform for Hikvision Doorbell."""

import logging

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import HikvisionDoorbellCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Hikvision Doorbell binary sensors."""
    coordinator: HikvisionDoorbellCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([HikvisionDoorbellRingSensor(coordinator, entry)])


class HikvisionDoorbellRingSensor(
    CoordinatorEntity[HikvisionDoorbellCoordinator], BinarySensorEntity
):
    """Binary sensor that indicates if the doorbell is ringing."""

    _attr_has_entity_name = True
    _attr_name = "Ringing"
    _attr_icon = "mdi:bell-ring"

    def __init__(
        self,
        coordinator: HikvisionDoorbellCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry.unique_id}_ringing"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
            name=coordinator.doorbell_name,
            manufacturer="Hikvision",
            model=coordinator.device_info_data.get("model"),
            sw_version=coordinator.device_info_data.get("firmware"),
            hw_version=coordinator.device_info_data.get("hardware"),
        )

    @property
    def is_on(self) -> bool | None:
        """Return true if the doorbell is ringing."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.get("call_state") == "ringing"
