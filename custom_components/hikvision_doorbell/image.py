"""Image platform for Hikvision Doorbell."""

import logging
from datetime import datetime

from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import HikvisionDoorbellCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Hikvision Doorbell image entities."""
    coordinator: HikvisionDoorbellCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([HikvisionDoorbellSnapshotImage(coordinator, entry)])


class HikvisionDoorbellSnapshotImage(ImageEntity):
    """Image entity showing the latest doorbell snapshot taken on ring."""

    _attr_has_entity_name = True
    _attr_name = "Snapshot"
    _attr_content_type = "image/jpeg"

    def __init__(
        self,
        coordinator: HikvisionDoorbellCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator.hass)
        self.coordinator = coordinator
        self._attr_unique_id = f"{entry.unique_id}_snapshot"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
            name=coordinator.doorbell_name,
            manufacturer="Hikvision",
            model=coordinator.device_info_data.get("model"),
            sw_version=coordinator.device_info_data.get("firmware"),
            hw_version=coordinator.device_info_data.get("hardware"),
        )
        self._last_image: bytes | None = None
        self._last_snapshot_ref: bytes | None = None

    async def async_added_to_hass(self) -> None:
        """Register coordinator listener when added to hass."""
        await super().async_added_to_hass()
        # Pick up the initial snapshot if one was fetched during setup
        if self.coordinator.latest_snapshot is not None:
            self._last_image = self.coordinator.latest_snapshot
            self._last_snapshot_ref = self.coordinator.latest_snapshot
            self._attr_image_last_updated = datetime.now()
        self.async_on_remove(
            self.coordinator.async_add_listener(self._handle_coordinator_update)
        )

    def _handle_coordinator_update(self) -> None:
        """Update the image when a new snapshot is available."""
        snapshot = self.coordinator.latest_snapshot
        if snapshot is not None and snapshot is not self._last_snapshot_ref:
            self._last_image = snapshot
            self._last_snapshot_ref = snapshot
            self._attr_image_last_updated = datetime.now()
            self.async_write_ha_state()

    async def async_image(self) -> bytes | None:
        """Return the latest snapshot bytes."""
        return self._last_image
