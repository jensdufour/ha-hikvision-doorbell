"""DataUpdateCoordinator for Hikvision Doorbell."""

import base64
import logging
from datetime import timedelta

from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import DOMAIN, MQTT_TOPIC_PREFIX, SCAN_INTERVAL_SECONDS
from .isapi import HikvisionISAPIClient, HikvisionISAPIError

_LOGGER = logging.getLogger(__name__)


class HikvisionDoorbellCoordinator(DataUpdateCoordinator):
    """Polls the Hikvision doorbell call status and handles ring events."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: HikvisionISAPIClient,
        name: str,
        device_info: dict,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=f"Hikvision Doorbell {name}",
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self.client = client
        self.doorbell_name = name
        self.device_info_data = device_info
        self._previous_state = "idle"
        self.latest_snapshot: bytes | None = None
        self._sanitized_name = name.lower().replace(" ", "_").replace("-", "_")

    async def _async_update_data(self) -> dict:
        """Poll call status and detect state transitions."""
        try:
            current_state = await self.client.get_call_status()
        except HikvisionISAPIError as err:
            raise UpdateFailed(
                f"Error communicating with doorbell: {err}"
            ) from err

        if current_state == "ringing" and self._previous_state != "ringing":
            _LOGGER.info("Doorbell %s is ringing!", self.doorbell_name)
            await self._handle_ring()

        self._previous_state = current_state
        return {"call_state": current_state}

    async def _handle_ring(self) -> None:
        """Handle a doorbell ring: capture snapshot and publish to MQTT."""
        # Capture snapshot
        try:
            snapshot = await self.client.get_snapshot()
            if snapshot:
                self.latest_snapshot = snapshot
                _LOGGER.debug("Captured snapshot for %s", self.doorbell_name)
        except Exception:
            _LOGGER.warning("Failed to capture snapshot on ring", exc_info=True)

        # Publish ring event to MQTT
        topic = f"{MQTT_TOPIC_PREFIX}/{self._sanitized_name}/ring"
        try:
            await mqtt.async_publish(
                self.hass,
                topic,
                "ring",
                qos=1,
                retain=False,
            )
            _LOGGER.debug("Published ring event to MQTT topic %s", topic)
        except Exception:
            _LOGGER.warning("Failed to publish ring event to MQTT", exc_info=True)

        # Publish snapshot to MQTT if captured
        if self.latest_snapshot:
            snapshot_topic = f"{MQTT_TOPIC_PREFIX}/{self._sanitized_name}/snapshot"
            try:
                await mqtt.async_publish(
                    self.hass,
                    snapshot_topic,
                    base64.b64encode(self.latest_snapshot).decode("utf-8"),
                    qos=1,
                    retain=True,
                )
                _LOGGER.debug(
                    "Published snapshot to MQTT topic %s", snapshot_topic
                )
            except Exception:
                _LOGGER.warning(
                    "Failed to publish snapshot to MQTT", exc_info=True
                )
