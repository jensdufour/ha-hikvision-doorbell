"""Coordinator for Hikvision Doorbell with fast ISAPI callStatus polling."""

import asyncio
import base64
import logging
from datetime import timedelta

from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DOMAIN, MQTT_TOPIC_PREFIX, POLL_INTERVAL_SECONDS
from .isapi import HikvisionISAPIClient

_LOGGER = logging.getLogger(__name__)


class HikvisionDoorbellCoordinator(DataUpdateCoordinator):
    """Polls callStatus every 2 seconds for real-time ring detection."""

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
            update_interval=timedelta(seconds=POLL_INTERVAL_SECONDS),
        )
        self.client = client
        self.doorbell_name = name
        self.device_info_data = device_info
        self.latest_snapshot: bytes | None = None
        self._sanitized_name = name.lower().replace(" ", "_").replace("-", "_")
        self._ringing = False
        self._ring_clear_task: asyncio.Task | None = None

    async def _async_update_data(self) -> dict:
        """Poll callStatus and trigger ring events."""
        status = await self.client.get_call_status()

        if status == "ring" and not self._ringing:
            await self._trigger_ring()
        elif status != "ring" and self._ringing:
            self._ringing = False
            if self._ring_clear_task and not self._ring_clear_task.done():
                self._ring_clear_task.cancel()
                self._ring_clear_task = None

        return {"call_state": "ringing" if self._ringing else "idle"}

    async def _trigger_ring(self) -> None:
        """Handle a ring event: capture snapshot, publish MQTT, set state."""
        _LOGGER.info(
            "Doorbell %s is ringing! Capturing snapshot and publishing MQTT.",
            self.doorbell_name,
        )
        self._ringing = True

        # Capture snapshot
        try:
            snapshot = await self.client.get_snapshot()
            if snapshot:
                self.latest_snapshot = snapshot
        except Exception:
            _LOGGER.warning("Failed to capture snapshot on ring", exc_info=True)

        # Publish ring event to MQTT
        topic = f"{MQTT_TOPIC_PREFIX}/{self._sanitized_name}/ring"
        try:
            await mqtt.async_publish(
                self.hass, topic, "ring", qos=1, retain=False,
            )
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
            except Exception:
                _LOGGER.warning(
                    "Failed to publish snapshot to MQTT", exc_info=True
                )

        # Auto-clear ringing state after 10 seconds
        if self._ring_clear_task and not self._ring_clear_task.done():
            self._ring_clear_task.cancel()
        self._ring_clear_task = self.hass.async_create_task(
            self._clear_ringing()
        )

    async def _clear_ringing(self) -> None:
        """Clear the ringing state after a delay."""
        await asyncio.sleep(10)
        self._ringing = False
        self.async_set_updated_data({"call_state": "idle"})
