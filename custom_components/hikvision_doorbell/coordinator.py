"""Coordinator for Hikvision Doorbell using ISAPI polling."""

import asyncio
import base64
import logging
from datetime import timedelta

from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
)

from .const import DOMAIN, MQTT_TOPIC_PREFIX, SCAN_INTERVAL_SECONDS
from .isapi import HikvisionISAPIClient

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
        self.latest_snapshot: bytes | None = None
        self._sanitized_name = name.lower().replace(" ", "_").replace("-", "_")
        self._previous_state: str | None = None
        self._ringing = False
        self._ring_clear_task: asyncio.Task | None = None
        self._poll_count = 0

    async def _async_update_data(self) -> dict:
        """Poll call status and detect state transitions."""
        self._poll_count += 1

        try:
            current_state, raw_response = await self.client.get_call_status_raw()
        except Exception as err:
            _LOGGER.debug("Error polling call status: %s", err)
            return self.data or {"call_state": "idle"}

        # Log the full raw response at WARNING level for the first 20 polls,
        # and then whenever the state changes. This is critical for diagnostics.
        if self._poll_count <= 20 or current_state != self._previous_state:
            _LOGGER.warning(
                "Poll #%d: call_state=%s, raw=%s",
                self._poll_count,
                current_state,
                raw_response[:300],
            )

        # Detect ringing state
        if current_state != "idle" and self._previous_state == "idle":
            _LOGGER.warning(
                "Doorbell %s state changed: %s -> %s",
                self.doorbell_name,
                self._previous_state,
                current_state,
            )
            if not self._ringing:
                self._ringing = True
                await self._handle_ring()
                if self._ring_clear_task and not self._ring_clear_task.done():
                    self._ring_clear_task.cancel()
                self._ring_clear_task = self.hass.async_create_task(
                    self._clear_ringing()
                )

        self._previous_state = current_state
        return {"call_state": "ringing" if self._ringing else current_state}

    async def _clear_ringing(self) -> None:
        """Clear the ringing state after a delay."""
        await asyncio.sleep(10)
        self._ringing = False
        self.async_set_updated_data({"call_state": "idle"})

    async def _handle_ring(self) -> None:
        """Handle a doorbell ring: capture snapshot and publish to MQTT."""
        _LOGGER.warning(
            "Doorbell %s is RINGING! Capturing snapshot and publishing MQTT.",
            self.doorbell_name,
        )
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
