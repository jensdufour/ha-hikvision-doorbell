"""Coordinator for Hikvision Doorbell with fast ISAPI callStatus polling."""

import asyncio
import base64
import logging
from datetime import timedelta

from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import DOMAIN, MQTT_TOPIC_PREFIX, POLL_INTERVAL_SECONDS
from .isapi import HikvisionISAPIClient, HikvisionISAPIError

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
        self._poll_count = 0
        self._last_status = "idle"
        self._consecutive_errors = 0

    async def _async_update_data(self) -> dict:
        """Poll callStatus and trigger ring events."""
        self._poll_count += 1

        try:
            status, raw = await self.client.get_call_status()
            self._consecutive_errors = 0
        except HikvisionISAPIError as err:
            self._consecutive_errors += 1
            _LOGGER.warning(
                "Poll #%d: callStatus request failed (%d consecutive): %s",
                self._poll_count, self._consecutive_errors, err,
            )
            if self._consecutive_errors >= 5:
                raise UpdateFailed(
                    f"Doorbell unreachable after {self._consecutive_errors} "
                    f"consecutive errors: {err}"
                ) from err
            return {"call_state": "ringing" if self._ringing else "idle"}

        # Log first 5 polls and any state change for diagnostics
        if self._poll_count <= 5 or status != self._last_status:
            _LOGGER.warning(
                "Poll #%d: callStatus=%s (was %s) raw=%s",
                self._poll_count, status, self._last_status, raw.strip(),
            )
        self._last_status = status

        if status == "ring" and not self._ringing:
            await self._trigger_ring()
        elif status != "ring" and self._ringing:
            _LOGGER.warning("Doorbell %s stopped ringing", self.doorbell_name)
            self._ringing = False
            if self._ring_clear_task and not self._ring_clear_task.done():
                self._ring_clear_task.cancel()
                self._ring_clear_task = None

        return {"call_state": "ringing" if self._ringing else "idle"}

    async def _trigger_ring(self) -> None:
        """Handle a ring event: capture snapshot, publish MQTT, set state."""
        _LOGGER.warning(
            "Doorbell %s is RINGING! Capturing snapshot and publishing MQTT.",
            self.doorbell_name,
        )
        self._ringing = True

        # Capture snapshot
        try:
            snapshot = await self.client.get_snapshot()
            if snapshot:
                self.latest_snapshot = snapshot
                _LOGGER.warning(
                    "Snapshot captured: %d bytes", len(snapshot),
                )
            else:
                _LOGGER.warning("Snapshot returned empty")
        except Exception:
            _LOGGER.warning("Failed to capture snapshot on ring", exc_info=True)

        # Publish ring event to MQTT
        topic = f"{MQTT_TOPIC_PREFIX}/{self._sanitized_name}/ring"
        try:
            await mqtt.async_publish(
                self.hass, topic, "ring", qos=1, retain=False,
            )
            _LOGGER.warning("Published ring to MQTT topic %s", topic)
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

        # Auto-clear ringing state after 10 seconds as fallback
        if self._ring_clear_task and not self._ring_clear_task.done():
            self._ring_clear_task.cancel()
        self._ring_clear_task = self.hass.async_create_task(
            self._clear_ringing()
        )

    async def _clear_ringing(self) -> None:
        """Clear the ringing state after a timeout fallback."""
        await asyncio.sleep(10)
        if self._ringing:
            _LOGGER.warning(
                "Doorbell %s: clearing ringing state after timeout",
                self.doorbell_name,
            )
            self._ringing = False
            self.async_set_updated_data({"call_state": "idle"})
