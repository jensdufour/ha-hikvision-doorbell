"""Coordinator for Hikvision Doorbell with webhook push and polling fallback."""

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
    """Manages doorbell state with webhook push events and a keepalive poll."""

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
        self._ringing = False
        self._ring_clear_task: asyncio.Task | None = None

    def handle_alert_stream_event(self, event_xml: str) -> None:
        """Handle an event from the alertStream background thread.

        This is called from a worker thread, so we schedule onto the loop.
        """
        _LOGGER.warning(
            "alertStream event received for %s: %s",
            self.doorbell_name,
            event_xml[:300],
        )
        self.hass.loop.call_soon_threadsafe(
            self.hass.async_create_task, self.trigger_ring()
        )

    async def _async_update_data(self) -> dict:
        """Fast poll of callStatus to detect button press."""
        try:
            call_state, call_raw = await self.client.get_call_status_raw()
        except Exception as err:
            call_state = "idle"
            _LOGGER.debug("Poll error: %s", err)

        # Log every poll so we can see state changes in the logs
        if call_state != "idle":
            _LOGGER.warning(
                "callStatus poll: %s (ringing=%s)",
                call_state,
                self._ringing,
            )

        # If the poll detects a non-idle state, treat it as a ring
        if call_state != "idle" and not self._ringing:
            _LOGGER.warning(
                "Doorbell %s ring detected via polling: %s",
                self.doorbell_name,
                call_state,
            )
            await self.trigger_ring()

        return {"call_state": "ringing" if self._ringing else "idle"}

    async def trigger_ring(self) -> None:
        """Trigger a ring event (called from webhook handler or polling)."""
        if self._ringing:
            return

        _LOGGER.warning(
            "Doorbell %s is RINGING! Capturing snapshot and publishing MQTT.",
            self.doorbell_name,
        )
        self._ringing = True
        self.async_set_updated_data({"call_state": "ringing"})

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
            snapshot_topic = (
                f"{MQTT_TOPIC_PREFIX}/{self._sanitized_name}/snapshot"
            )
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

        # Schedule clearing the ringing state
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
