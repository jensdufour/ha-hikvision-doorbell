"""Coordinator for Hikvision Doorbell with SDK protocol and polling fallback."""

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
from .sdk_protocol import HikvisionSDKReconnector

_LOGGER = logging.getLogger(__name__)


class HikvisionDoorbellCoordinator(DataUpdateCoordinator):
    """Manages doorbell state with SDK protocol events and a keepalive poll."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: HikvisionISAPIClient,
        name: str,
        device_info: dict,
        sdk_port: int = 8000,
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
        self._sdk_port = sdk_port
        self._sdk_reconnector: HikvisionSDKReconnector | None = None

    async def start_sdk_listener(self, host: str, username: str, password: str) -> None:
        """Start the SDK protocol connection for real-time event detection."""
        self._sdk_reconnector = HikvisionSDKReconnector(
            host=host,
            port=self._sdk_port,
            username=username,
            password=password,
            on_ring=self._on_sdk_ring,
            on_event=self._on_sdk_event,
        )
        await self._sdk_reconnector.start()

    async def _on_sdk_ring(self) -> None:
        """Called by the SDK protocol when a doorbell ring is detected."""
        _LOGGER.warning(
            "SDK ring event received for %s!", self.doorbell_name
        )
        await self.trigger_ring()

    async def _on_sdk_event(self, cmd1: int, cmd2: int, payload: bytes) -> None:
        """Called by the SDK protocol for any event (for diagnostics)."""
        _LOGGER.warning(
            "SDK event for %s: cmd1=0x%08x cmd2=0x%04x payload_size=%d",
            self.doorbell_name, cmd1, cmd2, len(payload),
        )

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
        """Slow keepalive poll. Ring detection is via SDK protocol, not polling."""
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

    async def stop_sdk(self) -> None:
        """Stop the SDK protocol connection."""
        if self._sdk_reconnector:
            await self._sdk_reconnector.stop()
            self._sdk_reconnector = None
