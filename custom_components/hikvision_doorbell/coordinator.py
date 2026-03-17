"""Coordinator for Hikvision Doorbell using ISAPI alertStream."""

import asyncio
import base64
import logging
import xml.etree.ElementTree as ET
from datetime import timedelta

from homeassistant.components import mqtt
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
)

from .const import DOMAIN, MQTT_TOPIC_PREFIX, SCAN_INTERVAL_SECONDS
from .isapi import HikvisionISAPIClient

_LOGGER = logging.getLogger(__name__)

# Event types from the ISAPI alertStream that indicate a doorbell ring.
# These are matched case-insensitively against the <eventType> XML value.
_RING_EVENT_TYPES = {
    "videointercom",
    "callstatus",
    "doorbell",
    "videointercomevent",
    "videointercomalarm",
}


class HikvisionDoorbellCoordinator(DataUpdateCoordinator):
    """Manages the Hikvision doorbell alert stream and ring events.

    Uses ISAPI alertStream for real-time push events instead of polling.
    Falls back to callStatus polling if the alertStream is not available.
    """

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
        self._stream_started = False

    async def start_alert_stream(self) -> None:
        """Start listening to the ISAPI alert stream."""
        if self._stream_started:
            return
        self._stream_started = True

        def _on_alert_event(raw_event: str) -> None:
            """Called from the executor thread when an alert event arrives."""
            event_type = self._extract_event_type(raw_event)
            _LOGGER.info(
                "Alert stream event received - eventType=%s, raw length=%d",
                event_type or "unknown",
                len(raw_event),
            )

            if self._is_ring_event(event_type, raw_event):
                _LOGGER.info(
                    "Ring event detected (eventType=%s)!", event_type
                )
                self.hass.loop.call_soon_threadsafe(
                    self.hass.async_create_task,
                    self._handle_ring_from_stream(),
                )
            else:
                _LOGGER.info(
                    "Non-ring event from stream: eventType=%s, data=%s",
                    event_type,
                    raw_event[:300],
                )

        await self.client.start_alert_stream(_on_alert_event)
        _LOGGER.info(
            "Started ISAPI alert stream for %s", self.doorbell_name
        )

    @staticmethod
    def _extract_event_type(raw_event: str) -> str | None:
        """Extract the eventType from the raw event XML."""
        try:
            xml_start = raw_event.find("<EventNotificationAlert")
            if xml_start < 0:
                xml_start = raw_event.find("<?xml")
            if xml_start >= 0:
                xml_text = raw_event[xml_start:]
                root = ET.fromstring(xml_text)
                for elem in root.iter():
                    tag = (
                        elem.tag.split("}")[-1]
                        if "}" in elem.tag
                        else elem.tag
                    )
                    if tag.lower() == "eventtype" and elem.text:
                        return elem.text.strip()
        except ET.ParseError:
            _LOGGER.debug("Could not parse event XML: %s", raw_event[:200])
        return None

    @staticmethod
    def _is_ring_event(event_type: str | None, raw_event: str) -> bool:
        """Determine if the event indicates a doorbell ring."""
        if event_type:
            if event_type.lower() in _RING_EVENT_TYPES:
                return True
        # Fallback: check raw text for ring indicators
        lower = raw_event.lower()
        return any(
            kw in lower
            for kw in ("ringing", "doorbell_ringing", "callincoming", "callstatus")
        )

    async def _handle_ring_from_stream(self) -> None:
        """Handle a ring event from the alert stream."""
        _LOGGER.info("Doorbell %s is ringing! (from alert stream)", self.doorbell_name)
        self._ringing = True
        self.data = {"call_state": "ringing"}
        self.async_update_listeners()

        await self._handle_ring()

        # Clear ringing state after 10 seconds
        if self._ring_clear_task and not self._ring_clear_task.done():
            self._ring_clear_task.cancel()
        self._ring_clear_task = self.hass.async_create_task(
            self._clear_ringing()
        )

    async def _clear_ringing(self) -> None:
        """Clear the ringing state after a delay."""
        await asyncio.sleep(10)
        self._ringing = False
        self.data = {"call_state": "idle"}
        self.async_update_listeners()

    async def _async_update_data(self) -> dict:
        """Periodic poll as fallback / keepalive.

        If the alert stream is running, this just confirms connectivity.
        If the alert stream is not running, it polls callStatus.
        """
        if self._ringing:
            return {"call_state": "ringing"}

        try:
            current_state = await self.client.get_call_status()
        except Exception:
            return self.data or {"call_state": "idle"}

        if current_state == "ringing" and not self._ringing:
            _LOGGER.info("Doorbell %s is ringing! (from poll)", self.doorbell_name)
            self._ringing = True
            await self._handle_ring()
            if self._ring_clear_task and not self._ring_clear_task.done():
                self._ring_clear_task.cancel()
            self._ring_clear_task = self.hass.async_create_task(
                self._clear_ringing()
            )

        return {"call_state": current_state if current_state == "ringing" else "idle"}

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
