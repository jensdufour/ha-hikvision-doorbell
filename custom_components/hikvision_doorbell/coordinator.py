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
        """Poll multiple endpoints and detect ring events."""
        self._poll_count += 1
        is_ringing = False

        # 1) Poll callStatus
        try:
            call_state, call_raw = await self.client.get_call_status_raw()
        except Exception as err:
            call_state, call_raw = "idle", f"error: {err}"

        # 2) Poll callerInfo
        try:
            caller_state, caller_raw = await self.client.get_caller_info_raw()
        except Exception as err:
            caller_state, caller_raw = "idle", f"error: {err}"

        # 3) Poll IO input 1 (doorStatus)
        try:
            io_state, io_raw = await self.client.get_io_input_status_raw("1")
        except Exception as err:
            io_state, io_raw = "low", f"error: {err}"

        # Ring if ANY source indicates non-idle/triggered state
        if call_state != "idle":
            is_ringing = True
        if caller_state != "idle":
            is_ringing = True
        if io_state.lower() in ("high", "active", "triggered"):
            is_ringing = True

        combined_state = (
            f"call={call_state}, caller={caller_state}, io={io_state}"
        )

        # Log for first 20 polls and on any state change
        if self._poll_count <= 20 or combined_state != self._previous_state:
            _LOGGER.warning(
                "Poll #%d: %s | call_raw=%s | caller_raw=%s | io_raw=%s",
                self._poll_count,
                combined_state,
                call_raw[:200],
                caller_raw[:200],
                io_raw[:200],
            )

        # Detect ringing transition
        if is_ringing and not self._ringing:
            _LOGGER.warning(
                "Doorbell %s RING detected! %s",
                self.doorbell_name,
                combined_state,
            )
            self._ringing = True
            await self._handle_ring()
            if self._ring_clear_task and not self._ring_clear_task.done():
                self._ring_clear_task.cancel()
            self._ring_clear_task = self.hass.async_create_task(
                self._clear_ringing()
            )

        self._previous_state = combined_state
        return {"call_state": "ringing" if self._ringing else "idle"}

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
