"""Coordinator for Hikvision Doorbell with ISAPI callStatus polling."""

import asyncio
import logging
from datetime import timedelta

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from .const import DOMAIN, POLL_INTERVAL_SECONDS
from .isapi import HikvisionISAPIAuthError, HikvisionISAPIClient, HikvisionISAPIError

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
        self._ringing = False
        self._ring_clear_task: asyncio.Task | None = None
        self._last_status = "idle"
        self._consecutive_errors = 0

    async def _async_update_data(self) -> dict:
        """Poll callStatus and trigger ring events."""
        try:
            status, raw = await self.client.get_call_status()
            self._consecutive_errors = 0
        except HikvisionISAPIAuthError:
            # 401 from callStatus means the endpoint is not available on this
            # device, not that credentials are wrong. Return idle silently.
            self._consecutive_errors = 0
            return {"call_state": "ringing" if self._ringing else "idle"}
        except HikvisionISAPIError as err:
            self._consecutive_errors += 1
            _LOGGER.debug(
                "callStatus request failed (%d consecutive): %s",
                self._consecutive_errors, err,
            )
            if self._consecutive_errors >= 5:
                raise UpdateFailed(
                    f"Doorbell unreachable after {self._consecutive_errors} "
                    f"consecutive errors: {err}"
                ) from err
            return {"call_state": "ringing" if self._ringing else "idle"}

        if status != self._last_status:
            _LOGGER.debug("callStatus changed: %s -> %s", self._last_status, status)
        self._last_status = status

        if status == "ring" and not self._ringing:
            await self._trigger_ring()
        elif status != "ring" and self._ringing:
            _LOGGER.debug("Doorbell %s stopped ringing", self.doorbell_name)
            self._ringing = False
            self._cancel_ring_clear_task()

        return {"call_state": "ringing" if self._ringing else "idle"}

    async def _trigger_ring(self) -> None:
        """Handle a ring event: capture snapshot and set state."""
        _LOGGER.info("Doorbell %s is ringing", self.doorbell_name)
        self._ringing = True

        # Capture snapshot
        try:
            snapshot = await self.client.get_snapshot()
            if snapshot:
                self.latest_snapshot = snapshot
                _LOGGER.debug("Snapshot captured: %d bytes", len(snapshot))
        except Exception:
            _LOGGER.debug("Failed to capture snapshot on ring", exc_info=True)

        # Publish ring event to MQTT if available
        await self._publish_mqtt_ring()

        # Auto-clear ringing state after 10 seconds as fallback
        self._cancel_ring_clear_task()
        self._ring_clear_task = self.hass.async_create_task(
            self._clear_ringing()
        )

    async def _publish_mqtt_ring(self) -> None:
        """Publish ring event to MQTT if the integration is available."""
        if not self.hass.services.has_service("mqtt", "publish"):
            return

        from homeassistant.components import mqtt

        sanitized = self.doorbell_name.lower().replace(" ", "_").replace("-", "_")
        topic = f"{DOMAIN}/{sanitized}/ring"
        try:
            await mqtt.async_publish(self.hass, topic, "ring", qos=1, retain=False)
            _LOGGER.debug("Published ring event to MQTT topic %s", topic)
        except Exception:
            _LOGGER.debug("Failed to publish ring event to MQTT", exc_info=True)

    def _cancel_ring_clear_task(self) -> None:
        """Cancel any pending ring clear task."""
        if self._ring_clear_task and not self._ring_clear_task.done():
            self._ring_clear_task.cancel()
            self._ring_clear_task = None

    async def _clear_ringing(self) -> None:
        """Clear the ringing state after a timeout fallback."""
        await asyncio.sleep(10)
        if self._ringing:
            _LOGGER.debug(
                "Doorbell %s: clearing ringing state after timeout",
                self.doorbell_name,
            )
            self._ringing = False
            self.async_set_updated_data({"call_state": "idle"})

    async def async_shutdown(self) -> None:
        """Clean up on coordinator shutdown."""
        self._cancel_ring_clear_task()
        await super().async_shutdown()
