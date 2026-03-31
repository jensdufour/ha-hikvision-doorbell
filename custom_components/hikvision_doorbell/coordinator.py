"""Coordinator for Hikvision Doorbell with alert stream and callStatus fallback."""

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

# Event types from the ISAPI alert stream that indicate a doorbell ring
_RING_EVENT_TYPES = frozenset({
    "videointercomevent",
    "videointercom",
    "callingdevice",
    "bellringing",
})

# Event states that indicate the event is currently active
_ACTIVE_STATES = frozenset({"active", "1"})


class HikvisionDoorbellCoordinator(DataUpdateCoordinator):
    """Detect doorbell rings via ISAPI alert stream or callStatus polling.

    Tries the alert stream first (persistent HTTP connection, event-driven).
    Falls back to callStatus polling if the alert stream is unavailable.
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
        self._stream_task: asyncio.Task | None = None
        self._stream_available: bool | None = None  # None = not yet probed
        self._no_detection_warned = False

    async def async_start_event_stream(self) -> bool:
        """Probe and start the alert stream if available.

        Returns True if the stream was started, False otherwise.
        """
        try:
            available = await self.client.check_alert_stream()
        except Exception:
            available = False

        self._stream_available = available
        if not available:
            _LOGGER.debug(
                "Alert stream not available for %s, using callStatus polling",
                self.doorbell_name,
            )
            return False

        _LOGGER.info(
            "Alert stream available for %s, starting event listener",
            self.doorbell_name,
        )
        self._stream_task = self.hass.async_create_task(
            self._run_event_stream()
        )
        return True

    async def _run_event_stream(self) -> None:
        """Background task: listen to the alert stream and trigger rings."""
        reconnect_delay = 5
        empty_attempts = 0
        max_empty_attempts = 3
        while True:
            try:
                _LOGGER.debug("Connecting to alert stream for %s", self.doorbell_name)
                got_data = False
                async for event in self.client.iter_alert_stream():
                    _LOGGER.debug("Alert stream event: %s", event)
                    await self._handle_stream_event(event)
                    got_data = True
                    reconnect_delay = 5
                    empty_attempts = 0

                # Stream ended normally
                if got_data:
                    # Had data but stream closed; reconnect after short delay
                    _LOGGER.debug(
                        "Alert stream closed after receiving data for %s",
                        self.doorbell_name,
                    )
                else:
                    empty_attempts += 1
                    _LOGGER.debug(
                        "Alert stream closed without data for %s (%d/%d)",
                        self.doorbell_name, empty_attempts, max_empty_attempts,
                    )
                    if empty_attempts >= max_empty_attempts:
                        _LOGGER.warning(
                            "Alert stream for %s closed %d times without "
                            "data; disabling event stream",
                            self.doorbell_name, empty_attempts,
                        )
                        self._stream_available = False
                        return
            except HikvisionISAPIAuthError:
                _LOGGER.warning(
                    "Alert stream returned 401 for %s; disabling",
                    self.doorbell_name,
                )
                self._stream_available = False
                return
            except asyncio.CancelledError:
                return
            except Exception as err:
                _LOGGER.debug(
                    "Alert stream error for %s: %s",
                    self.doorbell_name, err,
                )

            # Always wait before reconnecting
            _LOGGER.debug(
                "Reconnecting alert stream in %ds for %s",
                reconnect_delay, self.doorbell_name,
            )
            await asyncio.sleep(reconnect_delay)
            reconnect_delay = min(reconnect_delay * 2, 60)

    async def _handle_stream_event(self, event: dict[str, str]) -> None:
        """Process a single event from the alert stream."""
        event_type = event.get("eventType", "").lower()
        event_state = event.get("eventState", "").lower()

        # Also check nested VideoInterEvent.eventType
        nested_type = event.get("VideoInterEvent.eventType", "").lower()

        is_ring = (
            event_type in _RING_EVENT_TYPES
            or nested_type in _RING_EVENT_TYPES
        )
        is_active = event_state in _ACTIVE_STATES

        if is_ring and is_active and not self._ringing:
            await self._trigger_ring()
            self.async_set_updated_data({"call_state": "ringing"})
        elif is_ring and not is_active and self._ringing:
            _LOGGER.debug("Doorbell %s stopped ringing (stream)", self.doorbell_name)
            self._ringing = False
            self._cancel_ring_clear_task()
            self.async_set_updated_data({"call_state": "idle"})

    async def _async_update_data(self) -> dict:
        """Poll callStatus (only if alert stream is not active)."""
        # If the alert stream is handling ring detection, just return state
        if self._stream_task and not self._stream_task.done():
            return {"call_state": "ringing" if self._ringing else "idle"}

        # If callStatus polling is also disabled, no ring detection possible
        if not self.client._callstatus_available:
            if not self._no_detection_warned:
                _LOGGER.warning(
                    "No ring detection method available for %s. "
                    "Both alert stream and callStatus are unavailable",
                    self.doorbell_name,
                )
                self._no_detection_warned = True
                self.update_interval = timedelta(seconds=300)
            return {"call_state": "idle"}

        # Fall back to callStatus polling
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
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
            try:
                await self._stream_task
            except asyncio.CancelledError:
                pass
            self._stream_task = None
        await super().async_shutdown()
