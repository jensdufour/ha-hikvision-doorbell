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
        self._mqtt_unsubscribe = None  # MQTT listener cleanup callback
        self._mqtt_listener_active = False

    async def async_start_event_stream(self) -> bool:
        """Start the alert stream background task.

        The task itself will determine if the stream actually works.
        Returns True (task started). The task may disable itself later.
        """
        _LOGGER.info(
            "Starting alert stream listener for %s",
            self.doorbell_name,
        )
        self._stream_available = True
        self._stream_task = self.hass.async_create_task(
            self._run_event_stream()
        )
        return True

    async def async_start_mqtt_listener(self) -> bool:
        """Subscribe to MQTT ring events from the companion SDK add-on.

        The add-on publishes to 'hikvision_doorbell/{serial}/ring'.
        This provides a third ring detection path for devices where
        HTTP-based methods (alert stream, callStatus) do not work.

        Returns True if the subscription was set up.
        """
        if "mqtt" not in self.hass.config.components:
            _LOGGER.debug("MQTT integration not available, skipping SDK listener")
            return False

        serial = self.device_info_data.get("serial", "")
        if not serial:
            _LOGGER.debug("No serial number available, skipping MQTT listener")
            return False

        topic = f"hikvision_doorbell/{serial}/ring"

        from homeassistant.components import mqtt
        from homeassistant.core import callback

        @callback
        def _handle_mqtt_ring(msg) -> None:
            """Handle ring event from the SDK add-on via MQTT."""
            _LOGGER.info(
                "Ring event received via MQTT (SDK add-on) for %s",
                self.doorbell_name,
            )
            if not self._ringing:
                self.hass.async_create_task(self._trigger_ring())
                self.async_set_updated_data({"call_state": "ringing"})

        self._mqtt_unsubscribe = await mqtt.async_subscribe(
            self.hass, topic, _handle_mqtt_ring, qos=1
        )
        self._mqtt_listener_active = True
        _LOGGER.info("Subscribed to SDK add-on MQTT topic: %s", topic)
        return True

    async def _run_event_stream(self) -> None:
        """Background task: listen to the alert stream and trigger rings."""
        import time

        reconnect_delay = 5
        attempt = 0
        while True:
            attempt += 1
            try:
                _LOGGER.debug("Connecting to alert stream for %s", self.doorbell_name)
                got_data = False
                start = time.monotonic()
                async for event in self.client.iter_alert_stream():
                    _LOGGER.debug("Alert stream event: %s", event)
                    await self._handle_stream_event(event)
                    got_data = True
                    reconnect_delay = 5
                    attempt = 0
                elapsed = time.monotonic() - start

                if got_data:
                    _LOGGER.debug(
                        "Alert stream closed after receiving data for %s",
                        self.doorbell_name,
                    )
                elif elapsed < 2.0:
                    # Stream returned 200 but closed almost immediately.
                    # This firmware does not actually support the alert stream.
                    _LOGGER.info(
                        "Alert stream for %s closed instantly (%.1fs, no data); "
                        "endpoint not supported, falling back to callStatus",
                        self.doorbell_name, elapsed,
                    )
                    self._stream_available = False
                    return
                else:
                    _LOGGER.debug(
                        "Alert stream closed without data for %s after %.1fs",
                        self.doorbell_name, elapsed,
                    )
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
                if self._mqtt_listener_active:
                    _LOGGER.info(
                        "HTTP ring detection unavailable for %s; "
                        "using MQTT listener from SDK add-on",
                        self.doorbell_name,
                    )
                else:
                    _LOGGER.warning(
                        "No ring detection method available for %s. "
                        "Both alert stream and callStatus are unavailable. "
                        "Install the Hikvision Doorbell SDK add-on for "
                        "native event detection via MQTT",
                        self.doorbell_name,
                    )
                self._no_detection_warned = True
                self.update_interval = timedelta(seconds=300)
            return {"call_state": "ringing" if self._ringing else "idle"}

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
        if self._mqtt_unsubscribe:
            self._mqtt_unsubscribe()
            self._mqtt_unsubscribe = None
        if self._stream_task and not self._stream_task.done():
            self._stream_task.cancel()
            try:
                await self._stream_task
            except asyncio.CancelledError:
                pass
            self._stream_task = None
        await super().async_shutdown()
