"""Hikvision Doorbell integration."""

import logging
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from aiohttp import web

from homeassistant.components import webhook
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady
from homeassistant.helpers.network import get_url, NoURLAvailableError

from .const import DOMAIN, WEBHOOK_ID_PREFIX
from .coordinator import HikvisionDoorbellCoordinator
from .isapi import HikvisionISAPIClient, HikvisionISAPIError

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["binary_sensor", "image"]
_VERSION = "1.2.6"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Hikvision Doorbell from a config entry."""
    _LOGGER.warning("Hikvision Doorbell integration v%s loading", _VERSION)
    client = HikvisionISAPIClient(
        host=entry.data["host"],
        username=entry.data["username"],
        password=entry.data["password"],
    )

    try:
        device_info = await client.get_device_info()
    except HikvisionISAPIError as err:
        await client.close()
        raise ConfigEntryNotReady(
            f"Cannot connect to doorbell: {err}"
        ) from err
    except Exception as err:
        await client.close()
        raise ConfigEntryNotReady(
            f"Unexpected error connecting to doorbell: {err}"
        ) from err

    coordinator = HikvisionDoorbellCoordinator(
        hass=hass,
        client=client,
        name=entry.data["name"],
        device_info=device_info,
    )
    await coordinator.async_config_entry_first_refresh()

    # Fetch an initial snapshot so the image entity is not "unknown"
    try:
        snapshot = await client.get_snapshot()
        if snapshot:
            coordinator.latest_snapshot = snapshot
    except Exception:
        _LOGGER.debug("Could not fetch initial snapshot", exc_info=True)

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Register webhook for event push from the doorbell
    webhook_id = f"{WEBHOOK_ID_PREFIX}_{entry.entry_id}"
    webhook.async_register(
        hass,
        DOMAIN,
        "Hikvision Doorbell",
        webhook_id,
        handler=_handle_webhook,
        local_only=True,
    )
    _LOGGER.info("Registered webhook %s for doorbell events", webhook_id)

    # Try to configure the doorbell to push events to our webhook
    hass.async_create_task(
        _configure_doorbell_push(hass, client, webhook_id, entry)
    )

    # Probe endpoints in background for diagnostics
    hass.async_create_task(client.probe_endpoints())

    # alertStream confirmed non-functional on this device model
    # (returns fixed 40-byte XML declaration, not a real stream)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _configure_doorbell_push(
    hass: HomeAssistant,
    client: HikvisionISAPIClient,
    webhook_id: str,
    entry: ConfigEntry,
) -> None:
    """Configure the doorbell to POST event notifications to our webhook."""
    # Determine the HA internal URL so the doorbell can reach us
    try:
        ha_url = get_url(hass, prefer_external=False, allow_internal=True)
    except NoURLAvailableError:
        _LOGGER.warning(
            "No internal URL configured in HA. "
            "Cannot configure doorbell push notifications. "
            "Set an internal URL in Settings > System > Network."
        )
        return

    parsed = urlparse(ha_url)
    ha_ip = parsed.hostname
    ha_port = parsed.port or (443 if parsed.scheme == "https" else 8123)
    webhook_path = f"/api/webhook/{webhook_id}"

    _LOGGER.warning(
        "Configuring doorbell HTTP host notification: "
        "http://%s:%s%s",
        ha_ip,
        ha_port,
        webhook_path,
    )

    # First, log current HTTP host config for diagnostics
    try:
        current = await client.get_http_hosts()
        _LOGGER.warning("Current HTTP host config:\n%s", current)
    except Exception as err:
        _LOGGER.warning("Could not read HTTP host config: %s", err)

    # Configure the doorbell to push events to us
    try:
        result = await client.configure_http_host(
            "1", ha_ip, ha_port, webhook_path
        )
        _LOGGER.warning("HTTP host configuration result: %s", result)

        # Read back to verify
        try:
            updated = await client.get_http_hosts()
            _LOGGER.warning("Updated HTTP host config:\n%s", updated)
        except Exception:
            pass
    except Exception as err:
        _LOGGER.warning(
            "Could not configure HTTP host notification on doorbell: %s. "
            "Ring detection will rely on polling fallback (which may not work "
            "on this device model).",
            err,
        )

    # Enable call center on doorbell keys so button presses report to HTTP host
    try:
        result = await client.enable_call_center_on_keys()
        _LOGGER.warning("Enable call center on keys result: %s", result)
    except Exception as err:
        _LOGGER.warning("Could not enable call center on keys: %s", err)

    # Enable event subscriptions so the doorbell actually pushes events
    try:
        result = await client.enable_center_notifications()
        _LOGGER.warning("Enable center notifications result: %s", result)
    except Exception as err:
        _LOGGER.warning("Could not enable center notifications: %s", err)

    try:
        result = await client.enable_host_notification_subscriptions("1")
        _LOGGER.warning("Host notification subscriptions result: %s", result)
    except Exception as err:
        _LOGGER.warning("Could not configure host subscriptions: %s", err)


async def _handle_webhook(
    hass: HomeAssistant, webhook_id: str, request: web.Request
) -> web.Response:
    """Handle an incoming event notification from the doorbell."""
    try:
        body = await request.text()
    except Exception:
        _LOGGER.warning("Could not read webhook body")
        return web.Response(status=200)

    _LOGGER.warning("Doorbell webhook event received: %s", body[:1000])

    # Find the coordinator for this webhook
    entry_id = webhook_id.replace(f"{WEBHOOK_ID_PREFIX}_", "", 1)
    coordinator: HikvisionDoorbellCoordinator | None = (
        hass.data.get(DOMAIN, {}).get(entry_id)
    )
    if coordinator is None:
        _LOGGER.warning("No coordinator found for webhook %s", webhook_id)
        return web.Response(status=200)

    # Parse the event - be generous in what we accept as a ring event
    is_ring = _parse_event_is_ring(body)

    if is_ring:
        _LOGGER.warning("Ring event detected from webhook!")
        await coordinator.trigger_ring()
    else:
        _LOGGER.warning("Non-ring webhook event (logging for diagnostics)")

    return web.Response(status=200)


def _parse_event_is_ring(body: str) -> bool:
    """Parse an ISAPI event notification and determine if it is a ring event.

    Hikvision event notifications are XML with an <EventNotificationAlert> root.
    We look for event types related to video intercom / doorbell press.
    """
    # Check for known ring-related keywords in the raw body first
    lower = body.lower()
    ring_keywords = (
        "videoloss",
        "VideoIntercom",
        "callincoming",
        "bellringing",
        "doorbell",
        "callstatus",
        "ringing",
        "ring",
    )
    for kw in ring_keywords:
        if kw.lower() in lower:
            return True

    # Try XML parsing
    try:
        root = ET.fromstring(body)

        # Look for eventType element
        for prefix in (
            "{http://www.hikvision.com/ver20/XMLSchema}",
            "{http://www.isapi.org/ver20/XMLSchema}",
            "{*}",
            "",
        ):
            event_type = root.find(f"{prefix}eventType")
            event_state = root.find(f"{prefix}eventState")
            event_desc = root.find(f"{prefix}eventDescription")

            if event_type is not None and event_type.text:
                et = event_type.text.lower()
                if any(
                    kw in et
                    for kw in ("intercom", "doorbell", "bell", "call", "ring")
                ):
                    return True

            if event_desc is not None and event_desc.text:
                ed = event_desc.text.lower()
                if any(
                    kw in ed
                    for kw in ("incoming", "ring", "bell", "call")
                ):
                    return True

            if event_state is not None and event_state.text:
                if event_state.text.lower() == "active":
                    # Any active event from the doorbell is likely a ring
                    return True
    except ET.ParseError:
        pass

    return False


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    # Unregister webhook
    webhook_id = f"{WEBHOOK_ID_PREFIX}_{entry.entry_id}"
    webhook.async_unregister(hass, webhook_id)

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        coordinator: HikvisionDoorbellCoordinator = hass.data[DOMAIN].pop(
            entry.entry_id
        )
        # Try to clean up HTTP host config on the doorbell
        try:
            await coordinator.client.delete_http_host("1")
        except Exception:
            _LOGGER.debug("Could not clean up HTTP host config", exc_info=True)
        await coordinator.client.close()
    return unload_ok
