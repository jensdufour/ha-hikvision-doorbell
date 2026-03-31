"""ISAPI client for Hikvision doorbell devices."""

import asyncio
import json
import logging
import xml.etree.ElementTree as ET
from collections.abc import AsyncGenerator
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)


class HikvisionISAPIError(Exception):
    """Error communicating with the Hikvision device."""


class HikvisionISAPIAuthError(HikvisionISAPIError):
    """Authentication failed."""


class HikvisionISAPILockoutError(HikvisionISAPIAuthError):
    """Account locked by the device after too many failed attempts."""


class HikvisionISAPIClient:
    """Async client for the Hikvision ISAPI interface.

    Tries Digest auth first (most common on Hikvision devices).
    Falls back to Basic auth during initial connection if Digest fails.
    """

    def __init__(self, host: str, username: str, password: str) -> None:
        if not host.startswith(("http://", "https://")):
            base_url = f"http://{host}"
        else:
            base_url = host
        self._base_url = base_url.rstrip("/")
        self._username = username
        self._password = password
        self._client: httpx.AsyncClient | None = None
        self._device_info_cache: dict[str, Any] | None = None
        self._callstatus_available: bool = True

    def _create_client(self, auth: httpx.Auth) -> httpx.AsyncClient:
        """Create an httpx client with the given auth method."""
        return httpx.AsyncClient(
            auth=auth,
            timeout=httpx.Timeout(10.0),
            verify=False,
            follow_redirects=True,
        )

    async def async_init(self) -> None:
        """Probe the device to determine the correct auth method.

        Tries Digest first, then Basic.  Call this once during setup.
        Caches the device-info response so get_device_info() needs no
        additional round-trip.  Raises on authentication failure.
        """
        last_response_body: bytes | None = None

        for auth_type, auth in [
            ("Digest", httpx.DigestAuth(self._username, self._password)),
            ("Basic", httpx.BasicAuth(self._username, self._password)),
        ]:
            client = self._create_client(auth)
            try:
                response = await client.get(
                    f"{self._base_url}/ISAPI/System/deviceInfo"
                )
                _LOGGER.debug(
                    "Auth probe %s: HTTP %s", auth_type, response.status_code
                )
                if response.status_code == 401:
                    last_response_body = response.content
                    await client.aclose()
                    continue

                self._client = client
                _LOGGER.debug("Auth method resolved: %s", auth_type)

                # Cache device info from the successful probe response
                if response.status_code == 200:
                    try:
                        self._device_info_cache = self._parse_device_info_xml(
                            response.content
                        )
                    except Exception:
                        pass  # Will be fetched again by get_device_info()
                return
            except httpx.HTTPError as err:
                _LOGGER.debug("Auth probe %s error: %s", auth_type, err)
                await client.aclose()

        # Both auth methods returned 401 or failed
        if last_response_body:
            body_text = last_response_body.decode("utf-8", errors="replace")
            _LOGGER.debug("Last 401 response body: %.500s", body_text)
            if any(
                indicator in body_text
                for indicator in (
                    "userFloor",
                    "isIrreversive",
                    "retryLoginTime",
                    "invalidOperation",
                )
            ):
                raise HikvisionISAPILockoutError(
                    "Account is locked by the device due to too many failed "
                    "login attempts. Wait for the lockout to expire and try again"
                )

        raise HikvisionISAPIAuthError("Invalid username or password")

    def _ensure_client(self) -> httpx.AsyncClient:
        """Return the client, creating a default if async_init was not called."""
        if self._client is None:
            self._client = self._create_client(
                httpx.DigestAuth(self._username, self._password)
            )
        return self._client

    async def _request(self, path: str, timeout: float = 10.0) -> tuple[bytes, dict[str, str]]:
        """Make an authenticated async request to the device."""
        client = self._ensure_client()
        url = f"{self._base_url}{path}"
        try:
            response = await client.get(url, timeout=timeout)
            if response.status_code == 401:
                raise HikvisionISAPIAuthError(
                    f"Authentication failed for {path}"
                )
            response.raise_for_status()
            return response.content, dict(response.headers)
        except HikvisionISAPIError:
            raise
        except httpx.HTTPStatusError as err:
            raise HikvisionISAPIError(
                f"HTTP {err.response.status_code} requesting {path}"
            ) from err
        except (httpx.ConnectError, httpx.ConnectTimeout) as err:
            raise HikvisionISAPIError(
                f"Cannot connect to {self._base_url}: {err}"
            ) from err
        except httpx.TimeoutException as err:
            raise HikvisionISAPIError(
                f"Timeout requesting {path}: {err}"
            ) from err
        except httpx.HTTPError as err:
            raise HikvisionISAPIError(
                f"Connection error: {err}"
            ) from err

    @staticmethod
    def _parse_device_info_xml(body: bytes) -> dict[str, Any]:
        """Parse device info XML response into a dict."""
        text = body.decode("utf-8", errors="replace")
        root = ET.fromstring(text)

        def _find_text(tag: str) -> str | None:
            for prefix in (
                "{http://www.hikvision.com/ver20/XMLSchema}",
                "{*}",
                "",
            ):
                elem = root.find(f"{prefix}{tag}")
                if elem is not None and elem.text:
                    return elem.text.strip()
            return None

        return {
            "name": _find_text("deviceName"),
            "model": _find_text("model"),
            "serial": _find_text("serialNumber"),
            "firmware": _find_text("firmwareVersion"),
            "hardware": _find_text("hardwareVersion"),
            "mac": _find_text("macAddress"),
        }

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information from the ISAPI /System/deviceInfo endpoint."""
        if self._device_info_cache is not None:
            info = self._device_info_cache
            self._device_info_cache = None
            return info
        body, _ = await self._request("/ISAPI/System/deviceInfo")
        return self._parse_device_info_xml(body)

    async def get_call_status(self) -> tuple[str, str]:
        """Get the current video intercom call status.

        Tries multiple known ISAPI paths for call status.
        Returns (status, raw_response_text).
        """
        if not self._callstatus_available:
            return "idle", ""

        paths = [
            "/ISAPI/VideoIntercom/callStatus?format=json",
            "/ISAPI/VideoIntercom/callStatus",
        ]
        last_error: Exception | None = None
        auth_failures = 0
        for path in paths:
            try:
                body, _ = await self._request(path)
            except HikvisionISAPIAuthError:
                # 401 on this endpoint means it doesn't exist or requires
                # different permissions, not that credentials are wrong
                # (credentials were validated during async_init).
                auth_failures += 1
                continue
            except HikvisionISAPIError as err:
                last_error = err
                continue

            text = body.decode("utf-8", errors="replace")

            # Try JSON first
            try:
                data = json.loads(text)
                status = data.get("CallStatus", {}).get("status")
                if status:
                    return status, text
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

            # Fallback: try XML parsing for firmware that ignores format=json
            try:
                root = ET.fromstring(text)
                for prefix in (
                    "{http://www.hikvision.com/ver20/XMLSchema}",
                    "{*}",
                    "",
                ):
                    elem = root.find(f"{prefix}status")
                    if elem is not None and elem.text:
                        return elem.text.strip(), text
            except ET.ParseError:
                pass

        # All paths returned 401: disable polling to prevent account lockout
        if auth_failures == len(paths):
            self._callstatus_available = False
            _LOGGER.warning(
                "callStatus endpoint returned 401 for all paths; "
                "disabling callStatus polling to prevent account lockout. "
                "Ring detection will not work"
            )
            return "idle", ""

        if last_error:
            raise HikvisionISAPIError(
                f"callStatus unavailable: {last_error}"
            )
        return "idle", ""

    async def get_snapshot(self) -> bytes | None:
        """Capture a JPEG snapshot from the doorbell camera.

        Tries channel 101 (main stream) first, then falls back to channel 1.
        """
        for channel in ("101", "1"):
            try:
                body, headers = await self._request(
                    f"/ISAPI/Streaming/channels/{channel}/picture"
                )
                content_type = headers.get("content-type", "")
                if content_type.startswith("image/") or body[:3] == b"\xff\xd8\xff":
                    return body
            except HikvisionISAPIError:
                continue
        return None

    # -- ISAPI Alert Stream (event-driven ring detection) -------------------

    async def check_alert_stream(self) -> bool:
        """Test whether the alert stream endpoint is accessible.

        Returns True if the device accepts the connection (HTTP 200),
        False on 401 or connection error.
        """
        client = self._ensure_client()
        url = f"{self._base_url}/ISAPI/Event/notification/alertStream"
        try:
            response = await client.get(url, timeout=5.0)
            if response.status_code == 401:
                return False
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def iter_alert_stream(self) -> AsyncGenerator[dict[str, str], None]:
        """Connect to the ISAPI alert stream and yield parsed events.

        This is a long-lived HTTP connection.  The device sends multipart
        chunks separated by a boundary string.  Each chunk contains an XML
        ``EventNotificationAlert`` element.

        Yields dicts with keys: event_type, event_state, channel_id,
        plus any extra fields found in the XML.
        """
        client = self._ensure_client()
        url = f"{self._base_url}/ISAPI/Event/notification/alertStream"

        async with client.stream("GET", url) as response:
            if response.status_code == 401:
                raise HikvisionISAPIAuthError(
                    "Alert stream authentication failed"
                )
            response.raise_for_status()

            buffer = ""
            async for chunk in response.aiter_text():
                buffer += chunk
                # Split on multipart boundaries (any line starting with --)
                while True:
                    event_dict = self._extract_alert_event(buffer)
                    if event_dict is None:
                        break
                    event_dict, buffer = event_dict
                    yield event_dict

    def _extract_alert_event(
        self, buffer: str
    ) -> tuple[dict[str, str], str] | None:
        """Try to extract one complete XML event from the buffer.

        Returns (parsed_event_dict, remaining_buffer) or None if no
        complete event is available yet.
        """
        # Look for a complete XML document between boundaries
        xml_start = buffer.find("<EventNotificationAlert")
        if xml_start == -1:
            return None

        xml_end = buffer.find("</EventNotificationAlert>", xml_start)
        if xml_end == -1:
            return None

        xml_end += len("</EventNotificationAlert>")
        xml_text = buffer[xml_start:xml_end]
        remaining = buffer[xml_end:]

        try:
            return self._parse_alert_xml(xml_text), remaining
        except ET.ParseError:
            _LOGGER.debug("Failed to parse alert XML: %.200s", xml_text)
            return None

    @staticmethod
    def _parse_alert_xml(xml_text: str) -> dict[str, str]:
        """Parse an EventNotificationAlert XML fragment into a dict."""
        root = ET.fromstring(xml_text)
        result: dict[str, str] = {}

        for tag in (
            "eventType",
            "eventState",
            "eventDescription",
            "channelID",
            "activePostCount",
        ):
            for prefix in (
                "{http://www.hikvision.com/ver20/XMLSchema}",
                "{http://www.std-cgi.com/ver10/XMLSchema}",
                "{*}",
                "",
            ):
                elem = root.find(f"{prefix}{tag}")
                if elem is not None and elem.text:
                    result[tag] = elem.text.strip()
                    break

        # Check for nested VideoInterEvent / VideoIntercom elements
        for nested_tag in ("VideoInterEvent", "VideoIntercom"):
            for prefix in (
                "{http://www.hikvision.com/ver20/XMLSchema}",
                "{http://www.std-cgi.com/ver10/XMLSchema}",
                "{*}",
                "",
            ):
                nested = root.find(f"{prefix}{nested_tag}")
                if nested is not None:
                    for child in nested:
                        local = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        if child.text:
                            result[f"{nested_tag}.{local}"] = child.text.strip()
                    break

        return result

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
