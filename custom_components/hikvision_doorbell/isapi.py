"""ISAPI client for Hikvision doorbell devices."""

import asyncio
import json
import logging
import socket
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from functools import partial
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Alert stream URL paths to try (primary first, fallback for older firmware)
_ALERT_STREAM_PATHS = (
    "/ISAPI/Event/notification/alertStream",
    "/Event/notification/alertStream",
)


class HikvisionISAPIError(Exception):
    """Error communicating with the Hikvision device."""


class HikvisionISAPIAuthError(HikvisionISAPIError):
    """Authentication failed."""


class HikvisionISAPIClient:
    """Client for the Hikvision ISAPI interface using HTTP Digest auth.

    Uses urllib which has built-in, reliable HTTPDigestAuthHandler support.
    All requests run in the executor to avoid blocking the event loop.
    """

    def __init__(self, host: str, username: str, password: str) -> None:
        self._base_url = f"http://{host}"
        self._username = username
        self._password = password
        self._alert_stream_task: asyncio.Task | None = None
        self._alert_stream_stop = False

    def _build_opener(self) -> urllib.request.OpenerDirector:
        """Build a urllib opener with Digest + Basic auth support."""
        password_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        password_mgr.add_password(
            None, self._base_url, self._username, self._password
        )
        digest_handler = urllib.request.HTTPDigestAuthHandler(password_mgr)
        basic_handler = urllib.request.HTTPBasicAuthHandler(password_mgr)
        return urllib.request.build_opener(digest_handler, basic_handler)

    def _sync_request(self, path: str, timeout: int = 10) -> tuple[bytes, dict]:
        """Make a synchronous HTTP request with auth. Returns (body, headers)."""
        url = f"{self._base_url}{path}"
        opener = self._build_opener()
        try:
            response = opener.open(url, timeout=timeout)
            body = response.read()
            headers = dict(response.headers)
            return body, headers
        except urllib.error.HTTPError as err:
            if err.code == 401:
                raise HikvisionISAPIAuthError("Invalid credentials") from err
            raise HikvisionISAPIError(
                f"HTTP {err.code} requesting {path}"
            ) from err
        except urllib.error.URLError as err:
            raise HikvisionISAPIError(
                f"Cannot connect to {self._base_url}: {err.reason}"
            ) from err
        except OSError as err:
            raise HikvisionISAPIError(
                f"Connection error: {err}"
            ) from err

    async def _async_request(self, path: str, timeout: int = 10) -> tuple[bytes, dict]:
        """Run a request in the executor to avoid blocking the event loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, partial(self._sync_request, path, timeout)
        )

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information from the ISAPI /System/deviceInfo endpoint."""
        body, _ = await self._async_request("/ISAPI/System/deviceInfo")
        text = body.decode("utf-8", errors="replace")

        root = ET.fromstring(text)

        def _find_text(tag: str) -> str | None:
            """Find text content of a tag, trying various namespace approaches."""
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

    async def get_call_status(self) -> str:
        """Get the current video intercom call status.

        Returns a status string such as 'idle', 'ringing', 'dismissed'.
        """
        try:
            body, _ = await self._async_request(
                "/ISAPI/VideoIntercom/callStatus?format=json"
            )
        except HikvisionISAPIError:
            return "idle"

        text = body.decode("utf-8", errors="replace")

        # Try JSON first, fall back to XML
        try:
            data = json.loads(text)
            status = data.get("CallStatus", {}).get("status")
            if status:
                return status
        except Exception:
            pass

        # Try XML parsing as fallback
        try:
            root = ET.fromstring(text)
            for prefix in (
                "{http://www.hikvision.com/ver20/XMLSchema}",
                "{*}",
                "",
            ):
                elem = root.find(f"{prefix}status")
                if elem is not None and elem.text:
                    return elem.text.strip()
        except ET.ParseError:
            pass

        return "idle"

    def _sync_listen_alert_stream(
        self, callback: Callable[[str], None]
    ) -> None:
        """Listen to the ISAPI alert stream (blocking).

        Uses line-by-line reading (like pyhik) to avoid blocking on
        partial buffer fills. Scans for <EventNotificationAlert> XML
        envelopes and passes complete events to the callback.
        """
        opener = self._build_opener()
        response = None

        # Try each alert stream path
        for path in _ALERT_STREAM_PATHS:
            url = f"{self._base_url}{path}"
            try:
                response = opener.open(url, timeout=60)
                _LOGGER.info(
                    "Alert stream connected: %s (status %s)",
                    path,
                    response.status,
                )
                break
            except urllib.error.HTTPError as err:
                _LOGGER.warning(
                    "Alert stream %s returned HTTP %s, trying next path",
                    path,
                    err.code,
                )
                continue
            except Exception as err:
                _LOGGER.warning(
                    "Alert stream %s failed: %s, trying next path",
                    path,
                    err,
                )
                continue

        if response is None:
            _LOGGER.error(
                "Could not open alert stream on any path. "
                "The doorbell may not support ISAPI event streaming."
            )
            return

        # Set a socket-level read timeout (60 seconds between lines)
        # so readline() doesn't block forever during idle periods.
        raw_sock = response.fp.raw
        if hasattr(raw_sock, "_sock"):
            raw_sock._sock.settimeout(60)
        elif isinstance(raw_sock, socket.socket):
            raw_sock.settimeout(60)

        # Line-by-line parsing (same approach as pyhik)
        parse_string = ""
        in_event = False

        while not self._alert_stream_stop:
            try:
                line_bytes = response.readline()
                if not line_bytes:
                    _LOGGER.warning("Alert stream: connection closed by device")
                    break

                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue

                # Log every non-empty line at debug level for diagnostics
                _LOGGER.debug("Alert stream line: %s", line[:300])

                # Detect start of an EventNotificationAlert XML envelope
                if "<EventNotificationAlert" in line:
                    in_event = True
                    parse_string = line

                elif "</EventNotificationAlert>" in line:
                    parse_string += " " + line
                    in_event = False
                    _LOGGER.info(
                        "Alert stream received complete event: %s",
                        parse_string[:500],
                    )
                    callback(parse_string)
                    parse_string = ""

                elif in_event:
                    parse_string += " " + line

            except socket.timeout:
                # No data for 60 seconds, this is normal for idle doorbells
                _LOGGER.debug("Alert stream: no data for 60s (keepalive)")
                continue
            except OSError as err:
                if self._alert_stream_stop:
                    break
                _LOGGER.warning("Alert stream read error: %s", err)
                break

    async def start_alert_stream(
        self, callback: Callable[[str], None]
    ) -> None:
        """Start listening to the ISAPI alert stream in a background task."""
        self._alert_stream_stop = False

        async def _run_stream() -> None:
            retry_delay = 5
            while not self._alert_stream_stop:
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(
                        None,
                        partial(self._sync_listen_alert_stream, callback),
                    )
                except Exception:
                    _LOGGER.warning(
                        "Alert stream error, reconnecting in %ds",
                        retry_delay,
                        exc_info=True,
                    )
                if not self._alert_stream_stop:
                    _LOGGER.info(
                        "Alert stream disconnected, reconnecting in %ds",
                        retry_delay,
                    )
                    await asyncio.sleep(retry_delay)

        self._alert_stream_task = asyncio.create_task(_run_stream())

    async def get_snapshot(self) -> bytes | None:
        """Capture a JPEG snapshot from the doorbell camera.

        Tries channel 101 (main stream) first, then falls back to channel 1.
        """
        for channel in ("101", "1"):
            try:
                body, headers = await self._async_request(
                    f"/ISAPI/Streaming/channels/{channel}/picture"
                )
                content_type = headers.get("Content-Type", "")
                if content_type.startswith("image/"):
                    return body
            except HikvisionISAPIError:
                _LOGGER.debug(
                    "Snapshot channel %s unavailable, trying next", channel
                )
                continue
        _LOGGER.warning("Failed to capture snapshot from any channel")
        return None

    async def close(self) -> None:
        """Stop the alert stream."""
        self._alert_stream_stop = True
        if self._alert_stream_task and not self._alert_stream_task.done():
            self._alert_stream_task.cancel()
            self._alert_stream_task = None
