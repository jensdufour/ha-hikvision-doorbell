"""ISAPI client for Hikvision doorbell devices."""

import asyncio
import json
import logging
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Callable
from functools import partial
from typing import Any

_LOGGER = logging.getLogger(__name__)


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
        """Listen to the ISAPI alert stream (blocking). Calls callback with event XML."""
        url = f"{self._base_url}/ISAPI/Event/notification/alertStream"
        opener = self._build_opener()
        try:
            response = opener.open(url, timeout=300)
        except Exception as err:
            _LOGGER.warning("Failed to open alert stream: %s", err)
            return

        buffer = b""
        boundary = None

        while not self._alert_stream_stop:
            try:
                chunk = response.read(4096)
                if not chunk:
                    break
                buffer += chunk

                # Detect the multipart boundary from the first chunk
                if boundary is None:
                    content_type = response.headers.get("Content-Type", "")
                    if "boundary=" in content_type:
                        boundary = (
                            "--"
                            + content_type.split("boundary=")[1].split(";")[0].strip()
                        ).encode()
                    else:
                        # Try to detect from buffer
                        for line in buffer.split(b"\r\n"):
                            if line.startswith(b"--"):
                                boundary = line.strip()
                                break
                    if boundary is None:
                        # Not multipart, treat entire buffer as event data
                        text = buffer.decode("utf-8", errors="replace")
                        if "<eventType>" in text:
                            callback(text)
                            buffer = b""
                        continue

                # Split on boundary and process complete parts
                parts = buffer.split(boundary)
                # Keep the last part (may be incomplete)
                buffer = parts[-1]

                for part in parts[:-1]:
                    text = part.decode("utf-8", errors="replace")
                    if "<eventType>" in text or '"eventType"' in text:
                        callback(text)
            except OSError:
                if self._alert_stream_stop:
                    break
                _LOGGER.debug("Alert stream read error, reconnecting")
                break

    async def start_alert_stream(
        self, callback: Callable[[str], None]
    ) -> None:
        """Start listening to the ISAPI alert stream in a background task."""
        self._alert_stream_stop = False

        async def _run_stream() -> None:
            while not self._alert_stream_stop:
                loop = asyncio.get_running_loop()
                try:
                    await loop.run_in_executor(
                        None,
                        partial(self._sync_listen_alert_stream, callback),
                    )
                except Exception:
                    _LOGGER.warning(
                        "Alert stream error, reconnecting in 5s", exc_info=True
                    )
                if not self._alert_stream_stop:
                    await asyncio.sleep(5)

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
