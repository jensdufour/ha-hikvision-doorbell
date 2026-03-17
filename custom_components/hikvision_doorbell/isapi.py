"""ISAPI client for Hikvision doorbell devices."""

import asyncio
import json
import logging
import urllib.request
import xml.etree.ElementTree as ET
from functools import partial
from typing import Any

_LOGGER = logging.getLogger(__name__)

# ISAPI endpoints to probe for call/ring detection.
# Each tuple is (path, description).
_INTERCOM_ENDPOINTS = (
    ("/ISAPI/VideoIntercom/callStatus", "callStatus"),
    ("/ISAPI/VideoIntercom/callStatus?format=json", "callStatus (JSON)"),
    ("/ISAPI/VideoIntercom/callerInfo", "callerInfo"),
    ("/ISAPI/VideoIntercom/callSignal", "callSignal"),
    ("/ISAPI/VideoIntercom/operationStatus", "operationStatus"),
    ("/ISAPI/VideoIntercom/capabilities", "intercom capabilities"),
    ("/ISAPI/Event/triggers/notifications", "event triggers"),
    ("/ISAPI/Event/channels", "event channels"),
    ("/ISAPI/System/IO/inputs", "IO inputs"),
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

    async def get_call_status_raw(self) -> tuple[str, str]:
        """Get the raw call status response for diagnostics.

        Returns (status_string, raw_response_text).
        """
        try:
            body, _ = await self._async_request(
                "/ISAPI/VideoIntercom/callStatus?format=json"
            )
        except HikvisionISAPIError as err:
            return "idle", f"error: {err}"

        text = body.decode("utf-8", errors="replace")

        # Try JSON first, fall back to XML
        try:
            data = json.loads(text)
            status = data.get("CallStatus", {}).get("status")
            if status:
                return status, text
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
                    return elem.text.strip(), text
        except ET.ParseError:
            pass

        return "idle", text

    async def get_call_status(self) -> str:
        """Get the current video intercom call status."""
        status, _ = await self.get_call_status_raw()
        return status

    async def probe_endpoints(self) -> dict[str, str]:
        """Probe all known ISAPI intercom endpoints and log their responses.

        Returns a dict of {endpoint_name: response_text_or_error}.
        Used for diagnostics to discover what the device supports.
        """
        results: dict[str, str] = {}
        for path, name in _INTERCOM_ENDPOINTS:
            try:
                body, headers = await self._async_request(path, timeout=5)
                text = body.decode("utf-8", errors="replace")
                results[name] = text[:500]
                _LOGGER.warning(
                    "PROBE %s [%s]: %s", name, path, text[:300]
                )
            except HikvisionISAPIError as err:
                results[name] = f"error: {err}"
                _LOGGER.warning("PROBE %s [%s]: %s", name, path, err)
        return results

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
        """Clean up resources."""
