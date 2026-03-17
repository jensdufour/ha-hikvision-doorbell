"""ISAPI client for Hikvision doorbell devices."""

import logging
import xml.etree.ElementTree as ET
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)


class HikvisionISAPIError(Exception):
    """Error communicating with the Hikvision device."""


class HikvisionISAPIAuthError(HikvisionISAPIError):
    """Authentication failed."""


class HikvisionISAPIClient:
    """Client for the Hikvision ISAPI interface using HTTP Digest auth."""

    def __init__(self, host: str, username: str, password: str) -> None:
        self._base_url = f"http://{host}"
        self._username = username
        self._password = password
        self._session: aiohttp.ClientSession | None = None

    def _get_auth(self) -> aiohttp.DigestAuth:
        """Return a DigestAuth instance."""
        return aiohttp.DigestAuth(self._username, self._password)

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return a reusable aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information from the ISAPI /System/deviceInfo endpoint."""
        session = await self._get_session()
        url = f"{self._base_url}/ISAPI/System/deviceInfo"
        try:
            async with session.get(url, auth=self._get_auth()) as response:
                if response.status == 401:
                    raise HikvisionISAPIAuthError("Invalid credentials")
                response.raise_for_status()
                text = await response.text()
        except HikvisionISAPIAuthError:
            raise
        except aiohttp.ClientError as err:
            raise HikvisionISAPIError(
                f"Failed to get device info: {err}"
            ) from err

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
        session = await self._get_session()
        url = f"{self._base_url}/ISAPI/VideoIntercom/callStatus"
        try:
            async with session.get(
                url, auth=self._get_auth(), params={"format": "json"}
            ) as response:
                response.raise_for_status()
                text = await response.text()
        except aiohttp.ClientError as err:
            raise HikvisionISAPIError(
                f"Failed to get call status: {err}"
            ) from err

        # Try JSON first, fall back to XML
        try:
            import json
            data = json.loads(text)
            status = data.get("CallStatus", {}).get("status")
            if status:
                return status
        except Exception:
            _LOGGER.debug("Call status response is not JSON, trying XML")

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
            _LOGGER.debug("Call status response is not valid XML either")

        return "idle"

    async def get_snapshot(self) -> bytes | None:
        """Capture a JPEG snapshot from the doorbell camera.

        Tries channel 101 (main stream) first, then falls back to channel 1.
        """
        session = await self._get_session()
        for channel in ("101", "1"):
            url = f"{self._base_url}/ISAPI/Streaming/channels/{channel}/picture"
            try:
                async with session.get(url, auth=self._get_auth()) as response:
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "")
                    if content_type.startswith("image/"):
                        return await response.read()
            except aiohttp.ClientError:
                _LOGGER.debug(
                    "Snapshot channel %s unavailable, trying next", channel
                )
                continue
        _LOGGER.warning("Failed to capture snapshot from any channel")
        return None

    async def close(self) -> None:
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
