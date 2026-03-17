"""ISAPI client for Hikvision doorbell devices."""

import logging
import xml.etree.ElementTree as ET
from typing import Any

import httpx

_LOGGER = logging.getLogger(__name__)


class HikvisionISAPIError(Exception):
    """Error communicating with the Hikvision device."""


class HikvisionISAPIAuthError(HikvisionISAPIError):
    """Authentication failed."""


class HikvisionISAPIClient:
    """Client for the Hikvision ISAPI interface using HTTP Digest auth."""

    def __init__(self, host: str, username: str, password: str) -> None:
        self._base_url = f"http://{host}"
        self._auth = httpx.DigestAuth(username, password)
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Return a reusable async HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                auth=self._auth,
                timeout=httpx.Timeout(10.0),
            )
        return self._client

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information from the ISAPI /System/deviceInfo endpoint."""
        client = await self._get_client()
        try:
            response = await client.get(f"{self._base_url}/ISAPI/System/deviceInfo")
            if response.status_code == 401:
                raise HikvisionISAPIAuthError("Invalid credentials")
            response.raise_for_status()
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 401:
                raise HikvisionISAPIAuthError("Invalid credentials") from err
            raise HikvisionISAPIError(
                f"Failed to get device info: {err}"
            ) from err
        except httpx.HTTPError as err:
            raise HikvisionISAPIError(
                f"Failed to get device info: {err}"
            ) from err

        root = ET.fromstring(response.text)

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
        client = await self._get_client()
        try:
            response = await client.get(
                f"{self._base_url}/ISAPI/VideoIntercom/callStatus",
                params={"format": "json"},
            )
            response.raise_for_status()
            data = response.json()
            return data.get("CallStatus", {}).get("status", "idle")
        except httpx.HTTPError as err:
            raise HikvisionISAPIError(
                f"Failed to get call status: {err}"
            ) from err

    async def get_snapshot(self) -> bytes | None:
        """Capture a JPEG snapshot from the doorbell camera.

        Tries channel 101 (main stream) first, then falls back to channel 1.
        """
        client = await self._get_client()
        for channel in ("101", "1"):
            try:
                response = await client.get(
                    f"{self._base_url}/ISAPI/Streaming/channels/{channel}/picture",
                )
                response.raise_for_status()
                content_type = response.headers.get("content-type", "")
                if content_type.startswith("image/"):
                    return response.content
            except httpx.HTTPError:
                _LOGGER.debug(
                    "Snapshot channel %s unavailable, trying next", channel
                )
                continue
        _LOGGER.warning("Failed to capture snapshot from any channel")
        return None

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
