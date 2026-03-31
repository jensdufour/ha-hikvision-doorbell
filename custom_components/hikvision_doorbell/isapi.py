"""ISAPI client for Hikvision doorbell devices."""

import json
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

    def _create_client(self, auth: httpx.Auth) -> httpx.AsyncClient:
        """Create an httpx client with the given auth method."""
        return httpx.AsyncClient(
            auth=auth,
            timeout=httpx.Timeout(10.0),
            verify=False,
        )

    async def async_init(self) -> None:
        """Probe the device to determine the correct auth method.

        Tries Digest first, then Basic. Call this once during setup.
        """
        for auth_type, auth in [
            ("Digest", httpx.DigestAuth(self._username, self._password)),
            ("Basic", httpx.BasicAuth(self._username, self._password)),
        ]:
            client = self._create_client(auth)
            try:
                response = await client.get(
                    f"{self._base_url}/ISAPI/System/deviceInfo"
                )
                if response.status_code != 401:
                    self._client = client
                    _LOGGER.debug("Auth method resolved: %s", auth_type)
                    return
            except httpx.HTTPError:
                pass
            await client.aclose()

        # Neither worked, default to Digest (will fail with proper error later)
        self._client = self._create_client(
            httpx.DigestAuth(self._username, self._password)
        )

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

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information from the ISAPI /System/deviceInfo endpoint."""
        body, _ = await self._request("/ISAPI/System/deviceInfo")
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

    async def get_call_status(self) -> tuple[str, str]:
        """Get the current video intercom call status.

        Tries multiple known ISAPI paths for call status.
        Returns (status, raw_response_text).
        """
        paths = [
            "/ISAPI/VideoIntercom/callStatus?format=json",
            "/ISAPI/VideoIntercom/callStatus",
        ]
        last_error: Exception | None = None
        for path in paths:
            try:
                body, _ = await self._request(path)
            except HikvisionISAPIAuthError:
                # 401 on this endpoint means it doesn't exist or requires
                # different permissions, not that credentials are wrong
                # (credentials were validated during async_init).
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

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
