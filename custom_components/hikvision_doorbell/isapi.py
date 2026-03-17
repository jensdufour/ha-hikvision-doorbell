"""ISAPI client for Hikvision doorbell devices."""

import hashlib
import json
import logging
import time
import xml.etree.ElementTree as ET
from typing import Any

import aiohttp

_LOGGER = logging.getLogger(__name__)

# Counter for digest auth nonce count
_NC_COUNTER = 0


def _build_digest_header(
    method: str,
    url: str,
    username: str,
    password: str,
    www_authenticate: str,
) -> str:
    """Build an HTTP Digest Authorization header from a WWW-Authenticate challenge."""
    global _NC_COUNTER

    # Parse the WWW-Authenticate header
    parts = {}
    for part in www_authenticate.replace("Digest ", "").split(","):
        part = part.strip()
        if "=" in part:
            key, value = part.split("=", 1)
            parts[key.strip()] = value.strip().strip('"')

    realm = parts.get("realm", "")
    nonce = parts.get("nonce", "")
    qop = parts.get("qop", "")
    opaque = parts.get("opaque", "")

    _NC_COUNTER += 1
    nc = f"{_NC_COUNTER:08x}"
    cnonce = hashlib.md5(str(time.time()).encode()).hexdigest()[:16]

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{url}".encode()).hexdigest()

    if "auth" in qop:
        response = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
        return (
            f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{url}", response="{response}", qop={qop}, nc={nc}, '
            f'cnonce="{cnonce}"'
            + (f', opaque="{opaque}"' if opaque else "")
        )

    response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
    return (
        f'Digest username="{username}", realm="{realm}", nonce="{nonce}", '
        f'uri="{url}", response="{response}"'
        + (f', opaque="{opaque}"' if opaque else "")
    )


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

    async def _get_session(self) -> aiohttp.ClientSession:
        """Return a reusable aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=10)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _request(
        self, method: str, path: str, **kwargs: Any
    ) -> aiohttp.ClientResponse:
        """Make an HTTP request with Digest auth handling."""
        session = await self._get_session()
        url = f"{self._base_url}{path}"

        # First request (will typically get 401 with WWW-Authenticate)
        async with session.request(method, url, **kwargs) as resp:
            if resp.status != 401:
                resp.raise_for_status()
                # Read and store body before context manager closes
                body = await resp.read()
                text = body.decode("utf-8", errors="replace")
                return _FakeResponse(
                    status=resp.status,
                    headers=resp.headers,
                    body=body,
                    text_content=text,
                )

            www_auth = resp.headers.get("WWW-Authenticate", "")
            if not www_auth.startswith("Digest"):
                raise HikvisionISAPIAuthError("Expected Digest auth challenge")

        # Parse path for digest (use path + query)
        digest_uri = path
        if "params" in kwargs and kwargs["params"]:
            from urllib.parse import urlencode
            digest_uri = f"{path}?{urlencode(kwargs['params'])}"

        auth_header = _build_digest_header(
            method=method.upper(),
            url=digest_uri,
            username=self._username,
            password=self._password,
            www_authenticate=www_auth,
        )

        headers = kwargs.pop("headers", {})
        headers["Authorization"] = auth_header

        async with session.request(method, url, headers=headers, **kwargs) as resp:
            if resp.status == 401:
                raise HikvisionISAPIAuthError("Invalid credentials")
            resp.raise_for_status()
            body = await resp.read()
            text = body.decode("utf-8", errors="replace")
            return _FakeResponse(
                status=resp.status,
                headers=resp.headers,
                body=body,
                text_content=text,
            )

    async def get_device_info(self) -> dict[str, Any]:
        """Get device information from the ISAPI /System/deviceInfo endpoint."""
        try:
            response = await self._request("GET", "/ISAPI/System/deviceInfo")
        except HikvisionISAPIAuthError:
            raise
        except aiohttp.ClientError as err:
            raise HikvisionISAPIError(
                f"Failed to get device info: {err}"
            ) from err

        root = ET.fromstring(response.text_content)

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
            response = await self._request(
                "GET",
                "/ISAPI/VideoIntercom/callStatus",
                params={"format": "json"},
            )
        except aiohttp.ClientError as err:
            raise HikvisionISAPIError(
                f"Failed to get call status: {err}"
            ) from err

        text = response.text_content

        # Try JSON first, fall back to XML
        try:
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
        for channel in ("101", "1"):
            try:
                response = await self._request(
                    "GET",
                    f"/ISAPI/Streaming/channels/{channel}/picture",
                )
                content_type = response.headers.get("content-type", "")
                if content_type.startswith("image/"):
                    return response.body
            except (aiohttp.ClientError, HikvisionISAPIError):
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


class _FakeResponse:
    """Lightweight response wrapper to carry data outside context manager."""

    def __init__(
        self,
        status: int,
        headers: Any,
        body: bytes,
        text_content: str,
    ) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.text_content = text_content
