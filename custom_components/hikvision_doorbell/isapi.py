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
    ("/ISAPI/VideoIntercom/callStatus?format=json", "callStatus (JSON)"),
    ("/ISAPI/VideoIntercom/callerInfo?format=json", "callerInfo (JSON)"),
    ("/ISAPI/VideoIntercom/capabilities", "intercom capabilities"),
    ("/ISAPI/Event/notification/httpHosts", "HTTP host notifications"),
    # Event subscription/trigger endpoints
    ("/ISAPI/Event/triggers", "event triggers root"),
    ("/ISAPI/Event/triggers/notifications", "event trigger notifications"),
    ("/ISAPI/Event/notification/httpHosts/1/notifications", "host 1 subscriptions"),
    ("/ISAPI/Event/notification/methods", "notification methods"),
    ("/ISAPI/Event/schedules", "event schedules"),
    ("/ISAPI/Event/notification/subscriptions", "event subscriptions"),
    # Video intercom event endpoints
    ("/ISAPI/VideoIntercom/phonestatus", "phone status"),
    ("/ISAPI/VideoIntercom/callSignal?format=json", "callSignal (JSON)"),
    ("/ISAPI/VideoIntercom/callRecord?format=json", "call records"),
    # Alarm/security endpoints
    ("/ISAPI/SecurityCP/AlarmControlByCSV?format=json", "alarm control"),
    ("/ISAPI/Security/AdminAccesses", "admin accesses"),
    # Smart event
    ("/ISAPI/Smart/capabilities", "smart capabilities"),
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

    def _sync_request_with_body(
        self,
        path: str,
        method: str = "PUT",
        body: str = "",
        content_type: str = "application/xml",
        timeout: int = 10,
    ) -> tuple[bytes, dict]:
        """Make a synchronous HTTP request with a body and auth."""
        url = f"{self._base_url}{path}"
        data = body.encode("utf-8") if body else None
        opener = self._build_opener()
        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Content-Type": content_type},
        )
        try:
            response = opener.open(req, timeout=timeout)
            resp_body = response.read()
            headers = dict(response.headers)
            return resp_body, headers
        except urllib.error.HTTPError as err:
            # Read the error response body for diagnostics
            err_body = ""
            try:
                err_body = err.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            if err.code == 401:
                raise HikvisionISAPIAuthError("Invalid credentials") from err
            raise HikvisionISAPIError(
                f"HTTP {err.code} {method} {path}: {err_body[:500]}"
            ) from err
        except urllib.error.URLError as err:
            raise HikvisionISAPIError(
                f"Cannot connect to {self._base_url}: {err.reason}"
            ) from err
        except OSError as err:
            raise HikvisionISAPIError(
                f"Connection error: {err}"
            ) from err

    async def _async_request_with_body(
        self,
        path: str,
        method: str = "PUT",
        body: str = "",
        content_type: str = "application/xml",
        timeout: int = 10,
    ) -> tuple[bytes, dict]:
        """Run a request with body in the executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            partial(
                self._sync_request_with_body,
                path,
                method,
                body,
                content_type,
                timeout,
            ),
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

    async def get_caller_info_raw(self) -> tuple[str, str]:
        """Get the callerInfo status and raw response.

        Returns (status_string, raw_response_text).
        """
        try:
            body, _ = await self._async_request(
                "/ISAPI/VideoIntercom/callerInfo?format=json"
            )
        except HikvisionISAPIError as err:
            return "idle", f"error: {err}"

        text = body.decode("utf-8", errors="replace")

        try:
            data = json.loads(text)
            status = data.get("CallerInfo", {}).get("status")
            if status:
                return status, text
        except Exception:
            pass

        # Try XML
        try:
            root = ET.fromstring(text)
            for prefix in (
                "{http://www.isapi.org/ver20/XMLSchema}",
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

    async def get_io_input_status_raw(self, input_id: str = "1") -> tuple[str, str]:
        """Get the IO input status and raw response.

        Returns (triggering_state, raw_response_text).
        triggering_state is 'low' (inactive) or 'high' (active/triggered).
        """
        try:
            body, _ = await self._async_request(
                f"/ISAPI/System/IO/inputs/{input_id}/status"
            )
        except HikvisionISAPIError as err:
            return "low", f"error: {err}"

        text = body.decode("utf-8", errors="replace")

        # Try XML - IOInputPort has <ioState> element
        try:
            root = ET.fromstring(text)
            for prefix in (
                "{http://www.isapi.org/ver20/XMLSchema}",
                "{http://www.hikvision.com/ver20/XMLSchema}",
                "{*}",
                "",
            ):
                for tag in ("ioState", "IOPortStatus", "triggering"):
                    elem = root.find(f"{prefix}{tag}")
                    if elem is not None and elem.text:
                        return elem.text.strip(), text
        except ET.ParseError:
            pass

        return "low", text

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
                results[name] = text[:1000]
                _LOGGER.warning(
                    "PROBE %s [%s]: %s", name, path, text[:800]
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
                # Some firmware returns JPEG without proper Content-Type
                if body[:3] == b"\xff\xd8\xff":
                    return body
            except HikvisionISAPIError:
                _LOGGER.debug(
                    "Snapshot channel %s unavailable, trying next", channel
                )
                continue
        _LOGGER.warning("Failed to capture snapshot from any channel")
        return None

    async def get_http_hosts(self) -> str:
        """Get the current HTTP host notification configuration."""
        try:
            body, _ = await self._async_request(
                "/ISAPI/Event/notification/httpHosts"
            )
            return body.decode("utf-8", errors="replace")
        except HikvisionISAPIError as err:
            return f"error: {err}"

    async def configure_http_host(
        self, host_id: str, ip: str, port: int, url_path: str
    ) -> str:
        """Configure an HTTP host for event push notifications.

        Strategy: GET the current config, modify only the fields we need,
        and PUT it back. This avoids XML format mismatches.
        """
        import re

        # Step 1: GET the current full list configuration
        try:
            body, _ = await self._async_request(
                "/ISAPI/Event/notification/httpHosts"
            )
            current_xml = body.decode("utf-8", errors="replace")
        except HikvisionISAPIError as err:
            return f"error getting config: {err}"

        _LOGGER.warning("Current HTTP host XML to modify:\n%s", current_xml)

        # Step 2: Modify the fields in the full XML directly
        # Use negative lookahead (?!List) to avoid matching the wrapper tag
        modified_xml = current_xml

        # Replace url (empty or existing)
        modified_xml = re.sub(
            r"<url>[^<]*</url>",
            f"<url>{url_path}</url>",
            modified_xml,
        )
        modified_xml = re.sub(
            r"<ipAddress>[^<]*</ipAddress>",
            f"<ipAddress>{ip}</ipAddress>",
            modified_xml,
        )
        modified_xml = re.sub(
            r"<portNo>[^<]*</portNo>",
            f"<portNo>{port}</portNo>",
            modified_xml,
        )

        _LOGGER.warning("Sending modified HTTP host config XML:\n%s", modified_xml)

        # Step 3: Try PUT to the list endpoint first, then individual
        for path in (
            "/ISAPI/Event/notification/httpHosts",
            f"/ISAPI/Event/notification/httpHosts/{host_id}",
        ):
            for method in ("PUT",):
                try:
                    resp_body, _ = await self._async_request_with_body(
                        path, method=method, body=modified_xml,
                    )
                    resp = resp_body.decode("utf-8", errors="replace")
                    _LOGGER.warning(
                        "HTTP host %s %s response: %s", method, path, resp
                    )
                    return resp
                except HikvisionISAPIError as err:
                    _LOGGER.warning(
                        "HTTP host %s %s failed: %s", method, path, err
                    )

        # Step 4: Also try extracting just the inner element for individual PUT
        match = re.search(
            r"(<HttpHostNotification(?!List)[^>]*>.*?</HttpHostNotification>)",
            current_xml,
            re.DOTALL,
        )
        if match:
            inner_xml = match.group(1)
            inner_xml = re.sub(
                r"<url>[^<]*</url>",
                f"<url>{url_path}</url>",
                inner_xml,
            )
            inner_xml = re.sub(
                r"<ipAddress>[^<]*</ipAddress>",
                f"<ipAddress>{ip}</ipAddress>",
                inner_xml,
            )
            inner_xml = re.sub(
                r"<portNo>[^<]*</portNo>",
                f"<portNo>{port}</portNo>",
                inner_xml,
            )
            single_body = f'<?xml version="1.0" encoding="UTF-8"?>\n{inner_xml}'
            _LOGGER.warning(
                "Trying individual element PUT:\n%s", single_body
            )
            try:
                resp_body, _ = await self._async_request_with_body(
                    f"/ISAPI/Event/notification/httpHosts/{host_id}",
                    method="PUT",
                    body=single_body,
                )
                resp = resp_body.decode("utf-8", errors="replace")
                _LOGGER.warning("Individual PUT response: %s", resp)
                return resp
            except HikvisionISAPIError as err:
                _LOGGER.warning("Individual PUT failed: %s", err)
                raise

        raise HikvisionISAPIError("All HTTP host configuration attempts failed")

    async def delete_http_host(self, host_id: str) -> None:
        """Remove an HTTP host notification configuration."""
        try:
            await self._async_request_with_body(
                f"/ISAPI/Event/notification/httpHosts/{host_id}",
                method="DELETE",
            )
        except HikvisionISAPIError:
            _LOGGER.debug("Could not delete HTTP host %s", host_id, exc_info=True)

    async def close(self) -> None:
        """Clean up resources."""
