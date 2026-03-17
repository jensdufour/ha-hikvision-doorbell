"""ISAPI client for Hikvision doorbell devices."""

import asyncio
import http.client
import json
import logging
import re as _re
import threading
import urllib.request
import xml.etree.ElementTree as ET
from functools import partial
from typing import Any, Callable

_LOGGER = logging.getLogger(__name__)

# ISAPI endpoints to probe for call/ring detection.
# Each tuple is (path, description).
_INTERCOM_ENDPOINTS = (
    ("/ISAPI/VideoIntercom/callStatus?format=json", "callStatus (JSON)"),
    ("/ISAPI/VideoIntercom/callerInfo?format=json", "callerInfo (JSON)"),
    ("/ISAPI/VideoIntercom/capabilities", "intercom capabilities"),
    ("/ISAPI/Event/notification/httpHosts", "HTTP host notifications"),
    ("/ISAPI/Event/triggers", "event triggers root"),
    ("/ISAPI/Event/notification/httpHosts/1/notifications", "host 1 subscriptions"),
    ("/ISAPI/System/IO/inputs", "IO inputs"),
    # Alarm upload config (device claims isSupportAlarmUploadCfg=true)
    ("/ISAPI/VideoIntercom/alarmUploadCfg", "alarm upload config"),
    ("/ISAPI/VideoIntercom/workStatus", "work status"),
    ("/ISAPI/VideoIntercom/operationTime", "operation time"),
    ("/ISAPI/VideoIntercom/keyCfg", "key config"),
    ("/ISAPI/VideoIntercom/systemSwitchCfg", "system switch config"),
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
                # Log each line separately to avoid HA log truncation
                for i, line in enumerate(text[:800].splitlines()):
                    _LOGGER.warning(
                        "PROBE %s [%s] line %d: %s", name, path, i, line
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

    # ------------------------------------------------------------------
    # Event trigger subscription
    # ------------------------------------------------------------------

    async def get_event_triggers_raw(self) -> str:
        """Return the full XML of /ISAPI/Event/triggers."""
        try:
            body, _ = await self._async_request("/ISAPI/Event/triggers")
            return body.decode("utf-8", errors="replace")
        except HikvisionISAPIError as err:
            return f"error: {err}"

    async def get_host_notifications_raw(self, host_id: str = "1") -> str:
        """Return the full XML from /ISAPI/Event/notification/httpHosts/<id>/notifications."""
        path = f"/ISAPI/Event/notification/httpHosts/{host_id}/notifications"
        try:
            body, _ = await self._async_request(path)
            return body.decode("utf-8", errors="replace")
        except HikvisionISAPIError as err:
            return f"error: {err}"

    def _log_xml_lines(self, label: str, xml_text: str) -> None:
        """Log each line of XML individually to avoid HA log truncation."""
        for i, line in enumerate(xml_text.splitlines()):
            _LOGGER.warning("%s [line %d]: %s", label, i, line)

    async def enable_center_notifications(self) -> str:
        """Enable 'center' (HTTP host) notification on every event trigger."""
        # Step 1 -- fetch triggers
        triggers_xml = await self.get_event_triggers_raw()

        if triggers_xml.startswith("error:"):
            _LOGGER.warning("EVENT TRIGGERS fetch error: %s", triggers_xml)
            return triggers_xml

        # Log every line separately so HA log viewer doesn't truncate
        self._log_xml_lines("EVENT_TRIGGERS", triggers_xml)

        # Step 2 -- parse and inspect
        try:
            root = ET.fromstring(triggers_xml)
        except ET.ParseError as exc:
            _LOGGER.warning("EVENT TRIGGERS XML parse error: %s", exc)
            return f"XML parse error: {exc}"

        m = _re.match(r"\{(.+?)\}", root.tag)
        ns = m.group(1) if m else ""
        if ns:
            ET.register_namespace("", ns)

        def _tag(name: str) -> str:
            return f"{{{ns}}}{name}" if ns else name

        # Log summary of each trigger
        trigger_count = 0
        modified = False
        for trigger in root.iter(_tag("EventTrigger")):
            trigger_count += 1
            tid_el = trigger.find(_tag("id"))
            etype_el = trigger.find(_tag("eventType"))
            tid = tid_el.text if tid_el is not None else "?"
            etype = etype_el.text if etype_el is not None else "?"

            # Collect current notification methods
            notif_list = trigger.find(_tag("EventTriggerNotificationList"))
            methods: list[str] = []
            max_id = 0
            has_center = False
            if notif_list is not None:
                for notif in notif_list.findall(_tag("EventTriggerNotification")):
                    nid = notif.find(_tag("id"))
                    if nid is not None and nid.text:
                        try:
                            max_id = max(max_id, int(nid.text))
                        except ValueError:
                            pass
                    method_el = notif.find(_tag("notificationMethod"))
                    if method_el is not None and method_el.text:
                        methods.append(method_el.text)
                        if method_el.text == "center":
                            has_center = True
            else:
                notif_list = ET.SubElement(
                    trigger, _tag("EventTriggerNotificationList")
                )

            _LOGGER.warning(
                "TRIGGER id=%s eventType=%s methods=%s hasCenter=%s",
                tid, etype, methods, has_center,
            )

            if not has_center:
                new_notif = ET.SubElement(
                    notif_list, _tag("EventTriggerNotification")
                )
                id_el = ET.SubElement(new_notif, _tag("id"))
                id_el.text = str(max_id + 1)
                method_el = ET.SubElement(
                    new_notif, _tag("notificationMethod")
                )
                method_el.text = "center"
                recur_el = ET.SubElement(
                    new_notif, _tag("notificationRecurrence")
                )
                recur_el.text = "beginning"
                modified = True
                _LOGGER.warning(
                    "INJECTED center notification for trigger id=%s type=%s",
                    tid, etype,
                )

        _LOGGER.warning(
            "TRIGGERS SUMMARY: %d triggers found, modified=%s",
            trigger_count, modified,
        )

        # Step 3 -- PUT back
        new_xml = ET.tostring(root, encoding="unicode", xml_declaration=True)
        self._log_xml_lines("TRIGGERS_PUT_BODY", new_xml)

        try:
            resp_body, _ = await self._async_request_with_body(
                "/ISAPI/Event/triggers", method="PUT", body=new_xml
            )
            resp = resp_body.decode("utf-8", errors="replace")
            _LOGGER.warning("Event triggers PUT response: %s", resp)
            return resp
        except HikvisionISAPIError as err:
            _LOGGER.warning("Event triggers PUT failed: %s", err)
            return await self._enable_center_individual_triggers(root, ns)

    async def _enable_center_individual_triggers(
        self, root: ET.Element, ns: str
    ) -> str:
        """Fallback: PUT each trigger individually."""

        def _tag(name: str) -> str:
            return f"{{{ns}}}{name}" if ns else name

        results: list[str] = []
        for trigger in root.iter(_tag("EventTrigger")):
            tid_el = trigger.find(_tag("id"))
            tid = tid_el.text if tid_el is not None else None
            if not tid:
                continue
            trigger_xml = ET.tostring(
                trigger, encoding="unicode", xml_declaration=True
            )
            path = f"/ISAPI/Event/triggers/{tid}"
            try:
                resp_body, _ = await self._async_request_with_body(
                    path, method="PUT", body=trigger_xml
                )
                resp = resp_body.decode("utf-8", errors="replace")
                results.append(f"trigger {tid}: OK")
                _LOGGER.warning(
                    "Individual trigger PUT %s response: %s", path, resp
                )
            except HikvisionISAPIError as err:
                results.append(f"trigger {tid}: {err}")
                _LOGGER.warning("Individual trigger PUT %s failed: %s", path, err)
        return "; ".join(results) if results else "no triggers found"

    async def enable_host_notification_subscriptions(
        self, host_id: str = "1"
    ) -> str:
        """Try to enable all event subscriptions on the HTTP host."""
        path = f"/ISAPI/Event/notification/httpHosts/{host_id}/notifications"
        raw = await self.get_host_notifications_raw(host_id)

        if raw.startswith("error:"):
            _LOGGER.warning("HOST %s NOTIFICATIONS error: %s", host_id, raw)
            return raw

        # Log every line to avoid HA truncation
        self._log_xml_lines(f"HOST_{host_id}_NOTIF", raw)

        # Try to parse - handle different possible root elements
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            _LOGGER.warning(
                "HOST %s NOTIFICATIONS parse error: %s -- raw repr: %r",
                host_id, exc, raw[:500],
            )
            return f"cannot parse host notifications XML: {exc}"

        m = _re.match(r"\{(.+?)\}", root.tag)
        ns = m.group(1) if m else ""
        if ns:
            ET.register_namespace("", ns)

        def _tag(name: str) -> str:
            return f"{{{ns}}}{name}" if ns else name

        _LOGGER.warning(
            "HOST %s NOTIFICATIONS root tag: %s", host_id, root.tag
        )

        # Log all child elements for diagnostics
        for child in root:
            _LOGGER.warning(
                "HOST %s NOTIF child: tag=%s text=%s attrib=%s",
                host_id, child.tag, (child.text or "").strip()[:100],
                child.attrib,
            )
            for sub in child:
                _LOGGER.warning(
                    "HOST %s NOTIF   sub: tag=%s text=%s",
                    host_id, sub.tag, (sub.text or "").strip()[:100],
                )

        # Try PUTting the XML back to confirm it's writable
        put_xml = ET.tostring(root, encoding="unicode", xml_declaration=True)
        try:
            resp_body, _ = await self._async_request_with_body(
                path, method="PUT", body=put_xml
            )
            resp = resp_body.decode("utf-8", errors="replace")
            _LOGGER.warning("Host %s notifications PUT response: %s", host_id, resp)
            return resp
        except HikvisionISAPIError as err:
            _LOGGER.warning("Host %s notifications PUT failed: %s", host_id, err)
            return f"PUT failed: {err}"

    async def close(self) -> None:
        """Clean up resources."""
        self.stop_alert_stream()

    # ------------------------------------------------------------------
    # alertStream - persistent streaming connection
    # ------------------------------------------------------------------

    _alert_stream_thread: threading.Thread | None = None
    _alert_stream_stop: threading.Event | None = None

    def start_alert_stream(
        self, callback: Callable[[str], None]
    ) -> None:
        """Start a background thread that listens to /ISAPI/Event/notification/alertStream.

        The callback receives each XML event chunk as a string and is called
        from a worker thread -- the caller must schedule coroutines onto the
        event loop if needed.
        """
        self.stop_alert_stream()  # ensure no duplicate

        stop_event = threading.Event()
        self._alert_stream_stop = stop_event

        def _reader() -> None:
            """Worker that maintains a persistent HTTP connection."""
            import base64
            path = "/ISAPI/Event/notification/alertStream"
            while not stop_event.is_set():
                conn: http.client.HTTPConnection | None = None
                try:
                    host = self._base_url.replace("http://", "").replace("https://", "")
                    conn = http.client.HTTPConnection(host, timeout=90)

                    # Build digest auth -- do an initial request to get the challenge
                    conn.request("GET", path)
                    resp = conn.getresponse()
                    _LOGGER.warning(
                        "alertStream initial response: %s %s headers=%s",
                        resp.status, resp.reason,
                        dict(resp.getheaders()),
                    )

                    if resp.status == 401:
                        # Need digest auth - use the opener approach
                        resp.read()  # drain
                        conn.close()
                        conn = None

                        # Use urllib opener for auth, but read in streaming mode
                        opener = self._build_opener()
                        url = f"{self._base_url}{path}"
                        stream_resp = opener.open(url, timeout=90)
                        content_type = stream_resp.headers.get("Content-Type", "")
                        transfer_enc = stream_resp.headers.get("Transfer-Encoding", "")
                        content_len = stream_resp.headers.get("Content-Length", "")
                        _LOGGER.warning(
                            "alertStream auth response: status=%s Content-Type=%s "
                            "Transfer-Encoding=%s Content-Length=%s",
                            stream_resp.status,
                            content_type,
                            transfer_enc,
                            content_len,
                        )

                        # Check if this is a real stream or a fixed response
                        if content_len and int(content_len) < 200:
                            # Small fixed response - not a real stream
                            body = stream_resp.read()
                            _LOGGER.warning(
                                "alertStream small body (%s bytes): %s",
                                len(body),
                                body.decode("utf-8", errors="replace"),
                            )
                            stream_resp.close()
                            # Wait before retry
                            stop_event.wait(30)
                            continue

                        # Read stream data
                        _LOGGER.warning("alertStream: starting to read stream...")
                        buffer = b""
                        while not stop_event.is_set():
                            chunk = stream_resp.read(4096)
                            if not chunk:
                                _LOGGER.warning("alertStream: stream ended (0 bytes)")
                                break
                            buffer += chunk
                            _LOGGER.warning(
                                "alertStream chunk (%d bytes): %s",
                                len(chunk),
                                chunk.decode("utf-8", errors="replace")[:500],
                            )
                            # Try to extract complete XML documents from buffer
                            text = buffer.decode("utf-8", errors="replace")
                            # ISAPI alertStream uses multipart boundary or
                            # sends individual XML docs separated by boundaries
                            while "</EventNotificationAlert>" in text:
                                end_idx = text.index("</EventNotificationAlert>") + len("</EventNotificationAlert>")
                                event_text = text[:end_idx]
                                text = text[end_idx:]
                                buffer = text.encode("utf-8")
                                _LOGGER.warning(
                                    "alertStream EVENT: %s", event_text[:800]
                                )
                                try:
                                    callback(event_text)
                                except Exception:
                                    _LOGGER.warning(
                                        "alertStream callback error",
                                        exc_info=True,
                                    )

                        stream_resp.close()
                    else:
                        # No auth needed or different response
                        body = resp.read()
                        _LOGGER.warning(
                            "alertStream non-401 body (%d bytes): %s",
                            len(body),
                            body.decode("utf-8", errors="replace")[:500],
                        )

                except Exception as exc:
                    if not stop_event.is_set():
                        _LOGGER.warning(
                            "alertStream error (will retry in 30s): %s", exc
                        )
                finally:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass
                # Wait before reconnecting
                stop_event.wait(30)

        thread = threading.Thread(
            target=_reader, name="hikvision-alertstream", daemon=True
        )
        thread.start()
        self._alert_stream_thread = thread
        _LOGGER.warning("alertStream listener thread started")

    def stop_alert_stream(self) -> None:
        """Stop the alertStream listener thread."""
        if self._alert_stream_stop:
            self._alert_stream_stop.set()
        if self._alert_stream_thread and self._alert_stream_thread.is_alive():
            self._alert_stream_thread.join(timeout=5)
        self._alert_stream_thread = None
        self._alert_stream_stop = None"
