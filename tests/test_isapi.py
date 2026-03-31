"""Tests for the Hikvision ISAPI client."""

import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest

# Import the isapi module directly to avoid pulling in homeassistant via __init__.py
_isapi_path = Path(__file__).resolve().parent.parent / "custom_components" / "hikvision_doorbell"
if str(_isapi_path) not in sys.path:
    sys.path.insert(0, str(_isapi_path))

# Force reimport to pick up changes
if "isapi" in sys.modules:
    del sys.modules["isapi"]
_isapi = importlib.import_module("isapi")

HikvisionISAPIError = _isapi.HikvisionISAPIError
HikvisionISAPIAuthError = _isapi.HikvisionISAPIAuthError
HikvisionISAPILockoutError = _isapi.HikvisionISAPILockoutError
HikvisionISAPIClient = _isapi.HikvisionISAPIClient

# -- Sample device responses --------------------------------------------------

DEVICE_INFO_XML = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo xmlns="http://www.hikvision.com/ver20/XMLSchema" version="2.0">
  <deviceName>Front Door</deviceName>
  <deviceID>12345</deviceID>
  <model>DS-KV8113-WME1</model>
  <serialNumber>DS-KV8113-WME120210101AAWRE12345678</serialNumber>
  <macAddress>aa:bb:cc:dd:ee:ff</macAddress>
  <firmwareVersion>V2.2.53</firmwareVersion>
  <hardwareVersion>1.0</hardwareVersion>
</DeviceInfo>
"""

DEVICE_INFO_XML_NO_NS = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo>
  <deviceName>Back Door</deviceName>
  <model>DS-KV6113</model>
  <serialNumber>SERIAL123</serialNumber>
  <firmwareVersion>V1.0.0</firmwareVersion>
  <hardwareVersion>2.0</hardwareVersion>
  <macAddress>11:22:33:44:55:66</macAddress>
</DeviceInfo>
"""

CALL_STATUS_JSON_IDLE = b'{"CallStatus": {"status": "idle"}}'
CALL_STATUS_JSON_RING = b'{"CallStatus": {"status": "ring"}}'

CALL_STATUS_XML_IDLE = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<CallStatus xmlns="http://www.hikvision.com/ver20/XMLSchema">
  <status>idle</status>
</CallStatus>
"""

CALL_STATUS_XML_RING = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<CallStatus xmlns="http://www.hikvision.com/ver20/XMLSchema">
  <status>ring</status>
</CallStatus>
"""

JPEG_HEADER = b"\xff\xd8\xff\xe0" + b"\x00" * 100


# -- Helpers -------------------------------------------------------------------

def _make_response(
    status_code: int = 200,
    content: bytes = b"",
    headers: dict | None = None,
) -> httpx.Response:
    """Create an httpx.Response for mocking."""
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers=headers or {},
        request=httpx.Request("GET", "http://192.168.1.1/test"),
    )


def _init_client(host="192.168.1.1", username="admin", password="pass"):
    """Create a client and force-initialize the internal httpx client for testing."""
    client = HikvisionISAPIClient(host, username, password)
    client._ensure_client()
    return client


# -- Test host URL normalization -----------------------------------------------

class TestClientInit:
    def test_plain_ip(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        assert client._base_url == "http://192.168.1.1"

    def test_with_http_scheme(self):
        client = HikvisionISAPIClient("http://192.168.1.1", "admin", "pass")
        assert client._base_url == "http://192.168.1.1"

    def test_with_https_scheme(self):
        client = HikvisionISAPIClient("https://192.168.1.1", "admin", "pass")
        assert client._base_url == "https://192.168.1.1"

    def test_trailing_slash_stripped(self):
        client = HikvisionISAPIClient("http://192.168.1.1/", "admin", "pass")
        assert client._base_url == "http://192.168.1.1"

    def test_hostname(self):
        client = HikvisionISAPIClient("doorbell.local", "admin", "pass")
        assert client._base_url == "http://doorbell.local"

    def test_client_starts_none(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        assert client._client is None


# -- Test async_init -----------------------------------------------------------

class TestAsyncInit:
    async def test_digest_auth_succeeds(self):
        """async_init should use Digest when device accepts it."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")

        async def mock_get(url, **kwargs):
            return _make_response(content=DEVICE_INFO_XML)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            await client.async_init()

        assert client._client is not None
        await client.close()

    async def test_fallback_to_basic(self):
        """async_init should fall back to Basic when Digest gets 401."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        clients_created = []

        original_create = client._create_client

        def tracking_create(auth):
            c = original_create(auth)
            clients_created.append(auth)
            return c

        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return _make_response(status_code=401)  # Digest fails
            return _make_response(content=DEVICE_INFO_XML)  # Basic succeeds

        with patch.object(client, "_create_client", side_effect=tracking_create):
            with patch("httpx.AsyncClient.get", side_effect=mock_get):
                await client.async_init()

        assert client._client is not None
        assert len(clients_created) == 2
        assert isinstance(clients_created[0], httpx.DigestAuth)
        assert isinstance(clients_created[1], httpx.BasicAuth)
        await client.close()

    async def test_both_fail_raises_auth_error(self):
        """If both auth methods return 401, async_init should raise."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "wrong")

        async def mock_get(url, **kwargs):
            return _make_response(status_code=401)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            with pytest.raises(HikvisionISAPIAuthError, match="Invalid username or password"):
                await client.async_init()

    async def test_lockout_detected(self):
        """If 401 body contains lockout indicators, raise lockout error."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        lockout_body = b"""<?xml version="1.0" encoding="UTF-8"?>
<ResponseStatus>
  <statusCode>401</statusCode>
  <subStatusCode>userFloor</subStatusCode>
  <retryLoginTime>30</retryLoginTime>
</ResponseStatus>"""

        async def mock_get(url, **kwargs):
            return _make_response(status_code=401, content=lockout_body)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            with pytest.raises(HikvisionISAPILockoutError, match="locked"):
                await client.async_init()

    async def test_lockout_detected_invalid_operation(self):
        """Firmware that uses invalidOperation as lockout indicator."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        lockout_body = b"""<?xml version="1.0" encoding="UTF-8"?>
<ResponseStatus version="1.0" xmlns="http://www.std-cgi.com/ver10/XMLSchema">
  <statusCode>4</statusCode>
  <statusString>Invalid Operation</statusString>
  <subStatusCode>invalidOperation</subStatusCode>
  <errorCode>1073741830</errorCode>
  <errorMsg>invalid operation</errorMsg>
</ResponseStatus>"""

        async def mock_get(url, **kwargs):
            return _make_response(status_code=401, content=lockout_body)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            with pytest.raises(HikvisionISAPILockoutError, match="locked"):
                await client.async_init()

    async def test_device_info_cached_from_probe(self):
        """async_init should cache device info from the successful probe."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")

        async def mock_get(url, **kwargs):
            return _make_response(content=DEVICE_INFO_XML)

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            await client.async_init()

        # get_device_info should return cached data without a network call
        info = await client.get_device_info()
        assert info["model"] == "DS-KV8113-WME1"
        assert info["serial"] == "DS-KV8113-WME120210101AAWRE12345678"

        # Cache should be cleared after first use
        assert client._device_info_cache is None
        await client.close()


# -- Test get_device_info ------------------------------------------------------

class TestGetDeviceInfo:
    async def test_parse_device_info_with_namespace(self):
        client = _init_client()
        mock_resp = _make_response(content=DEVICE_INFO_XML)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            info = await client.get_device_info()

        assert info["name"] == "Front Door"
        assert info["model"] == "DS-KV8113-WME1"
        assert info["serial"] == "DS-KV8113-WME120210101AAWRE12345678"
        assert info["firmware"] == "V2.2.53"
        assert info["hardware"] == "1.0"
        assert info["mac"] == "aa:bb:cc:dd:ee:ff"
        await client.close()

    async def test_parse_device_info_without_namespace(self):
        client = _init_client()
        mock_resp = _make_response(content=DEVICE_INFO_XML_NO_NS)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            info = await client.get_device_info()

        assert info["name"] == "Back Door"
        assert info["model"] == "DS-KV6113"
        assert info["serial"] == "SERIAL123"
        await client.close()

    async def test_auth_failure_raises(self):
        client = _init_client(password="wrong")
        mock_resp = _make_response(status_code=401)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(HikvisionISAPIAuthError):
                await client.get_device_info()
        await client.close()

    async def test_connection_error_raises(self):
        client = _init_client("192.168.1.99")
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            with pytest.raises(HikvisionISAPIError, match="Cannot connect"):
                await client.get_device_info()
        await client.close()

    async def test_timeout_raises(self):
        client = _init_client()
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ReadTimeout("timed out"),
        ):
            with pytest.raises(HikvisionISAPIError, match="Timeout"):
                await client.get_device_info()
        await client.close()

    async def test_http_500_raises(self):
        client = _init_client()
        mock_resp = _make_response(status_code=500)
        mock_resp.request = httpx.Request("GET", "http://192.168.1.1/ISAPI/System/deviceInfo")
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(HikvisionISAPIError, match="HTTP 500"):
                await client.get_device_info()
        await client.close()


# -- Test get_call_status ------------------------------------------------------

class TestGetCallStatus:
    async def test_json_idle(self):
        client = _init_client()
        mock_resp = _make_response(content=CALL_STATUS_JSON_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "idle"
        assert "idle" in raw
        await client.close()

    async def test_json_ring(self):
        client = _init_client()
        mock_resp = _make_response(content=CALL_STATUS_JSON_RING)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "ring"
        await client.close()

    async def test_xml_fallback_idle(self):
        """Firmware that ignores format=json and returns XML."""
        client = _init_client()
        mock_resp = _make_response(content=CALL_STATUS_XML_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "idle"
        await client.close()

    async def test_xml_fallback_ring(self):
        client = _init_client()
        mock_resp = _make_response(content=CALL_STATUS_XML_RING)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "ring"
        await client.close()

    async def test_callstatus_401_returns_idle(self):
        """A 401 on callStatus means endpoint unavailable, returns idle."""
        client = _init_client()
        mock_resp = _make_response(status_code=401)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "idle"
        await client.close()

    async def test_callstatus_401_disables_polling(self):
        """After all paths return 401, subsequent calls skip HTTP entirely."""
        client = _init_client()
        mock_resp = _make_response(status_code=401)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
            # First call: tries both paths, gets 401, disables polling
            status, raw = await client.get_call_status()
            assert status == "idle"
            assert not client._callstatus_available
            first_call_count = mock_get.call_count

            # Second call: no HTTP requests made at all
            status2, raw2 = await client.get_call_status()
            assert status2 == "idle"
            assert mock_get.call_count == first_call_count
        await client.close()

    async def test_callstatus_connection_error_raises(self):
        """Connection errors on callStatus should propagate."""
        client = _init_client()
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            with pytest.raises(HikvisionISAPIError, match="callStatus unavailable"):
                await client.get_call_status()
        await client.close()


# -- Test get_snapshot ---------------------------------------------------------

class TestGetSnapshot:
    async def test_snapshot_via_content_type(self):
        client = _init_client()
        mock_resp = _make_response(
            content=JPEG_HEADER,
            headers={"content-type": "image/jpeg"},
        )
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.get_snapshot()
        assert result == JPEG_HEADER
        await client.close()

    async def test_snapshot_via_magic_bytes(self):
        """Snapshot returned without proper content-type but has JPEG magic bytes."""
        client = _init_client()
        mock_resp = _make_response(
            content=JPEG_HEADER,
            headers={"content-type": "application/octet-stream"},
        )
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.get_snapshot()
        assert result == JPEG_HEADER
        await client.close()

    async def test_snapshot_fallback_to_channel_1(self):
        """Channel 101 fails, falls back to channel 1."""
        client = _init_client()
        call_count = 0

        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "101" in url:
                raise httpx.ConnectError("fail")
            return _make_response(
                content=JPEG_HEADER,
                headers={"content-type": "image/jpeg"},
            )

        with patch.object(client._client, "get", side_effect=mock_get):
            result = await client.get_snapshot()
        assert result == JPEG_HEADER
        assert call_count == 2
        await client.close()

    async def test_snapshot_all_channels_fail(self):
        client = _init_client()
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            result = await client.get_snapshot()
        assert result is None
        await client.close()

    async def test_snapshot_non_image_skipped(self):
        """Response is not an image (wrong content-type, no JPEG magic)."""
        client = _init_client()
        mock_resp = _make_response(
            content=b"<html>error</html>",
            headers={"content-type": "text/html"},
        )
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            result = await client.get_snapshot()
        assert result is None
        await client.close()


# -- Test close ----------------------------------------------------------------

class TestClose:
    async def test_close_calls_aclose(self):
        client = _init_client()
        with patch.object(client._client, "aclose", new_callable=AsyncMock) as mock_aclose:
            await client.close()
        mock_aclose.assert_called_once()

    async def test_close_when_no_client(self):
        """Closing a client that was never initialized should not error."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        await client.close()  # Should not raise
