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
_isapi = importlib.import_module("isapi")

HikvisionISAPIError = _isapi.HikvisionISAPIError
HikvisionISAPIAuthError = _isapi.HikvisionISAPIAuthError
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
    resp = httpx.Response(
        status_code=status_code,
        content=content,
        headers=headers or {},
        request=httpx.Request("GET", "http://192.168.1.1/test"),
    )
    return resp


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


# -- Test get_device_info ------------------------------------------------------

class TestGetDeviceInfo:
    async def test_parse_device_info_with_namespace(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
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
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=DEVICE_INFO_XML_NO_NS)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            info = await client.get_device_info()

        assert info["name"] == "Back Door"
        assert info["model"] == "DS-KV6113"
        assert info["serial"] == "SERIAL123"
        await client.close()

    async def test_auth_failure_raises(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "wrong")
        mock_resp = _make_response(status_code=401)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(HikvisionISAPIAuthError):
                await client.get_device_info()
        await client.close()

    async def test_connection_error_raises(self):
        client = HikvisionISAPIClient("192.168.1.99", "admin", "pass")
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("Connection refused"),
        ):
            with pytest.raises(HikvisionISAPIError, match="Cannot connect"):
                await client.get_device_info()
        await client.close()

    async def test_timeout_raises(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ReadTimeout("timed out"),
        ):
            with pytest.raises(HikvisionISAPIError, match="Timeout"):
                await client.get_device_info()
        await client.close()

    async def test_http_500_raises(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(status_code=500)
        mock_resp.request = httpx.Request("GET", "http://192.168.1.1/ISAPI/System/deviceInfo")
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            with pytest.raises(HikvisionISAPIError, match="HTTP 500"):
                await client.get_device_info()
        await client.close()


# -- Test get_call_status ------------------------------------------------------

class TestGetCallStatus:
    async def test_json_idle(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=CALL_STATUS_JSON_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "idle"
        assert "idle" in raw
        await client.close()

    async def test_json_ring(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=CALL_STATUS_JSON_RING)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "ring"
        await client.close()

    async def test_xml_fallback_idle(self):
        """Firmware that ignores format=json and returns XML."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=CALL_STATUS_XML_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "idle"
        await client.close()

    async def test_xml_fallback_ring(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=CALL_STATUS_XML_RING)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "ring"
        await client.close()

    async def test_unparseable_returns_unknown(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=b"this is not json or xml")
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, raw = await client.get_call_status()
        assert status == "unknown"
        await client.close()

    async def test_empty_json_status_returns_unknown(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        mock_resp = _make_response(content=b'{"CallStatus": {}}')
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
            status, _ = await client.get_call_status()
        assert status == "unknown"
        await client.close()


# -- Test get_snapshot ---------------------------------------------------------

class TestGetSnapshot:
    async def test_snapshot_via_content_type(self):
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
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
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
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
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
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
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            result = await client.get_snapshot()
        assert result is None
        await client.close()

    async def test_snapshot_non_image_skipped(self):
        """Response is not an image (wrong content-type, no JPEG magic)."""
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
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
        client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
        with patch.object(client._client, "aclose", new_callable=AsyncMock) as mock_aclose:
            await client.close()
        mock_aclose.assert_called_once()
