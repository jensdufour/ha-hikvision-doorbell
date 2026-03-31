"""Tests for the Hikvision Doorbell coordinator logic.

Since the coordinator depends on homeassistant internals (DataUpdateCoordinator, mqtt),
we test the core logic by exercising the ISAPI client interactions and state machine
through a lightweight mock harness that simulates the coordinator's behavior.
"""

import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import isapi directly
_isapi_path = Path(__file__).resolve().parent.parent / "custom_components" / "hikvision_doorbell"
if str(_isapi_path) not in sys.path:
    sys.path.insert(0, str(_isapi_path))
if "isapi" in sys.modules:
    del sys.modules["isapi"]
_isapi = importlib.import_module("isapi")

HikvisionISAPIClient = _isapi.HikvisionISAPIClient
HikvisionISAPIError = _isapi.HikvisionISAPIError
HikvisionISAPIAuthError = _isapi.HikvisionISAPIAuthError

import httpx


# We replicate the coordinator's state machine logic here to test it in isolation.
# This avoids needing a full HA install while still validating the ring detection.

class CoordinatorStateMachine:
    """Stripped-down replica of the coordinator's poll logic for testability."""

    def __init__(self, client: HikvisionISAPIClient):
        self.client = client
        self.ringing = False
        self.last_status = "idle"
        self.consecutive_errors = 0
        self.latest_snapshot: bytes | None = None
        self.ring_events: list[str] = []  # track ring triggers

    async def poll(self) -> dict:
        """Simulate one poll cycle."""
        try:
            status, raw = await self.client.get_call_status()
            self.consecutive_errors = 0
        except HikvisionISAPIAuthError:
            # 401 on callStatus = endpoint unavailable, not a real auth error
            self.consecutive_errors = 0
            return {"call_state": "ringing" if self.ringing else "idle"}
        except HikvisionISAPIError:
            self.consecutive_errors += 1
            if self.consecutive_errors >= 5:
                raise
            return {"call_state": "ringing" if self.ringing else "idle"}

        self.last_status = status

        if status == "ring" and not self.ringing:
            self.ringing = True
            self.ring_events.append("ring_start")
            # Capture snapshot
            try:
                snapshot = await self.client.get_snapshot()
                if snapshot:
                    self.latest_snapshot = snapshot
            except Exception:
                pass
        elif status != "ring" and self.ringing:
            self.ringing = False
            self.ring_events.append("ring_stop")

        return {"call_state": "ringing" if self.ringing else "idle"}


def _make_response(content: bytes = b"", headers: dict | None = None, status_code: int = 200):
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers=headers or {},
        request=httpx.Request("GET", "http://192.168.1.1/test"),
    )


CALL_STATUS_IDLE = b'{"CallStatus": {"status": "idle"}}'
CALL_STATUS_RING = b'{"CallStatus": {"status": "ring"}}'
JPEG_BYTES = b"\xff\xd8\xff\xe0" + b"\x00" * 50


def _make_client():
    """Create a client with the internal httpx client initialized for testing."""
    client = HikvisionISAPIClient("192.168.1.1", "admin", "pass")
    client._ensure_client()
    return client


class TestRingDetectionStateMachine:
    """Test the ring detection state machine logic."""

    async def test_idle_stays_idle(self):
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        resp = _make_response(content=CALL_STATUS_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=resp):
            result = await sm.poll()

        assert result == {"call_state": "idle"}
        assert not sm.ringing
        assert sm.ring_events == []
        await client.close()

    async def test_ring_detected(self):
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        async def mock_get(url, **kwargs):
            if "callStatus" in url:
                return _make_response(content=CALL_STATUS_RING)
            if "picture" in url:
                return _make_response(content=JPEG_BYTES, headers={"content-type": "image/jpeg"})
            return _make_response(content=b"")

        with patch.object(client._client, "get", side_effect=mock_get):
            result = await sm.poll()

        assert result == {"call_state": "ringing"}
        assert sm.ringing
        assert sm.ring_events == ["ring_start"]
        assert sm.latest_snapshot == JPEG_BYTES
        await client.close()

    async def test_ring_to_idle_transition(self):
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        # First: ring
        async def mock_ring(url, **kwargs):
            if "callStatus" in url:
                return _make_response(content=CALL_STATUS_RING)
            if "picture" in url:
                return _make_response(content=JPEG_BYTES, headers={"content-type": "image/jpeg"})
            return _make_response()

        with patch.object(client._client, "get", side_effect=mock_ring):
            await sm.poll()
        assert sm.ringing

        # Then: idle
        resp_idle = _make_response(content=CALL_STATUS_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=resp_idle):
            result = await sm.poll()

        assert result == {"call_state": "idle"}
        assert not sm.ringing
        assert sm.ring_events == ["ring_start", "ring_stop"]
        await client.close()

    async def test_repeated_ring_does_not_retrigger(self):
        """While ringing, additional ring polls should not trigger new events."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        async def mock_ring(url, **kwargs):
            if "callStatus" in url:
                return _make_response(content=CALL_STATUS_RING)
            if "picture" in url:
                return _make_response(content=JPEG_BYTES, headers={"content-type": "image/jpeg"})
            return _make_response()

        with patch.object(client._client, "get", side_effect=mock_ring):
            await sm.poll()  # triggers ring
            await sm.poll()  # should NOT re-trigger
            await sm.poll()  # should NOT re-trigger

        assert sm.ring_events == ["ring_start"]  # only one event
        await client.close()

    async def test_consecutive_errors_tolerated(self):
        """Up to 4 consecutive errors should be tolerated."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            for _ in range(4):
                result = await sm.poll()
                assert result == {"call_state": "idle"}

        assert sm.consecutive_errors == 4
        await client.close()

    async def test_5th_consecutive_error_raises(self):
        """The 5th consecutive error should propagate."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            for _ in range(4):
                await sm.poll()

            with pytest.raises(HikvisionISAPIError):
                await sm.poll()
        await client.close()

    async def test_errors_reset_on_success(self):
        """A successful poll should reset the error counter."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        # 3 failures...
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            for _ in range(3):
                await sm.poll()
        assert sm.consecutive_errors == 3

        # ...then success
        resp = _make_response(content=CALL_STATUS_IDLE)
        with patch.object(client._client, "get", new_callable=AsyncMock, return_value=resp):
            await sm.poll()
        assert sm.consecutive_errors == 0
        await client.close()

    async def test_ringing_preserved_during_errors(self):
        """If ringing and errors occur, ringing state should be preserved."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        # Start ringing
        async def mock_ring(url, **kwargs):
            if "callStatus" in url:
                return _make_response(content=CALL_STATUS_RING)
            return _make_response(content=JPEG_BYTES, headers={"content-type": "image/jpeg"})

        with patch.object(client._client, "get", side_effect=mock_ring):
            await sm.poll()
        assert sm.ringing

        # Now errors
        with patch.object(
            client._client, "get", new_callable=AsyncMock,
            side_effect=httpx.ConnectError("fail"),
        ):
            result = await sm.poll()

        assert result == {"call_state": "ringing"}
        assert sm.ringing
        await client.close()

    async def test_snapshot_failure_does_not_block_ring(self):
        """If snapshot capture fails, ring should still be detected."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        call_count = 0
        async def mock_get(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "callStatus" in url:
                return _make_response(content=CALL_STATUS_RING)
            # Snapshot fails
            raise httpx.ConnectError("snapshot fail")

        with patch.object(client._client, "get", side_effect=mock_get):
            result = await sm.poll()

        assert result == {"call_state": "ringing"}
        assert sm.ringing
        assert sm.latest_snapshot is None  # snapshot failed
        await client.close()


class TestFullCycleScenarios:
    """End-to-end scenarios combining multiple polls."""

    async def test_idle_ring_idle_ring_cycle(self):
        """Simulate a full ring cycle: idle -> ring -> idle -> ring."""
        client = _make_client()
        sm = CoordinatorStateMachine(client)

        responses = [
            CALL_STATUS_IDLE,
            CALL_STATUS_RING,
            CALL_STATUS_RING,
            CALL_STATUS_IDLE,
            CALL_STATUS_IDLE,
            CALL_STATUS_RING,
        ]

        for resp_body in responses:
            async def mock_get(url, body=resp_body, **kwargs):
                if "callStatus" in url:
                    return _make_response(content=body)
                return _make_response(content=JPEG_BYTES, headers={"content-type": "image/jpeg"})

            with patch.object(client._client, "get", side_effect=mock_get):
                await sm.poll()

        # Two ring starts, one ring stop (second ring is still active)
        assert sm.ring_events == ["ring_start", "ring_stop", "ring_start"]
        assert sm.ringing  # still ringing from last poll
        await client.close()
