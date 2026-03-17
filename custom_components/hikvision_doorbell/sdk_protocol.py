"""Pure Python implementation of the Hikvision SDK binary protocol.

Reverse-engineered from the HCNetSDK native library interface and Nmap service
probes. Communicates over TCP port 8000 using the Hikvision proprietary binary
protocol to receive real-time alarm events (DOORBELL_RINGING) without needing
the native C libraries.

Protocol overview (based on RE analysis):
  1. TCP connect to device port 8000
  2. Send Nmap-style identification probe (known to get a response)
  3. Login handshake (challenge-response with MD5)
  4. Subscribe to alarm channel
  5. Receive pushed binary alarm events

Each probe/login attempt uses a FRESH TCP connection because the device may
close the connection after receiving an unrecognized packet.
"""

import asyncio
import hashlib
import logging
import re as _re
import struct
from typing import Callable, Coroutine

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

DEFAULT_SDK_PORT = 8000
HEADER_SIZE = 32

# Known Nmap Hikvision probe: 32 bytes with command 0x63 at offset 4
# This is documented in Nmap's service-probes and reliably gets a response.
NMAP_PROBE = (
    b"\x00\x00\x00\x20"  # Bytes 0-3: header preamble (0x20 = 32)
    b"\x63"               # Byte 4: command 0x63 (device identification)
    b"\x00" * 27          # Bytes 5-31: zeros
)

# Alarm commands (from hcnetsdk.py COMM_ constants)
COMM_ALARM_V30 = 0x4000
COMM_ALARM_VIDEO_INTERCOM = 0x1133
COMM_UPLOAD_VIDEO_INTERCOM_EVENT = 0x1132
COMM_ISAPI_ALARM = 0x6009
COMM_ALARM_ACS = 0x5002

# Video Intercom Alarm types (byAlarmType field)
ALARM_TYPE_DOORBELL_RINGING = 17
ALARM_TYPE_DISMISS_INCOMING_CALL = 18

# Struct sizes
SERIALNO_LEN = 48
NAME_LEN = 32
MAX_DEV_NUMBER_LEN = 32


class HikvisionSDKError(Exception):
    """Error in the SDK protocol communication."""


# ------------------------------------------------------------------
# Helper: open a fresh TCP connection per probe/attempt
# ------------------------------------------------------------------


async def _open_tcp(host: str, port: int, timeout: float = 10):
    """Open a new TCP connection. Returns (reader, writer) or raises."""
    return await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )


async def _send_recv(
    host: str, port: int, data: bytes, timeout: float = 8, label: str = ""
) -> bytes | None:
    """Open a fresh TCP connection, send *data*, read response, close.

    A fresh connection is critical because the device closes the socket
    after receiving an unrecognised packet.
    """
    writer = None
    try:
        reader, writer = await _open_tcp(host, port, timeout=10)
    except (OSError, asyncio.TimeoutError) as err:
        _LOGGER.warning("SDK [%s]: TCP connect failed: %s", label, err)
        return None

    try:
        _LOGGER.warning(
            "SDK [%s]: TX %d bytes: %s", label, len(data), data.hex()
        )
        writer.write(data)
        await writer.drain()

        response = await asyncio.wait_for(reader.read(8192), timeout=timeout)

        if response:
            _LOGGER.warning(
                "SDK [%s]: RX %d bytes: %s",
                label, len(response), response.hex(),
            )
            _LOGGER.warning(
                "SDK [%s]: RX ASCII: %s",
                label, response.decode("ascii", errors="replace"),
            )
        else:
            _LOGGER.warning("SDK [%s]: empty response (peer closed)", label)
        return response or None

    except asyncio.TimeoutError:
        _LOGGER.warning("SDK [%s]: no response (timeout)", label)
        return None
    except (OSError, ConnectionError) as err:
        _LOGGER.warning("SDK [%s]: error: %s", label, err)
        return None
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


def _hexdump(label: str, data: bytes, max_bytes: int = 256) -> None:
    """Log a classic hex dump of *data*."""
    for i in range(0, min(max_bytes, len(data)), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        _LOGGER.warning(
            "SDK [%s] %04x: %-48s  %s", label, i, hex_part, asc_part
        )


# ------------------------------------------------------------------
# Protocol client
# ------------------------------------------------------------------


class HikvisionSDKProtocol:
    """Pure Python async TCP client for the Hikvision SDK binary protocol.

    v1.3.1 approach: **Protocol Discovery**

    Each probe is sent on a FRESH TCP connection (the device closes the
    socket after an unrecognised packet).  The Nmap identification probe
    (0x00000020 0x63 + zeros) is tried first because it is *known* to
    elicit a response from Hikvision devices on port 8000.

    Phase 1 (this version): send many probes, log every byte of every
    response so we can determine the exact wire format for login.
    Phase 2 (next version): proper login + alarm subscription.
    """

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        on_ring: Callable[[], Coroutine] | None = None,
        on_event: Callable[[int, int, bytes], Coroutine] | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._on_ring = on_ring
        self._on_event = on_event
        self._running = False
        self._listen_task: asyncio.Task | None = None

    # ------------------------------------------------------------------
    # Phase 1  -  Protocol discovery probes
    # ------------------------------------------------------------------

    async def probe_protocol(self) -> dict[str, bytes]:
        """Run all discovery probes and return a map of label -> response."""

        results: dict[str, bytes] = {}
        h, p = self._host, self._port

        # -- 1. Passive banner check (connect and just listen) -----------
        _LOGGER.warning("SDK PROBE 1/4: passive banner check %s:%d", h, p)
        banner = await self._passive_probe()
        if banner:
            results["banner"] = banner

        # -- 2. Nmap identification probe (known working) ----------------
        _LOGGER.warning("SDK PROBE 2/4: Nmap 0x63 identification %s:%d", h, p)
        resp = await _send_recv(h, p, NMAP_PROBE, timeout=8, label="nmap_0x63")
        if resp:
            results["nmap"] = resp
            _hexdump("nmap_resp", resp)
            self._analyse_nmap_response(resp)

        # -- 3. Single-byte command scan ---------------------------------
        _LOGGER.warning("SDK PROBE 3/4: command-byte scan %s:%d", h, p)
        for cmd in (0x01, 0x02, 0x03, 0x04, 0x05, 0x09, 0x0A,
                    0x10, 0x41, 0x50, 0x61, 0x62, 0x64, 0x65,
                    0xA0, 0xA1):
            pkt = bytearray(32)
            pkt[0:4] = b"\x00\x00\x00\x20"
            pkt[4] = cmd
            lbl = f"cmd_0x{cmd:02x}"
            resp = await _send_recv(h, p, bytes(pkt), timeout=5, label=lbl)
            if resp:
                results[lbl] = resp
                _hexdump(f"{lbl}_resp", resp)

        # -- 4. Login packet probes --------------------------------------
        _LOGGER.warning("SDK PROBE 4/4: login-format probes %s:%d", h, p)
        login_results = await self._probe_login_formats()
        results.update(login_results)

        return results

    # -- passive banner --------------------------------------------------

    async def _passive_probe(self) -> bytes | None:
        writer = None
        try:
            reader, writer = await _open_tcp(self._host, self._port, 10)
            _LOGGER.warning("SDK [passive]: connected, listening 5 s ...")
            data = await asyncio.wait_for(reader.read(4096), timeout=5)
            if data:
                _LOGGER.warning(
                    "SDK [passive]: RX %d bytes: %s", len(data), data.hex()
                )
                _hexdump("passive", data)
                return data
            _LOGGER.warning("SDK [passive]: no data (device waits for client)")
        except asyncio.TimeoutError:
            _LOGGER.warning("SDK [passive]: no banner (timeout)")
        except (OSError, ConnectionError) as err:
            _LOGGER.warning("SDK [passive]: error: %s", err)
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
        return None

    # -- login format probes ---------------------------------------------

    async def _probe_login_formats(self) -> dict[str, bytes]:
        results: dict[str, bytes] = {}

        user_bytes = self._username.encode("utf-8")[:NAME_LEN].ljust(
            NAME_LEN, b"\x00"
        )
        pass_bytes = self._password.encode("utf-8")[:NAME_LEN].ljust(
            NAME_LEN, b"\x00"
        )
        creds = user_bytes + pass_bytes  # 64 bytes

        h, p = self._host, self._port

        # A: 0x20 preamble + cmd 0x01 + datalen@24 + creds
        pkt = bytearray(32)
        pkt[0:4] = b"\x00\x00\x00\x20"
        pkt[4] = 0x01
        struct.pack_into("<I", pkt, 24, len(creds))
        resp = await _send_recv(h, p, bytes(pkt) + creds, 8, "loginA_cmd01")
        if resp:
            results["loginA"] = resp
            _hexdump("loginA_resp", resp)

        # B: Raw credentials (no header)
        resp = await _send_recv(h, p, creds, 8, "loginB_raw_creds")
        if resp:
            results["loginB"] = resp
            _hexdump("loginB_resp", resp)

        # C: LE struct header + creds
        hdr = struct.pack(
            "<I I I I HH I I",
            0x00000020, 0, 1, 0,
            0x0001, 0x0000,
            len(creds), 0,
        )
        resp = await _send_recv(h, p, hdr + creds, 8, "loginC_le_struct")
        if resp:
            results["loginC"] = resp
            _hexdump("loginC_resp", resp)

        # D: BE struct header + creds
        hdr = struct.pack(
            ">I I I I HH I I",
            0x00000020, 0, 1, 0,
            0x0001, 0x0000,
            len(creds), 0,
        )
        resp = await _send_recv(h, p, hdr + creds, 8, "loginD_be_struct")
        if resp:
            results["loginD"] = resp
            _hexdump("loginD_resp", resp)

        # E: datalen at offset 16 instead of 24
        pkt = bytearray(32)
        pkt[0:4] = b"\x00\x00\x00\x20"
        pkt[4] = 0x01
        struct.pack_into("<I", pkt, 16, len(creds))
        resp = await _send_recv(h, p, bytes(pkt) + creds, 8, "loginE_len16")
        if resp:
            results["loginE"] = resp
            _hexdump("loginE_resp", resp)

        # F: Username-only (challenge-response step 1)
        pkt = bytearray(32)
        pkt[0:4] = b"\x00\x00\x00\x20"
        pkt[4] = 0x01
        struct.pack_into("<I", pkt, 24, len(user_bytes))
        resp = await _send_recv(
            h, p, bytes(pkt) + user_bytes, 8, "loginF_user_only"
        )
        if resp:
            results["loginF"] = resp
            _hexdump("loginF_resp", resp)

        # G: "HK" magic prefix
        pkt = b"HK" + b"\x00" * 30 + creds
        resp = await _send_recv(h, p, pkt, 8, "loginG_HK_magic")
        if resp:
            results["loginG"] = resp
            _hexdump("loginG_resp", resp)

        # H: Various alternative login command bytes
        for cmd in (0xA1, 0xA0, 0x00, 0x04, 0x05, 0x09, 0x0A, 0x64, 0x65):
            pkt = bytearray(32)
            pkt[0:4] = b"\x00\x00\x00\x20"
            pkt[4] = cmd
            struct.pack_into("<I", pkt, 24, len(creds))
            lbl = f"loginH_cmd0x{cmd:02x}"
            resp = await _send_recv(h, p, bytes(pkt) + creds, 5, lbl)
            if resp:
                results[lbl] = resp
                _hexdump(f"{lbl}_resp", resp)

        return results

    # -- nmap response analysis ------------------------------------------

    def _analyse_nmap_response(self, data: bytes) -> None:
        if len(data) < 32:
            _LOGGER.warning("SDK ANALYSIS: response too short (%d B)", len(data))
            return

        _LOGGER.warning("SDK ANALYSIS: full hex dump of Nmap response:")
        _hexdump("nmap_analysis", data, max_bytes=512)

        if data[4] == 0x63:
            _LOGGER.warning(
                "SDK ANALYSIS: response mirrors cmd 0x63 "
                "(standard Hikvision identification)"
            )

        # Extract printable ASCII runs (model, serial, firmware)
        text = data.decode("ascii", errors="replace")
        strings = _re.findall(r"[\x20-\x7e]{4,}", text)
        if strings:
            _LOGGER.warning("SDK ANALYSIS: ASCII strings: %s", strings)

        if data[0:4] == b"\x00\x00\x00\x20":
            _LOGGER.warning(
                "SDK ANALYSIS: same 0x00000020 preamble (confirmed Hikvision)"
            )

    # ------------------------------------------------------------------
    # Phase 2 stub  -  persistent event listener
    # ------------------------------------------------------------------

    async def connect_and_listen(self) -> None:
        """Run protocol probes then keep a connection open for events."""

        _LOGGER.warning(
            "SDK: starting protocol discovery for %s:%d",
            self._host, self._port,
        )

        probe_results = await self.probe_protocol()

        responding = [k for k, v in probe_results.items() if v]
        _LOGGER.warning(
            "SDK: discovery complete. %d probes got responses: %s",
            len(responding), responding,
        )

        if not responding:
            _LOGGER.warning(
                "SDK: no probes got a response from %s:%d. "
                "Device may not support the SDK protocol on this port.",
                self._host, self._port,
            )
            return

        # Keep a long-lived connection open using the Nmap probe as
        # keepalive.  Any unsolicited data is logged for analysis.
        if "nmap" in probe_results:
            await self._nmap_keepalive_loop()

    async def _nmap_keepalive_loop(self) -> None:
        """Persistent connection that re-sends the Nmap probe periodically."""
        while self._running:
            writer = None
            try:
                reader, writer = await _open_tcp(
                    self._host, self._port, timeout=10
                )
                _LOGGER.warning(
                    "SDK: persistent connection to %s:%d established",
                    self._host, self._port,
                )

                while self._running:
                    # send Nmap keepalive
                    try:
                        writer.write(NMAP_PROBE)
                        await writer.drain()
                    except (OSError, ConnectionError):
                        break

                    # read response / unsolicited data
                    try:
                        data = await asyncio.wait_for(
                            reader.read(8192), timeout=60
                        )
                        if not data:
                            _LOGGER.warning("SDK: connection closed by device")
                            break
                        _LOGGER.warning(
                            "SDK: RX %d bytes: %s",
                            len(data), data[:128].hex(),
                        )
                        self._check_for_alarm(data)
                    except asyncio.TimeoutError:
                        _LOGGER.debug("SDK: 60 s silence, sending keepalive")
                        continue

            except (OSError, asyncio.TimeoutError) as err:
                _LOGGER.warning("SDK: connection error: %s", err)
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            if self._running:
                _LOGGER.warning("SDK: reconnecting in 30 s ...")
                await asyncio.sleep(30)

    # ------------------------------------------------------------------
    # Alarm detection (scan raw bytes)
    # ------------------------------------------------------------------

    def _check_for_alarm(self, data: bytes) -> None:
        """Scan received data for COMM_ALARM_VIDEO_INTERCOM (0x1133)."""
        for off in range(0, len(data) - 1):
            val16 = struct.unpack_from("<H", data, off)[0]
            if val16 == COMM_ALARM_VIDEO_INTERCOM:
                _LOGGER.warning(
                    "SDK: COMM_ALARM_VIDEO_INTERCOM at offset %d!", off
                )
                if self._on_ring:
                    asyncio.create_task(self._on_ring())
                return

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        """Start probe sequence and event listener.  Returns True."""
        self._running = True
        self._listen_task = asyncio.create_task(
            self.connect_and_listen(),
            name="hikvision-sdk-protocol",
        )
        return True

    async def stop(self) -> None:
        self._running = False
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
            try:
                await self._listen_task
            except (asyncio.CancelledError, Exception):
                pass


# ------------------------------------------------------------------
# Reconnector wrapper
# ------------------------------------------------------------------


class HikvisionSDKReconnector:
    """Manages the SDK connection with automatic reconnection."""

    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        on_ring: Callable[[], Coroutine] | None = None,
        on_event: Callable[[int, int, bytes], Coroutine] | None = None,
        reconnect_interval: int = 30,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._on_ring = on_ring
        self._on_event = on_event
        self._reconnect_interval = reconnect_interval
        self._protocol: HikvisionSDKProtocol | None = None
        self._task: asyncio.Task | None = None
        self._running = False

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(
            self._run_loop(), name="hikvision-sdk-reconnector"
        )

    async def _run_loop(self) -> None:
        while self._running:
            proto = HikvisionSDKProtocol(
                host=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                on_ring=self._on_ring,
                on_event=self._on_event,
            )
            self._protocol = proto

            await proto.start()

            # wait for the internal listen task to finish
            if proto._listen_task:
                try:
                    await proto._listen_task
                except (asyncio.CancelledError, Exception):
                    pass

            await proto.stop()
            self._protocol = None

            if self._running:
                _LOGGER.warning(
                    "SDK: reconnecting in %d s ...",
                    self._reconnect_interval,
                )
                await asyncio.sleep(self._reconnect_interval)

    async def stop(self) -> None:
        self._running = False
        if self._protocol:
            await self._protocol.stop()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
