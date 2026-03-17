"""Pure Python implementation of the Hikvision SDK binary protocol.

Reverse-engineered from the HCNetSDK native library interface. Communicates
over TCP port 8000 using the Hikvision proprietary binary protocol to receive
real-time alarm events (specifically DOORBELL_RINGING) without needing the
native C libraries.

Protocol overview:
  1. TCP connect to device port 8000
  2. Login handshake to get a session/user ID
  3. Subscribe to alarm channel
  4. Receive pushed binary alarm events
"""

import asyncio
import hashlib
import logging
import struct
from typing import Callable, Coroutine

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants (from Hikvision SDK headers / Pergola Fabio hcnetsdk.py)
# ---------------------------------------------------------------------------

DEFAULT_SDK_PORT = 8000

# Command types for alarm events
CYCLOPSE_HEADER_MAGIC = 0x00000000  # Placeholder - will be discovered
HEADER_SIZE = 32  # Standard Hikvision header is 32 bytes

# Alarm commands (from hcnetsdk.py COMM_ constants)
COMM_ALARM_V30 = 0x4000
COMM_ALARM_VIDEO_INTERCOM = 0x1133
COMM_UPLOAD_VIDEO_INTERCOM_EVENT = 0x1132
COMM_ISAPI_ALARM = 0x6009
COMM_ALARM_ACS = 0x5002

# Video Intercom Alarm types (byAlarmType field)
ALARM_TYPE_ZONE = 1
ALARM_TYPE_TAMPERING = 2
ALARM_TYPE_DOORBELL_RINGING = 17
ALARM_TYPE_DISMISS_INCOMING_CALL = 18

# ---------------------------------------------------------------------------
# Binary struct definitions matching C structs from hcnetsdk.py
# All little-endian, matching the ctypes Structure layouts.
# ---------------------------------------------------------------------------

# Size constants
SERIALNO_LEN = 48
NAME_LEN = 32
MACADDR_LEN = 6
MAX_DEV_NUMBER_LEN = 32

# NET_DVR_DEVICEINFO_V30 - total size calculated from fields
# Fields: sSerialNumber(48B) + 11 BYTEs + wDevType(2B) + 7 BYTEs + byRes3(2B)
#         + byMirrorChanNum(1B) + wStartMirrorChanNo(2B)
DEVICEINFO_V30_SIZE = 48 + 11 + 2 + 7 + 2 + 1 + 2  # = 73

# NET_DVR_SETUPALARM_PARAM_V50 - fields from hcnetsdk.py
# dwSize(4) + byLevel(1) + byAlarmInfoType(1) + byRetAlarmTypeV40(1) +
# byRetDevInfoVersion(1) + byRetVQDAlarmType(1) + byFaceAlarmDetection(1) +
# bySupport(1) + byBrokenNetHttp(1) + wTaskNo(2) + byDeployType(1) +
# byRes1(3) + byAlarmTypeURL(1) + byCustomCtrl(1) + byRes4(128)
SETUPALARM_V50_SIZE = 4 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 3 + 1 + 1 + 128  # = 148

# NET_DVR_ALARMER key fields - we only need to parse serialNumber
# Full struct is larger but we extract what we need
ALARMER_SIZE = 1 + 1 + 1 + 1 + 1 + 1 + 1 + 1  # 8 flag bytes
ALARMER_SIZE += 4  # lUserID (LONG)
ALARMER_SIZE += SERIALNO_LEN  # sSerialNumber
ALARMER_SIZE += 4  # dwDeviceVersion
ALARMER_SIZE += NAME_LEN  # sDeviceName
ALARMER_SIZE += MACADDR_LEN  # byMacAddr
ALARMER_SIZE += 2  # wLinkPort
ALARMER_SIZE += 128  # sDeviceIP
ALARMER_SIZE += 128  # sSocketIP
ALARMER_SIZE += 1  # byIpProtocol
ALARMER_SIZE += 6  # byRes2
# Total: 8 + 4 + 48 + 4 + 32 + 6 + 2 + 128 + 128 + 1 + 6 = 367

# NET_DVR_VIDEO_INTERCOM_ALARM partial parse
# dwSize(4) + struTime(8 bytes: NET_DVR_TIME_EX) + byDevNumber(32) +
# byAlarmType(1) + byRes1(3) + uAlarmInfo(256) + wLockID(1) + byRes2(1)
VIDEO_INTERCOM_ALARM_SIZE = 4 + 8 + MAX_DEV_NUMBER_LEN + 1 + 3 + 256 + 1 + 1  # = 306


class HikvisionSDKError(Exception):
    """Error in the SDK protocol communication."""


class HikvisionSDKProtocol:
    """Pure Python async TCP client for the Hikvision SDK binary protocol.

    This is a reverse-engineered implementation that speaks just enough of
    the proprietary protocol to:
      1. Authenticate (login)
      2. Subscribe to alarm events
      3. Parse DOORBELL_RINGING alarm events

    It connects to TCP port 8000 on the device and maintains a persistent
    connection for receiving push events.
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

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._session_id: int = 0
        self._user_id: int = -1
        self._sequence: int = 0
        self._running = False
        self._listen_task: asyncio.Task | None = None

        # Protocol discovery state
        self._header_format_idx = 0

    def _next_seq(self) -> int:
        self._sequence += 1
        return self._sequence

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish TCP connection to the device SDK port."""
        _LOGGER.warning(
            "SDK: Connecting to %s:%d ...", self._host, self._port
        )
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port),
                timeout=10,
            )
        except (OSError, asyncio.TimeoutError) as err:
            raise HikvisionSDKError(
                f"Cannot connect to {self._host}:{self._port}: {err}"
            ) from err

        _LOGGER.warning("SDK: TCP connected to %s:%d", self._host, self._port)

        # Some devices send data immediately on connect; read any banner
        try:
            banner = await asyncio.wait_for(
                self._reader.read(1024), timeout=3
            )
            if banner:
                _LOGGER.warning(
                    "SDK: Banner received (%d bytes): %s",
                    len(banner),
                    banner.hex(),
                )
                self._analyze_banner(banner)
        except asyncio.TimeoutError:
            _LOGGER.warning("SDK: No banner (device waiting for client)")

    def _analyze_banner(self, data: bytes) -> None:
        """Analyze any data the device sends upon TCP connect."""
        _LOGGER.warning("SDK BANNER hex: %s", data.hex())
        _LOGGER.warning("SDK BANNER ascii: %s", data.decode("ascii", errors="replace"))
        if len(data) >= 4:
            _LOGGER.warning(
                "SDK BANNER first 4 bytes as uint32 LE: 0x%08x",
                struct.unpack_from("<I", data, 0)[0],
            )
        if len(data) >= 32:
            _LOGGER.warning(
                "SDK BANNER 32-byte header parse attempt: %s",
                self._parse_header_variants(data[:32]),
            )

    def _parse_header_variants(self, header: bytes) -> dict:
        """Try multiple known header format guesses and log all of them."""
        results = {}

        # Variant A: Standard 32-byte Hikvision header
        # [4B magic][4B session][4B seq][4B status][4B cmd+flags][4B datalen][8B reserved]
        try:
            magic, session, seq, status, cmd_flags, datalen = struct.unpack_from(
                "<IIIIII", header, 0
            )
            results["variant_A"] = {
                "magic": f"0x{magic:08x}",
                "session": session,
                "seq": seq,
                "status": f"0x{status:08x}",
                "cmd_flags": f"0x{cmd_flags:08x}",
                "datalen": datalen,
            }
        except struct.error:
            pass

        # Variant B: [2B cmd][2B ver][4B session][4B seq][4B reserved][4B status][4B datalen][8B reserved]
        try:
            cmd, ver, session, seq, res, status, datalen = struct.unpack_from(
                "<HHIIIII", header, 0
            )
            results["variant_B"] = {
                "cmd": f"0x{cmd:04x}",
                "ver": f"0x{ver:04x}",
                "session": session,
                "seq": seq,
                "status": f"0x{status:08x}",
                "datalen": datalen,
            }
        except struct.error:
            pass

        # Variant C: DVR-IP style [1B magic 0xff][1B ver][2B reserved][4B session][4B seq][2B total_pkt][2B cur_pkt][2B msgid][4B datalen]
        try:
            magic_byte, ver, res, session, seq, total, cur, msgid, datalen = struct.unpack_from(
                "<BBHIIHHHI", header, 0
            )
            results["variant_C_DVRIP"] = {
                "magic": f"0x{magic_byte:02x}",
                "ver": ver,
                "session": session,
                "seq": seq,
                "msgid": f"0x{msgid:04x}",
                "datalen": datalen,
            }
        except struct.error:
            pass

        # Raw dump of each 4-byte word
        words = []
        for i in range(0, min(32, len(header)), 4):
            val = struct.unpack_from("<I", header, i)[0]
            words.append(f"0x{val:08x}")
        results["raw_words"] = words

        return results

    async def disconnect(self) -> None:
        """Close the TCP connection and stop listening."""
        _LOGGER.warning("SDK: Disconnecting from %s:%d", self._host, self._port)
        self._running = False
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
            try:
                await self._listen_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._writer = None
        self._reader = None

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(self) -> bool:
        """Perform the login handshake.

        Tries multiple known login packet formats. Returns True on success.
        The login formats tried are based on Hikvision SDK protocol analysis.
        """
        if not self._writer or not self._reader:
            raise HikvisionSDKError("Not connected")

        _LOGGER.warning("SDK: Attempting login as '%s' ...", self._username)

        # Build login payload: username(NAME_LEN) + password(NAME_LEN)
        user_bytes = self._username.encode("utf-8")[:NAME_LEN].ljust(NAME_LEN, b"\x00")
        pass_bytes = self._password.encode("utf-8")[:NAME_LEN].ljust(NAME_LEN, b"\x00")

        # Also prepare IP and port bytes
        ip_bytes = self._host.encode("utf-8")[:128].ljust(128, b"\x00")
        port_bytes = struct.pack("<H", self._port)

        # --- Login Format 1: Simple header + credentials ---
        # Many older/mid-range Hikvision devices use this format.
        # Header: 20 bytes, then credentials payload
        login_payload = user_bytes + pass_bytes
        login_formats = self._build_login_packets(login_payload, ip_bytes, port_bytes)

        for fmt_name, packet in login_formats:
            _LOGGER.warning(
                "SDK: Trying login format '%s' (%d bytes): header=%s",
                fmt_name,
                len(packet),
                packet[:32].hex(),
            )
            try:
                self._writer.write(packet)
                await self._writer.drain()
            except (OSError, ConnectionError) as err:
                _LOGGER.warning("SDK: Send error for format '%s': %s", fmt_name, err)
                continue

            # Read response with timeout
            try:
                response = await asyncio.wait_for(
                    self._reader.read(4096), timeout=8
                )
            except asyncio.TimeoutError:
                _LOGGER.warning("SDK: No response for format '%s' (timeout)", fmt_name)
                continue

            if not response:
                _LOGGER.warning("SDK: Empty response for format '%s'", fmt_name)
                continue

            _LOGGER.warning(
                "SDK: Response for '%s' (%d bytes): %s",
                fmt_name,
                len(response),
                response[:128].hex(),
            )
            _LOGGER.warning(
                "SDK: Response ASCII: %s",
                response[:128].decode("ascii", errors="replace"),
            )

            # Analyze the response
            success = self._parse_login_response(fmt_name, response)
            if success:
                _LOGGER.warning(
                    "SDK: Login SUCCESS with format '%s'! session=%d user_id=%d",
                    fmt_name,
                    self._session_id,
                    self._user_id,
                )
                return True

            _LOGGER.warning(
                "SDK: Login format '%s' did not yield success, trying next...",
                fmt_name,
            )

        _LOGGER.warning("SDK: All login formats exhausted. Login FAILED.")
        return False

    def _build_login_packets(
        self, credentials: bytes, ip_bytes: bytes, port_bytes: bytes
    ) -> list[tuple[str, bytes]]:
        """Build login packets in multiple known protocol formats.

        Returns list of (format_name, packet_bytes).
        """
        packets = []
        seq = self._next_seq()

        # Format A: 32-byte header + credentials
        # Header: [magic=0][session=0][seq][0][cmd_login=0x0001_0000][datalen][reserved=0]
        data = credentials
        header_a = struct.pack(
            "<IIIIIII I",
            0x00000000,  # magic
            0x00000000,  # session (0 for login)
            seq,         # sequence
            0x00000000,  # status
            0x00010000,  # command: login (guess)
            len(data),   # payload length
            0x00000000,  # reserved
            0x00000000,  # reserved
        )
        packets.append(("A_32hdr_creds", header_a + data))

        # Format B: Compact header + full login struct
        # Some devices expect IP + port + user + pass
        data_b = ip_bytes[:16] + port_bytes + credentials
        header_b = struct.pack(
            "<IIIIII II",
            0x00000020,  # could be header-length indicator
            0x00000000,  # session
            seq,
            0x00000000,
            0x00000001,  # cmd: login
            len(data_b),
            0, 0,
        )
        packets.append(("B_32hdr_full", header_b + data_b))

        # Format C: Login V30 style - IP(16) + port(2) + user(32) + pass(16)
        pass_16 = self._password.encode("utf-8")[:16].ljust(16, b"\x00")
        user_32 = self._username.encode("utf-8")[:32].ljust(32, b"\x00")
        data_c = ip_bytes[:16] + port_bytes + user_32 + pass_16
        header_c = struct.pack(
            "<IIIIII II",
            0x00000000, 0, seq, 0,
            0x00000050,  # possible login command
            len(data_c),
            0, 0,
        )
        packets.append(("C_v30_ip_port_user_pass16", header_c + data_c))

        # Format D: NET_DVR_Login_V30 parameters as-is
        # The SDK passes: IP(char*), port(WORD), user(char*), pass(char*), devinfo(out)
        # Wire format might place them sequentially
        data_d = ip_bytes[:128] + port_bytes + credentials
        header_d = struct.pack(
            "<IIIIII II",
            0x00000000, 0, seq, 0,
            0x00000001,  # LOGIN command
            len(data_d),
            0, 0,
        )
        packets.append(("D_v30_full_128ip", header_d + data_d))

        # Format E: Challenge-response aware - send just credentials first
        # Some newer devices require a 2-step challenge-response login.
        # Step 1: Send a "hello" with just username to get a challenge
        user_only = self._username.encode("utf-8")[:NAME_LEN].ljust(NAME_LEN, b"\x00")
        header_e = struct.pack(
            "<IIIIII II",
            0x00000000, 0, seq, 0,
            0x00000001,
            len(user_only),
            0, 0,
        )
        packets.append(("E_user_only_hello", header_e + user_only))

        # Format F: Minimal probe - just send 32-byte zero header to see what comes back
        header_f = b"\x00" * 32
        packets.append(("F_zero_probe", header_f))

        # Format G: Try with a common marker byte pattern
        # Some RE shows 0x63636363 as a request marker
        data_g = credentials
        header_g = struct.pack(
            "<IIIIII II",
            0x63636363, 0, seq, 0,
            0x00000001,
            len(data_g),
            0, 0,
        )
        packets.append(("G_alt_magic", header_g + data_g))

        return packets

    def _parse_login_response(self, fmt_name: str, data: bytes) -> bool:
        """Parse a login response and extract session info.

        Returns True if this looks like a successful login.
        """
        if len(data) < 8:
            return False

        # Log detailed analysis
        if len(data) >= 32:
            header_info = self._parse_header_variants(data[:32])
            _LOGGER.warning("SDK: Login response header analysis: %s", header_info)

        # Look for patterns that indicate success:
        # 1. A non-zero session ID at expected offsets
        # 2. A NET_DVR_DEVICEINFO_V30 struct (starts with 48-byte serial number)
        # 3. Device type field (wDevType) matching known types

        # Try to find DEVICEINFO_V30 in the response
        # It should appear after the header, and starts with the serial number
        for offset in (32, 20, 24, 16, 8, 0):
            if offset + DEVICEINFO_V30_SIZE > len(data):
                continue
            chunk = data[offset : offset + DEVICEINFO_V30_SIZE]
            serial_raw = chunk[:SERIALNO_LEN]
            # Serial numbers are ASCII digits
            serial_str = ""
            for b in serial_raw:
                if 0x30 <= b <= 0x39:  # '0'-'9'
                    serial_str += chr(b)
                elif b == 0:
                    serial_str += "0"
                else:
                    break

            if len(serial_str) >= 8:
                _LOGGER.warning(
                    "SDK: Possible serial number at offset %d: %s",
                    offset,
                    serial_str,
                )
                # This looks like valid device info - extract more
                try:
                    # After serialNo(48), there are control bytes, then wDevType at offset 48+11
                    dev_type_offset = offset + 48 + 11
                    if dev_type_offset + 2 <= len(data):
                        dev_type = struct.unpack_from("<H", data, dev_type_offset)[0]
                        _LOGGER.warning(
                            "SDK: wDevType=0x%04x (%d) at offset %d",
                            dev_type, dev_type, dev_type_offset,
                        )
                        # Known device types from Pergola code:
                        # OUTDOOR=603, INDOOR=602, VillaVTO=605, etc.
                        if dev_type in (602, 603, 605, 896, 31, 861, 10503, 10509, 10510):
                            _LOGGER.warning(
                                "SDK: Recognized device type %d!", dev_type
                            )
                except struct.error:
                    pass

                # Try to extract session ID from the header
                for sid_offset in (4, 8, 0):
                    if sid_offset + 4 <= offset:
                        session = struct.unpack_from("<I", data, sid_offset)[0]
                        if session != 0:
                            self._session_id = session
                            self._user_id = session  # Often the same
                            _LOGGER.warning(
                                "SDK: Possible session ID: %d (offset %d)",
                                session, sid_offset,
                            )
                            return True

                # Even without a clear session ID, finding a valid serial
                # is a strong indicator of success
                self._session_id = 1  # placeholder
                self._user_id = 1
                return True

        # Check if the response contains an error indicator
        # Common error patterns: all zeros, or specific error codes
        if data == b"\x00" * len(data):
            _LOGGER.warning("SDK: All-zero response (connection rejected?)")
            return False

        # Look for any non-zero 4-byte values that could be session IDs
        for i in range(0, min(32, len(data) - 3), 4):
            val = struct.unpack_from("<I", data, i)[0]
            if val != 0 and val != 0xFFFFFFFF:
                _LOGGER.warning(
                    "SDK: Non-zero value at offset %d: 0x%08x (%d)",
                    i, val, val,
                )

        return False

    # ------------------------------------------------------------------
    # Alarm subscription
    # ------------------------------------------------------------------

    async def setup_alarm(self) -> bool:
        """Subscribe to alarm events (equivalent to NET_DVR_SetupAlarmChan_V50).

        Sends an alarm setup packet to tell the device to start pushing events
        to this connection.
        """
        if not self._writer or not self._reader:
            raise HikvisionSDKError("Not connected")

        _LOGGER.warning("SDK: Setting up alarm channel (subscribing to events)...")

        # Build NET_DVR_SETUPALARM_PARAM_V50 struct
        alarm_param = bytearray(SETUPALARM_V50_SIZE)
        struct.pack_into("<I", alarm_param, 0, SETUPALARM_V50_SIZE)  # dwSize
        alarm_param[4] = 1   # byLevel = 1
        alarm_param[5] = 1   # byAlarmInfoType = 1
        alarm_param[9] = 1   # byFaceAlarmDetection = 1
        alarm_param[11] = 1  # byDeployType = 1 (client deploy)
        # bySupport bit 1 = 0: do NOT send backlog
        alarm_param[10] = alarm_param[10] & ~0x02

        seq = self._next_seq()
        data = bytes(alarm_param)

        # Try multiple command IDs for alarm setup
        # NET_DVR_SetupAlarmChan_V50 might map to different wire commands
        alarm_commands = [
            ("alarm_v50_0x0800", 0x00000800),
            ("alarm_v50_0x0003", 0x00000003),
            ("alarm_v50_0x1100", 0x00001100),
            ("alarm_v50_0x0400", 0x00000400),
        ]

        for cmd_name, cmd_val in alarm_commands:
            header = struct.pack(
                "<IIIIII II",
                0x00000000,
                self._session_id,
                seq,
                0x00000000,
                cmd_val,
                len(data),
                0, 0,
            )
            packet = header + data

            _LOGGER.warning(
                "SDK: Sending alarm setup '%s' (%d bytes): %s",
                cmd_name, len(packet), packet[:32].hex(),
            )

            try:
                self._writer.write(packet)
                await self._writer.drain()
            except (OSError, ConnectionError) as err:
                _LOGGER.warning("SDK: Alarm setup send error: %s", err)
                continue

            try:
                response = await asyncio.wait_for(
                    self._reader.read(4096), timeout=5
                )
            except asyncio.TimeoutError:
                _LOGGER.warning(
                    "SDK: No response for alarm setup '%s'", cmd_name
                )
                continue

            if response:
                _LOGGER.warning(
                    "SDK: Alarm setup '%s' response (%d bytes): %s",
                    cmd_name, len(response), response[:64].hex(),
                )
                _LOGGER.warning(
                    "SDK: Alarm setup '%s' ASCII: %s",
                    cmd_name,
                    response[:64].decode("ascii", errors="replace"),
                )
                # Any non-empty response that isn't a connection close is promising
                return True

        _LOGGER.warning("SDK: Alarm setup - no format got a response")
        return False

    # ------------------------------------------------------------------
    # Event listening
    # ------------------------------------------------------------------

    async def start_listening(self) -> None:
        """Start the background task that listens for alarm events."""
        self._running = True
        self._listen_task = asyncio.create_task(
            self._event_loop(), name="hikvision-sdk-events"
        )
        _LOGGER.warning("SDK: Event listener started")

    async def _event_loop(self) -> None:
        """Main loop: continuously read from the TCP connection and parse events."""
        buffer = b""
        while self._running and self._reader:
            try:
                chunk = await asyncio.wait_for(
                    self._reader.read(8192), timeout=120
                )
            except asyncio.TimeoutError:
                # Send keepalive / check connection
                _LOGGER.debug("SDK: No data for 120s, connection alive check")
                if self._writer:
                    try:
                        # Send a minimal probe to keep the connection alive
                        self._writer.write(b"\x00" * 4)
                        await self._writer.drain()
                    except (OSError, ConnectionError):
                        _LOGGER.warning("SDK: Connection lost during keepalive")
                        break
                continue
            except (OSError, ConnectionError) as err:
                _LOGGER.warning("SDK: Connection error in event loop: %s", err)
                break
            except asyncio.CancelledError:
                break

            if not chunk:
                _LOGGER.warning("SDK: Connection closed by device")
                break

            buffer += chunk

            _LOGGER.debug(
                "SDK: Received %d bytes (buffer: %d bytes)",
                len(chunk), len(buffer),
            )

            # Try to parse complete messages from the buffer
            buffer = self._process_buffer(buffer)

        _LOGGER.warning("SDK: Event loop ended")
        self._running = False

    def _process_buffer(self, buffer: bytes) -> bytes:
        """Parse and handle complete messages from the receive buffer.

        Returns the remaining unparsed bytes.
        """
        while len(buffer) >= 32:
            # Try to parse a header to get the data length
            # We try our header variants to find one that gives a reasonable datalen
            datalen = self._extract_datalen(buffer[:32])

            if datalen is None or datalen < 0:
                # Can't parse header - try scanning forward for a recognizable pattern
                _LOGGER.warning(
                    "SDK: Unparseable header, scanning forward. First 32 bytes: %s",
                    buffer[:32].hex(),
                )
                # Skip 1 byte and retry
                buffer = buffer[1:]
                continue

            total_msg_size = 32 + datalen
            if len(buffer) < total_msg_size:
                # Not enough data yet - wait for more
                break

            # Extract the complete message
            message = buffer[:total_msg_size]
            buffer = buffer[total_msg_size:]

            self._handle_message(message)

        return buffer

    def _extract_datalen(self, header: bytes) -> int | None:
        """Try to extract data length from a 32-byte header.

        Returns the payload length, or None if the header doesn't look valid.
        """
        # Try offset 20 (Variant A: [magic][session][seq][status][cmd][datalen])
        datalen_20 = struct.unpack_from("<I", header, 20)[0]
        if 0 <= datalen_20 < 1_000_000:
            return datalen_20

        # Try offset 24
        datalen_24 = struct.unpack_from("<I", header, 24)[0]
        if 0 <= datalen_24 < 1_000_000:
            return datalen_24

        # Try offset 16
        datalen_16 = struct.unpack_from("<I", header, 16)[0]
        if 0 <= datalen_16 < 1_000_000:
            return datalen_16

        # Check if this might be a header-only message (no payload)
        # If all potential datalen fields are 0, treat as header-only
        if datalen_20 == 0 and datalen_24 == 0 and datalen_16 == 0:
            return 0

        return None

    def _handle_message(self, message: bytes) -> None:
        """Handle a single complete protocol message."""
        if len(message) < 32:
            return

        header = message[:32]
        payload = message[32:]

        # Extract command from potential header positions
        # Variant A: command at offset 16 (as DWORD)
        cmd_16 = struct.unpack_from("<I", header, 16)[0]
        # Variant B: command at offset 12 (as WORD)
        cmd_12_w = struct.unpack_from("<H", header, 12)[0]

        _LOGGER.warning(
            "SDK: Message received - cmd@16=0x%08x cmd@12=0x%04x payload=%d bytes",
            cmd_16, cmd_12_w, len(payload),
        )

        if payload:
            _LOGGER.warning(
                "SDK: Payload first 64 bytes: %s",
                payload[:64].hex(),
            )

        # Check if any extracted command matches known alarm types
        for cmd in (cmd_16, cmd_12_w, cmd_16 & 0xFFFF):
            if cmd in (
                COMM_ALARM_VIDEO_INTERCOM,
                COMM_UPLOAD_VIDEO_INTERCOM_EVENT,
                COMM_ALARM_V30,
                COMM_ISAPI_ALARM,
                COMM_ALARM_ACS,
            ):
                _LOGGER.warning(
                    "SDK: ALARM EVENT detected! command=0x%04x", cmd
                )
                asyncio.create_task(
                    self._handle_alarm_event(cmd, payload)
                )
                return

        # Also report to the generic event callback for analysis
        if self._on_event and payload:
            asyncio.create_task(
                self._on_event(cmd_16, cmd_12_w, payload)
            )

    async def _handle_alarm_event(self, command: int, payload: bytes) -> None:
        """Parse an alarm event and trigger callbacks."""
        _LOGGER.warning(
            "SDK: Parsing alarm command=0x%04x payload_size=%d",
            command, len(payload),
        )

        if command == COMM_ALARM_VIDEO_INTERCOM:
            # Payload contains NET_DVR_ALARMER + NET_DVR_VIDEO_INTERCOM_ALARM
            # Skip past the ALARMER struct to get to the alarm info
            alarm_offset = ALARMER_SIZE
            if alarm_offset + 50 > len(payload):
                # Try without ALARMER (some firmware versions skip it)
                alarm_offset = 0

            if alarm_offset + 50 <= len(payload):
                alarm_data = payload[alarm_offset:]
                # NET_DVR_VIDEO_INTERCOM_ALARM:
                #   dwSize(4) + struTime(8) + byDevNumber(32) + byAlarmType(1) ...
                alarm_type_offset = 4 + 8 + MAX_DEV_NUMBER_LEN  # = 44
                if alarm_type_offset < len(alarm_data):
                    alarm_type = alarm_data[alarm_type_offset]
                    _LOGGER.warning(
                        "SDK: Video intercom alarm type=%d (DOORBELL_RINGING=%d)",
                        alarm_type, ALARM_TYPE_DOORBELL_RINGING,
                    )

                    if alarm_type == ALARM_TYPE_DOORBELL_RINGING:
                        _LOGGER.warning("SDK: *** DOORBELL IS RINGING! ***")
                        if self._on_ring:
                            await self._on_ring()
                        return

                    if alarm_type == ALARM_TYPE_DISMISS_INCOMING_CALL:
                        _LOGGER.warning("SDK: Call dismissed")
                        return

            _LOGGER.warning(
                "SDK: Video intercom alarm - could not parse alarm type. "
                "Payload hex: %s",
                payload[:100].hex(),
            )
            # Treat any video intercom alarm as a potential ring
            if self._on_ring:
                _LOGGER.warning(
                    "SDK: Treating unrecognized video intercom alarm as ring"
                )
                await self._on_ring()

        elif command in (COMM_UPLOAD_VIDEO_INTERCOM_EVENT, COMM_ALARM_V30):
            _LOGGER.warning(
                "SDK: Event command=0x%04x detected, payload hex: %s",
                command,
                payload[:100].hex(),
            )
            # Log for analysis but don't trigger ring for non-intercom alarms

        elif command == COMM_ISAPI_ALARM:
            # ISAPI alarm - payload might contain XML/JSON
            _LOGGER.warning(
                "SDK: ISAPI alarm, payload text: %s",
                payload[:500].decode("utf-8", errors="replace"),
            )

    # ------------------------------------------------------------------
    # High-level connect + login + subscribe
    # ------------------------------------------------------------------

    async def start(self) -> bool:
        """Full startup sequence: connect, login, subscribe, listen.

        Returns True if the connection is established and listening for events.
        """
        try:
            await self.connect()
        except HikvisionSDKError as err:
            _LOGGER.warning("SDK: Connection failed: %s", err)
            return False

        login_ok = await self.login()
        if not login_ok:
            _LOGGER.warning(
                "SDK: Login failed. The raw traffic has been logged above for "
                "protocol analysis. Check the logs and update the login format."
            )
            # Don't disconnect - keep the diagnostic data flowing
            # Start listening anyway to capture any data the device sends
            await self.start_listening()
            return False

        await self.setup_alarm()
        await self.start_listening()
        return True

    async def stop(self) -> None:
        """Stop and disconnect."""
        await self.disconnect()


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
        """Start the connection manager."""
        self._running = True
        self._task = asyncio.create_task(
            self._run_loop(), name="hikvision-sdk-reconnector"
        )

    async def _run_loop(self) -> None:
        """Main reconnection loop."""
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

            success = await proto.start()
            if success:
                _LOGGER.warning(
                    "SDK: Connected and listening for events on %s:%d",
                    self._host, self._port,
                )
            else:
                _LOGGER.warning(
                    "SDK: Connection/login did not fully succeed on %s:%d. "
                    "The protocol probe data has been logged. Listening "
                    "for any data the device sends...",
                    self._host, self._port,
                )

            # Wait for the event loop to end (disconnection)
            if proto._listen_task:
                try:
                    await proto._listen_task
                except (asyncio.CancelledError, Exception):
                    pass

            await proto.stop()
            self._protocol = None

            if self._running:
                _LOGGER.warning(
                    "SDK: Reconnecting in %ds...", self._reconnect_interval
                )
                await asyncio.sleep(self._reconnect_interval)

    async def stop(self) -> None:
        """Stop the connection manager."""
        self._running = False
        if self._protocol:
            await self._protocol.stop()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
