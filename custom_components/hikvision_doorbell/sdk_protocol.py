"""Pure Python Hikvision SDK binary protocol client (v1.3.4).

Key findings from v1.3.3 logs:
  - Rapid TCP connections (5 within 100ms) ALL get RST on step1.
  - The passive loop, connecting 30s later, gets the 127-byte challenge.
  - After receiving the 127-byte challenge, the device expects the
    hashed login response IMMEDIATELY. Sending another probe (or anything
    else) kills the connection.
  - The device enforces a connection rate limit: too many connections
    too fast triggers RST for all subsequent attempts.

v1.3.4 strategy:
  - 10-second delay between each login attempt to avoid rate limiting.
  - On each connection, do the FULL two-step flow:
      Step 1: Send 32-byte header-only probe -> read 127-byte challenge
      Step 2: IMMEDIATELY send header + hashed credentials -> read response
  - One hash variant per connection to avoid confusing the device.
  - Also test: read-first (no probe) in case device sends challenge on connect.
  - Max 5 attempts total to preserve retry budget.
"""

import asyncio
import hashlib
import hmac
import logging
import struct
from typing import Callable, Coroutine

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SDK_PORT = 8000
HEADER_SIZE = 32

# Challenge response layout (127 bytes):
#   [0:4]       preamble/size = 0x7f (127)
#   [4:8]       status = 0x0407 (challenge issued)
#   [8:112]     zeros (empty device info, not authenticated)
#   [112:116]   retry count (LE uint32), e.g. 0x0A = 10
#   [116:124]   8-byte challenge salt/nonce
#   [124:127]   algo indicator (byte 124 = 0x06) + 2 zero bytes
CHALLENGE_SALT_OFFSET = 116
CHALLENGE_SALT_LEN = 8
CHALLENGE_ALGO_OFFSET = 124
CHALLENGE_RETRY_OFFSET = 112
CHALLENGE_MIN_LEN = 125

# Login payload field sizes
USERNAME_LEN = 32
PASSWORD_LEN = 16  # NET_DVR_LOGIN_PASSWD_MAX_LEN

# Alarm commands
COMM_ALARM_VIDEO_INTERCOM = 0x1133


class HikvisionSDKError(Exception):
    """Error in SDK protocol."""


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def _build_header(
    cmd: int = 0,
    datalen: int = 0,
    session: int = 0,
    status: int = 0,
    extra1: int = 0,
    extra2: int = 0,
    extra3: int = 0,
) -> bytes:
    """32-byte LE header (8 x uint32)."""
    return struct.pack(
        "<8I",
        HEADER_SIZE,  # [0:4] preamble = 0x20
        status,       # [4:8]
        cmd,          # [8:12]
        session,      # [12:16]
        extra1,       # [16:20]
        datalen,      # [20:24]
        extra2,       # [24:28]
        extra3,       # [28:32]
    )


def _parse_header(data: bytes) -> dict:
    """Parse a response as LE uint32 fields."""
    if len(data) < 4:
        return {"raw_len": len(data)}
    names = ["preamble", "status", "command", "session",
             "extra1", "payload_len", "extra2", "extra3"]
    fields = {}
    for i, name in enumerate(names):
        off = i * 4
        if off + 4 <= len(data):
            fields[name] = struct.unpack_from("<I", data, off)[0]
    return fields


def _hexdump(label: str, data: bytes, max_bytes: int = 256) -> None:
    """Log a hex dump."""
    for i in range(0, min(max_bytes, len(data)), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        _LOGGER.warning("SDK [%s] %04x: %-48s  %s", label, i, hx, asc)


# ---------------------------------------------------------------------------
# TCP helpers
# ---------------------------------------------------------------------------


async def _tcp_open(host: str, port: int, timeout: float = 10):
    """Open TCP connection."""
    return await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )


async def _tcp_read_all(reader, timeout: float = 5) -> bytes:
    """Read all available data from a reader with timeout."""
    chunks = []
    t = timeout
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(8192), timeout=t)
            if not chunk:
                break
            chunks.append(chunk)
            t = 0.5  # short timeout for subsequent fragments
    except asyncio.TimeoutError:
        pass
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Hash computation
# ---------------------------------------------------------------------------


def _compute_hash(password: str, salt: bytes, variant: str) -> bytes:
    """Compute a single hash variant."""
    pw16 = password.encode("utf-8")[:PASSWORD_LEN]
    pw_full = password.encode("utf-8")

    if variant == "sha256_pw16_salt":
        return hashlib.sha256(pw16 + salt).digest()
    elif variant == "sha256_salt_pw16":
        return hashlib.sha256(salt + pw16).digest()
    elif variant == "sha256_dbl_pw16_salt":
        return hashlib.sha256(hashlib.sha256(pw16).digest() + salt).digest()
    elif variant == "hmac_sha256_salt_pw16":
        return hmac.new(salt, pw16, hashlib.sha256).digest()
    elif variant == "sha256_pwfull_salt":
        return hashlib.sha256(pw_full + salt).digest()
    elif variant == "hmac_sha256_salt_pwfull":
        return hmac.new(salt, pw_full, hashlib.sha256).digest()
    elif variant == "md5_pw16_salt":
        return hashlib.md5(pw16 + salt).digest()
    elif variant == "md5_dbl_pw16_salt":
        return hashlib.md5(hashlib.md5(pw16).digest() + salt).digest()
    elif variant == "hmac_md5_salt_pw16":
        return hmac.new(salt, pw16, hashlib.md5).digest()
    elif variant == "md5_pwfull_salt":
        return hashlib.md5(pw_full + salt).digest()
    else:
        return hashlib.sha256(pw16 + salt).digest()


# ---------------------------------------------------------------------------
# Protocol client
# ---------------------------------------------------------------------------


class HikvisionSDKProtocol:
    """v1.3.4: Rate-limited single-connection challenge-response login.

    Each login attempt:
      1. Open ONE TCP connection
      2. Send 32-byte header-only probe
      3. Read 127-byte challenge (extract salt + algo)
      4. IMMEDIATELY send 32-byte header + hashed creds on SAME connection
      5. Read login response
      6. Close connection
      7. Wait 10 seconds before next attempt
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
        self._session_id: int = 0

    # ------------------------------------------------------------------
    # Login orchestration
    # ------------------------------------------------------------------

    async def _run_login_attempts(self) -> bool:
        """Try login with different hash variants, 10s apart.

        Returns True if login succeeded.
        """
        h, p = self._host, self._port

        _LOGGER.warning(
            "SDK: v1.3.4 login sequence for %s:%d (10s between attempts)", h, p
        )

        # Each attempt: (label, hash_variant, step2_cmd, payload_format)
        # payload_format: "u32h32" = username(32) + hash(32) = 64 bytes
        #                 "u32h16" = username(32) + hash(16) = 48 bytes
        attempts = [
            # Attempt 0: Read-first test (no probe) to check if device
            # sends challenge automatically on connect
            ("readfirst", None, None, None),
            # Attempt 1: SHA-256(pw16 + salt), cmd=0x0001
            ("sha256_pw16", "sha256_pw16_salt", 0x0001, "u32h32"),
            # Attempt 2: HMAC-SHA256(salt, pw16), cmd=0x0001
            ("hmac_sha256", "hmac_sha256_salt_pw16", 0x0001, "u32h32"),
            # Attempt 3: SHA-256(SHA-256(pw16) + salt), cmd=0x0001
            ("sha256_dbl", "sha256_dbl_pw16_salt", 0x0001, "u32h32"),
            # Attempt 4: MD5(pw16 + salt), cmd=0x0001
            ("md5_pw16", "md5_pw16_salt", 0x0001, "u32h32"),
        ]

        for idx, (label, hash_variant, step2_cmd, fmt) in enumerate(attempts):
            if not self._running:
                return False

            if idx > 0:
                _LOGGER.warning("SDK: waiting 10s before attempt %d...", idx)
                await asyncio.sleep(10)

            if hash_variant is None:
                # Special: read-first test
                result = await self._try_read_first(label)
            else:
                result = await self._try_login(
                    label, hash_variant, step2_cmd, fmt, idx
                )

            if result == "success":
                return True
            elif result == "locked":
                _LOGGER.warning("SDK: device locked, aborting login attempts")
                return False

        _LOGGER.warning("SDK: all login attempts exhausted")
        return False

    async def _try_read_first(self, label: str) -> str:
        """Test if device sends challenge automatically on TCP connect.

        Does NOT send anything - just reads immediately after connecting.
        This determines whether we need the header-only probe or not.
        """
        h, p = self._host, self._port
        writer = None

        _LOGGER.warning("SDK [%s]: testing read-first (no probe sent)", label)

        try:
            reader, writer = await _tcp_open(h, p, timeout=10)
            _LOGGER.warning("SDK [%s]: connected, reading without sending...", label)

            # Try to read without sending anything
            data = await _tcp_read_all(reader, timeout=5)

            if data:
                _LOGGER.warning(
                    "SDK [%s]: got %d bytes WITHOUT sending probe: %s",
                    label, len(data), data.hex(),
                )
                _hexdump(f"{label}_auto", data)

                if len(data) >= CHALLENGE_MIN_LEN:
                    _LOGGER.warning(
                        "SDK [%s]: DEVICE SENDS CHALLENGE ON CONNECT! "
                        "No probe needed.",
                        label,
                    )
                    return "auto_challenge"
            else:
                _LOGGER.warning(
                    "SDK [%s]: no data received without probe (need to send probe)",
                    label,
                )
                return "no_auto"

        except (OSError, ConnectionError, asyncio.TimeoutError) as err:
            _LOGGER.warning("SDK [%s]: error: %s", label, err)
            return "error"
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        return "no_auto"

    async def _try_login(
        self,
        label: str,
        hash_variant: str,
        step2_cmd: int,
        payload_fmt: str,
        attempt_num: int,
    ) -> str:
        """Execute one complete login flow on a single TCP connection.

        Step 1: send header-only -> read challenge
        Step 2: send hashed creds -> read response (on SAME connection)

        Returns: "success", "failed", "locked", "error"
        """
        h, p = self._host, self._port
        writer = None

        _LOGGER.warning(
            "SDK [%s]: attempt %d - hash=%s cmd=0x%04x",
            label, attempt_num, hash_variant, step2_cmd,
        )

        try:
            reader, writer = await _tcp_open(h, p, timeout=10)
            _LOGGER.warning("SDK [%s]: connected", label)

            # === STEP 1: Send header-only probe, read challenge ===
            step1_pkt = _build_header(cmd=0, datalen=0)
            _LOGGER.warning(
                "SDK [%s] S1-TX: %d B: %s",
                label, len(step1_pkt), step1_pkt.hex(),
            )
            writer.write(step1_pkt)
            await writer.drain()

            s1_data = await _tcp_read_all(reader, timeout=5)

            if not s1_data:
                _LOGGER.warning("SDK [%s] S1: no response", label)
                return "error"

            _LOGGER.warning(
                "SDK [%s] S1-RX: %d B: %s",
                label, len(s1_data), s1_data.hex(),
            )
            _hexdump(f"{label}_s1", s1_data)

            if len(s1_data) < CHALLENGE_MIN_LEN:
                _LOGGER.warning(
                    "SDK [%s] S1: too short for challenge (%d < %d)",
                    label, len(s1_data), CHALLENGE_MIN_LEN,
                )
                return "failed"

            # Parse challenge fields
            s1_hdr = _parse_header(s1_data)
            _LOGGER.warning("SDK [%s] S1: header=%s", label, s1_hdr)

            retries = struct.unpack_from("<I", s1_data, CHALLENGE_RETRY_OFFSET)[0]
            salt = s1_data[CHALLENGE_SALT_OFFSET:CHALLENGE_SALT_OFFSET + CHALLENGE_SALT_LEN]
            algo = s1_data[CHALLENGE_ALGO_OFFSET]

            _LOGGER.warning(
                "SDK [%s] S1: retries=%d salt=%s algo=0x%02x",
                label, retries, salt.hex(), algo,
            )

            if retries <= 1:
                _LOGGER.warning("SDK [%s]: only %d retries left!", label, retries)
                return "locked"

            # === Compute hash ===
            hashed = _compute_hash(self._password, salt, hash_variant)
            _LOGGER.warning(
                "SDK [%s] HASH(%s): %s", label, hash_variant, hashed.hex(),
            )

            # === STEP 2: Send hashed credentials on SAME connection ===
            user_bytes = (
                self._username.encode("utf-8")[:USERNAME_LEN]
                .ljust(USERNAME_LEN, b"\x00")
            )

            if payload_fmt == "u32h32":
                payload = user_bytes + hashed[:32].ljust(32, b"\x00")
            elif payload_fmt == "u32h16":
                payload = user_bytes + hashed[:16].ljust(16, b"\x00")
            else:
                payload = user_bytes + hashed[:32].ljust(32, b"\x00")

            step2_pkt = _build_header(cmd=step2_cmd, datalen=len(payload)) + payload

            _LOGGER.warning(
                "SDK [%s] S2-TX: %d B: %s",
                label, len(step2_pkt), step2_pkt.hex(),
            )
            writer.write(step2_pkt)
            await writer.drain()

            s2_data = await _tcp_read_all(reader, timeout=5)

            if not s2_data:
                _LOGGER.warning(
                    "SDK [%s] S2: no response (connection closed after step2)",
                    label,
                )
                return "failed"

            _LOGGER.warning(
                "SDK [%s] S2-RX: %d B: %s",
                label, len(s2_data), s2_data.hex(),
            )
            _hexdump(f"{label}_s2", s2_data)

            # Parse step2 response
            s2_hdr = _parse_header(s2_data)
            _LOGGER.warning("SDK [%s] S2: header=%s", label, s2_hdr)

            # Log non-zero bytes
            nz = [(i, b) for i, b in enumerate(s2_data) if b != 0]
            _LOGGER.warning(
                "SDK [%s] S2: %d non-zero bytes: %s",
                label, len(nz),
                [(f"{o}=0x{v:02x}") for o, v in nz[:30]],
            )

            # === Analyse step2 response ===

            # Generic error = format rejected
            generic_err = bytes.fromhex("000000100000000d0000000d00000000")
            if s2_data[:16] == generic_err:
                _LOGGER.warning("SDK [%s] S2: GENERIC ERROR", label)
                return "failed"

            # Same as step1 = re-challenge (wrong hash, try next)
            if s2_data == s1_data:
                _LOGGER.warning("SDK [%s] S2: same as S1 (wrong hash)", label)
                if len(s2_data) > CHALLENGE_RETRY_OFFSET + 4:
                    new_retries = struct.unpack_from(
                        "<I", s2_data, CHALLENGE_RETRY_OFFSET
                    )[0]
                    _LOGGER.warning(
                        "SDK [%s] S2: retries now=%d (was %d)",
                        label, new_retries, retries,
                    )
                return "failed"

            # Different from step1 = something happened!
            if s2_data != s1_data:
                _LOGGER.warning(
                    "SDK [%s] S2: *** DIFFERENT from S1! *** "
                    "(s1=%d bytes, s2=%d bytes)",
                    label, len(s1_data), len(s2_data),
                )

                # Show byte-level diff
                for i in range(min(len(s1_data), len(s2_data))):
                    if s1_data[i] != s2_data[i]:
                        _LOGGER.warning(
                            "SDK [%s] DIFF: off=%d s1=0x%02x s2=0x%02x",
                            label, i, s1_data[i], s2_data[i],
                        )

                # Check for session ID at offset 12
                if len(s2_data) >= 16:
                    sid = struct.unpack_from("<I", s2_data, 12)[0]
                    if sid != 0:
                        _LOGGER.warning(
                            "SDK [%s] S2: SESSION ID = 0x%08x !!!",
                            label, sid,
                        )
                        self._session_id = sid
                        return "success"

                # Check status
                status = s2_hdr.get("status", 0)
                _LOGGER.warning(
                    "SDK [%s] S2: status=0x%08x", label, status,
                )

                # Retry count change?
                if len(s2_data) > CHALLENGE_RETRY_OFFSET + 4:
                    new_retries = struct.unpack_from(
                        "<I", s2_data, CHALLENGE_RETRY_OFFSET
                    )[0]
                    _LOGGER.warning(
                        "SDK [%s] S2: retries now=%d (was %d)",
                        label, new_retries, retries,
                    )

                return "different"

            return "failed"

        except (OSError, ConnectionError, asyncio.TimeoutError) as err:
            _LOGGER.warning("SDK [%s]: error: %s", label, err)
            return "error"
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Alarm / passive listeners
    # ------------------------------------------------------------------

    def _check_for_alarm(self, data: bytes) -> None:
        """Check for video intercom alarm in data."""
        for off in range(0, len(data) - 1):
            val16 = struct.unpack_from("<H", data, off)[0]
            if val16 == COMM_ALARM_VIDEO_INTERCOM:
                _LOGGER.warning(
                    "SDK: COMM_ALARM_VIDEO_INTERCOM at offset %d!", off,
                )
                if self._on_ring:
                    asyncio.create_task(self._on_ring())
                return

    async def _alarm_listen_loop(self) -> None:
        """Post-login alarm subscription loop."""
        while self._running:
            writer = None
            try:
                reader, writer = await _tcp_open(
                    self._host, self._port, timeout=10
                )
                _LOGGER.warning("SDK: alarm listener connected")

                while self._running:
                    try:
                        data = await asyncio.wait_for(
                            reader.read(8192), timeout=60
                        )
                        if not data:
                            break
                        _LOGGER.warning(
                            "SDK: alarm RX %d B: %s",
                            len(data), data[:128].hex(),
                        )
                        self._check_for_alarm(data)
                    except asyncio.TimeoutError:
                        try:
                            writer.write(_build_header(cmd=0, datalen=0))
                            await writer.drain()
                        except (OSError, ConnectionError):
                            break
            except (OSError, asyncio.TimeoutError) as err:
                _LOGGER.warning("SDK: alarm error: %s", err)
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            if self._running:
                _LOGGER.warning("SDK: reconnecting in 30s ...")
                await asyncio.sleep(30)

    async def _passive_listen_loop(self) -> None:
        """Pre-login: keep connection open, log everything."""
        while self._running:
            writer = None
            try:
                reader, writer = await _tcp_open(
                    self._host, self._port, timeout=10
                )
                _LOGGER.warning(
                    "SDK: passive listener connected to %s:%d",
                    self._host, self._port,
                )

                # Send one probe to trigger the challenge
                writer.write(_build_header(cmd=0, datalen=0))
                await writer.drain()

                # Read the challenge response
                data = await _tcp_read_all(reader, timeout=5)
                if data:
                    _LOGGER.warning(
                        "SDK: passive RX %d B: %s",
                        len(data), data.hex(),
                    )
                    self._check_for_alarm(data)

                    # After challenge, try to read more data (the device
                    # may send events without full login on some models)
                    try:
                        extra = await asyncio.wait_for(
                            reader.read(8192), timeout=30
                        )
                        if extra:
                            _LOGGER.warning(
                                "SDK: passive extra RX %d B: %s",
                                len(extra), extra.hex(),
                            )
                            self._check_for_alarm(extra)
                    except asyncio.TimeoutError:
                        pass
                else:
                    _LOGGER.warning("SDK: passive no data")

            except (OSError, asyncio.TimeoutError) as err:
                _LOGGER.warning("SDK: passive error: %s", err)
            finally:
                if writer:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            if self._running:
                _LOGGER.warning("SDK: reconnecting in 60s ...")
                await asyncio.sleep(60)

    # ------------------------------------------------------------------
    # Main orchestration
    # ------------------------------------------------------------------

    async def connect_and_listen(self) -> None:
        """Run login attempts, then listen loop."""
        _LOGGER.warning(
            "SDK: starting v1.3.4 for %s:%d", self._host, self._port,
        )

        login_ok = await self._run_login_attempts()

        if login_ok:
            _LOGGER.warning(
                "SDK: logged in (session=0x%08x), starting alarm listener",
                self._session_id,
            )
            await self._alarm_listen_loop()
        else:
            _LOGGER.warning("SDK: login failed, entering passive mode")
            await self._passive_listen_loop()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> bool:
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

            if proto._listen_task:
                try:
                    await proto._listen_task
                except (asyncio.CancelledError, Exception):
                    pass

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
