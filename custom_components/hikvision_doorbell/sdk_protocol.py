"""Pure Python Hikvision SDK binary protocol client (v1.3.3).

Key findings from v1.3.2 logs:
  - The 32-byte LE header (8 x uint32) is confirmed correct.
  - A header-only packet (cmd=0, no payload) gets the 127-byte challenge.
  - ANY packet with cleartext credential bytes gets Connection Reset.
  - The 28-byte header from v1.3.1 was structurally wrong (7 fields, not 8).
  - Device has 10 login attempts before lockout; must be conservative.

v1.3.3 strategy:
  - Single TCP connection for all steps (no per-probe fresh connections).
  - Step 1: Send 32-byte header-only to get challenge nonce.
  - Step 2: Send 32-byte header + hashed credentials on SAME connection.
  - Focus on algo byte 0x06 = SHA-256 variants.
  - Password truncated to 16 bytes (SDK limit from NET_DVR_LOGIN_PASSWD_MAX_LEN).
  - Try 5 login flows max (5 connections x 1 attempt each) to preserve attempts.
  - Log everything for analysis.
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

# From the v1.3.2 challenge response analysis:
#   Byte 112:  0x0A = 10 remaining attempts
#   Bytes 116-123: 8-byte challenge salt
#   Byte 124:  0x06 = hash algorithm indicator
CHALLENGE_SALT_OFFSET = 116
CHALLENGE_SALT_LEN = 8
CHALLENGE_ALGO_OFFSET = 124
CHALLENGE_RETRY_OFFSET = 112

# Field sizes in the login payload
USERNAME_LEN = 32   # matches NAME_LEN in SDK
PASSWORD_LEN = 16   # NET_DVR_LOGIN_PASSWD_MAX_LEN

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
    """32-byte LE header (8 x uint32).

    Layout:
      [0:4]   preamble = 0x20
      [4:8]   status (0 in requests)
      [8:12]  command
      [12:16] session ID
      [16:20] extra1
      [20:24] payload length
      [24:28] extra2
      [28:32] extra3
    """
    return struct.pack(
        "<8I",
        HEADER_SIZE,
        status,
        cmd,
        session,
        extra1,
        datalen,
        extra2,
        extra3,
    )


def _parse_header(data: bytes) -> dict:
    """Parse a 32-byte LE response header."""
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


def _hexline(data: bytes, max_bytes: int = 128) -> str:
    """One-line hex representation."""
    trunc = data[:max_bytes]
    return trunc.hex() + ("..." if len(data) > max_bytes else "")


def _hexdump(label: str, data: bytes, max_bytes: int = 256) -> None:
    """Log a hex dump."""
    for i in range(0, min(max_bytes, len(data)), 16):
        chunk = data[i:i + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        _LOGGER.warning("SDK [%s] %04x: %-48s  %s", label, i, hx, asc)


def _nonzero_map(data: bytes) -> list[tuple[int, int]]:
    """Return list of (offset, byte_value) for non-zero bytes."""
    return [(i, b) for i, b in enumerate(data) if b != 0]


# ---------------------------------------------------------------------------
# TCP helpers
# ---------------------------------------------------------------------------


async def _tcp_open(host: str, port: int, timeout: float = 10):
    """Open TCP connection."""
    return await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )


async def _tcp_read(reader, timeout: float = 8) -> bytes:
    """Read all available data from a reader."""
    chunks = []
    read_timeout = timeout
    try:
        while True:
            chunk = await asyncio.wait_for(
                reader.read(8192), timeout=read_timeout
            )
            if not chunk:
                break
            chunks.append(chunk)
            read_timeout = 1.0  # short timeout for subsequent fragments
    except asyncio.TimeoutError:
        pass
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Hash computation for challenge-response
# ---------------------------------------------------------------------------


def _compute_login_hashes(
    password: str, salt: bytes, algo_byte: int
) -> list[tuple[str, bytes]]:
    """Compute candidate hashes for the login challenge.

    The SDK password field is 16 bytes max, so we truncate before hashing.
    algo_byte 0x06 likely means SHA-256 based.

    Returns list of (name, hash_bytes) to try.
    """
    pw = password.encode("utf-8")[:PASSWORD_LEN]
    pw_full = password.encode("utf-8")  # full password for variants

    variants = []

    # SHA-256 variants (most likely for algo=0x06)
    variants.append(("sha256_pw16_salt",
                      hashlib.sha256(pw + salt).digest()))
    variants.append(("sha256_salt_pw16",
                      hashlib.sha256(salt + pw).digest()))
    variants.append(("sha256_sha256pw16_salt",
                      hashlib.sha256(hashlib.sha256(pw).digest() + salt).digest()))
    variants.append(("hmac_sha256_salt_pw16",
                      hmac.new(salt, pw, hashlib.sha256).digest()))
    variants.append(("hmac_sha256_pw16_salt",
                      hmac.new(pw.ljust(PASSWORD_LEN, b"\x00"), salt, hashlib.sha256).digest()))

    # SHA-256 with full (non-truncated) password
    variants.append(("sha256_pwfull_salt",
                      hashlib.sha256(pw_full + salt).digest()))
    variants.append(("hmac_sha256_salt_pwfull",
                      hmac.new(salt, pw_full, hashlib.sha256).digest()))

    # MD5 variants (fallback, in case algo byte interpretation is wrong)
    variants.append(("md5_pw16_salt",
                      hashlib.md5(pw + salt).digest()))
    variants.append(("md5_md5pw16_salt",
                      hashlib.md5(hashlib.md5(pw).digest() + salt).digest()))

    # HMAC-MD5
    variants.append(("hmac_md5_salt_pw16",
                      hmac.new(salt, pw, hashlib.md5).digest()))

    return variants


# ---------------------------------------------------------------------------
# Login flow builder
# ---------------------------------------------------------------------------


def _build_login_payload(
    username: str, hashed_pw: bytes, payload_style: str
) -> bytes:
    """Build the credential payload for the step-2 login packet.

    We try different payload layouts since the exact format is unknown.
    """
    user = username.encode("utf-8")[:USERNAME_LEN].ljust(USERNAME_LEN, b"\x00")

    if payload_style == "user32_hash32":
        # username(32) + hash(32) = 64 bytes
        return user + hashed_pw[:32].ljust(32, b"\x00")

    elif payload_style == "user32_hash16":
        # username(32) + hash(16) = 48 bytes
        return user + hashed_pw[:16].ljust(16, b"\x00")

    elif payload_style == "user32_hash32_pad":
        # username(32) + hash(32) + padding(32) = 96 bytes
        return user + hashed_pw[:32].ljust(32, b"\x00") + b"\x00" * 32

    else:
        return user + hashed_pw[:32].ljust(32, b"\x00")


# ---------------------------------------------------------------------------
# Protocol client
# ---------------------------------------------------------------------------


class HikvisionSDKProtocol:
    """v1.3.3: Single-connection challenge-response login.

    Strategy:
      1. Open one TCP connection
      2. Send header-only packet -> get 127-byte challenge
      3. Extract salt and algo byte
      4. Send header + hashed creds on SAME connection
      5. Analyse response for session / success
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

    async def probe_protocol(self) -> None:
        """Run login attempts with careful resource management."""
        h, p = self._host, self._port

        _LOGGER.warning(
            "SDK: starting v1.3.3 single-connection login for %s:%d", h, p
        )

        # Define login flows to try. Each flow = (hash_name, cmd_for_step2,
        # payload_style). We limit to 5 flows to preserve login attempts.
        #
        # The step-1 always uses cmd=0 (header-only, confirmed to work).
        # For step-2, we try different command values.

        login_flows = [
            # Flow 1: SHA-256(pw16 + salt), step2 cmd=0x0001, 64-byte payload
            ("sha256_pw16_salt", 0x0001, "user32_hash32"),
            # Flow 2: HMAC-SHA256(salt, pw16), step2 cmd=0x0001, 64-byte payload
            ("hmac_sha256_salt_pw16", 0x0001, "user32_hash32"),
            # Flow 3: SHA-256(SHA-256(pw16) + salt), step2 cmd=0x0001, 64-byte payload
            ("sha256_sha256pw16_salt", 0x0001, "user32_hash32"),
            # Flow 4: SHA-256(pw16 + salt), step2 cmd=0x0400, 64-byte payload
            ("sha256_pw16_salt", 0x0400, "user32_hash32"),
            # Flow 5: SHA-256(pw_full + salt), step2 cmd=0x0001, 64-byte payload
            ("sha256_pwfull_salt", 0x0001, "user32_hash32"),
        ]

        for flow_idx, (hash_name, step2_cmd, payload_style) in enumerate(login_flows):
            _LOGGER.warning(
                "SDK LOGIN FLOW %d/%d: hash=%s cmd=0x%04x style=%s",
                flow_idx + 1, len(login_flows), hash_name,
                step2_cmd, payload_style,
            )

            result = await self._try_login_flow(
                hash_name, step2_cmd, payload_style, flow_idx + 1
            )

            if result == "success":
                _LOGGER.warning("SDK: LOGIN SUCCEEDED on flow %d!", flow_idx + 1)
                return
            elif result == "locked":
                _LOGGER.warning("SDK: device appears locked, stopping attempts")
                return
            elif result == "different":
                _LOGGER.warning(
                    "SDK: got a DIFFERENT response on flow %d, analyzing...",
                    flow_idx + 1,
                )
                # Continue to see what other flows produce

        _LOGGER.warning("SDK: all %d login flows exhausted", len(login_flows))

    async def _try_login_flow(
        self,
        hash_name: str,
        step2_cmd: int,
        payload_style: str,
        flow_num: int,
    ) -> str:
        """Execute one complete login flow on a single connection.

        Returns: "success", "failed", "locked", "error", "different"
        """
        h, p = self._host, self._port
        writer = None
        label = f"flow{flow_num}"

        try:
            reader, writer = await _tcp_open(h, p, timeout=10)
            _LOGGER.warning("SDK [%s]: connected to %s:%d", label, h, p)
        except (OSError, asyncio.TimeoutError) as err:
            _LOGGER.warning("SDK [%s]: connect failed: %s", label, err)
            return "error"

        try:
            # --- STEP 1: Header-only probe to get challenge ---
            step1_hdr = _build_header(cmd=0, datalen=0)
            _LOGGER.warning(
                "SDK [%s] STEP1: TX %d B: %s",
                label, len(step1_hdr), step1_hdr.hex(),
            )
            writer.write(step1_hdr)
            await writer.drain()

            s1_resp = await _tcp_read(reader, timeout=8)

            if not s1_resp:
                _LOGGER.warning("SDK [%s] STEP1: no response", label)
                return "error"

            _LOGGER.warning(
                "SDK [%s] STEP1: RX %d B: %s",
                label, len(s1_resp), _hexline(s1_resp),
            )
            _hexdump(f"{label}_s1", s1_resp)

            # Parse the challenge response
            if len(s1_resp) < 125:
                _LOGGER.warning(
                    "SDK [%s] STEP1: response too short (%d bytes) "
                    "for challenge extraction",
                    label, len(s1_resp),
                )
                return "failed"

            # Log all non-zero bytes for analysis
            nz = _nonzero_map(s1_resp)
            _LOGGER.warning(
                "SDK [%s] STEP1: %d non-zero bytes: %s",
                label, len(nz),
                [(f"{o}=0x{v:02x}", v) for o, v in nz],
            )

            # Extract retry count
            retries = struct.unpack_from("<I", s1_resp, CHALLENGE_RETRY_OFFSET)[0]
            _LOGGER.warning("SDK [%s] STEP1: retries remaining = %d", label, retries)

            if retries <= 1:
                _LOGGER.warning(
                    "SDK [%s] STEP1: only %d retries left, aborting to "
                    "avoid lockout",
                    label, retries,
                )
                return "locked"

            # Extract salt
            salt = s1_resp[CHALLENGE_SALT_OFFSET:CHALLENGE_SALT_OFFSET + CHALLENGE_SALT_LEN]
            _LOGGER.warning("SDK [%s] STEP1: salt = %s", label, salt.hex())

            # Extract algo byte
            algo = s1_resp[CHALLENGE_ALGO_OFFSET]
            _LOGGER.warning("SDK [%s] STEP1: algo byte = 0x%02x", label, algo)

            # --- Compute the hash for this flow ---
            all_hashes = _compute_login_hashes(self._password, salt, algo)
            target_hash = None
            for name, hval in all_hashes:
                if name == hash_name:
                    target_hash = hval
                    break

            if target_hash is None:
                _LOGGER.warning("SDK [%s]: hash %s not found", label, hash_name)
                return "error"

            _LOGGER.warning(
                "SDK [%s] HASH: %s = %s",
                label, hash_name, target_hash.hex(),
            )

            # --- STEP 2: Send hashed credentials ---
            payload = _build_login_payload(
                self._username, target_hash, payload_style
            )
            step2_hdr = _build_header(cmd=step2_cmd, datalen=len(payload))
            step2_pkt = step2_hdr + payload

            _LOGGER.warning(
                "SDK [%s] STEP2: TX %d B (hdr=%d + payload=%d): %s",
                label, len(step2_pkt), HEADER_SIZE, len(payload),
                step2_pkt.hex(),
            )
            writer.write(step2_pkt)
            await writer.drain()

            s2_resp = await _tcp_read(reader, timeout=8)

            if not s2_resp:
                _LOGGER.warning("SDK [%s] STEP2: no response (connection may be dead)", label)
                return "failed"

            _LOGGER.warning(
                "SDK [%s] STEP2: RX %d B: %s",
                label, len(s2_resp), _hexline(s2_resp),
            )
            _hexdump(f"{label}_s2", s2_resp)

            # Parse step2 response header
            s2_hdr = _parse_header(s2_resp)
            _LOGGER.warning("SDK [%s] STEP2: header fields: %s", label, s2_hdr)

            # Log non-zero bytes
            nz2 = _nonzero_map(s2_resp)
            _LOGGER.warning(
                "SDK [%s] STEP2: %d non-zero bytes: %s",
                label, len(nz2),
                [(f"{o}=0x{v:02x}", v) for o, v in nz2],
            )

            # Check for generic error
            generic_err = bytes.fromhex("000000100000000d0000000d00000000")
            if s2_resp[:16] == generic_err:
                _LOGGER.warning(
                    "SDK [%s] STEP2: GENERIC ERROR (format rejected)",
                    label,
                )
                return "failed"

            # Check if response is same as step1 (another challenge = wrong hash)
            if s2_resp == s1_resp:
                _LOGGER.warning(
                    "SDK [%s] STEP2: same as step1 (re-challenge, "
                    "hash was wrong)",
                    label,
                )
                return "failed"

            # Check if response has a session (non-zero at offset 12)
            if len(s2_resp) >= 16:
                session_candidate = struct.unpack_from("<I", s2_resp, 12)[0]
                if session_candidate != 0:
                    _LOGGER.warning(
                        "SDK [%s] STEP2: SESSION ID = 0x%08x (%d) !!!",
                        label, session_candidate, session_candidate,
                    )
                    self._session_id = session_candidate
                    return "success"

            # Check status field
            status = s2_hdr.get("status", 0)
            if status == 0x0407:
                _LOGGER.warning(
                    "SDK [%s] STEP2: status 0x0407 = another challenge "
                    "(hash was wrong)",
                    label,
                )
                # Extract new retry count
                if len(s2_resp) > CHALLENGE_RETRY_OFFSET + 4:
                    new_retries = struct.unpack_from(
                        "<I", s2_resp, CHALLENGE_RETRY_OFFSET
                    )[0]
                    _LOGGER.warning(
                        "SDK [%s] STEP2: new retries = %d", label, new_retries
                    )
                return "failed"

            # Check for zero status (possible success with user_id in another field)
            if status == 0:
                _LOGGER.warning(
                    "SDK [%s] STEP2: status=0, checking for user_id...",
                    label,
                )
                # Scan for potential user_id / session in the response
                for off in [4, 8, 12, 16, 20]:
                    if off + 4 <= len(s2_resp):
                        v = struct.unpack_from("<I", s2_resp, off)[0]
                        if v != 0:
                            _LOGGER.warning(
                                "SDK [%s] STEP2: offset %d = 0x%08x (%d)",
                                label, off, v, v,
                            )

            # If we got a different-length response, that's interesting
            if len(s2_resp) != len(s1_resp):
                _LOGGER.warning(
                    "SDK [%s] STEP2: DIFFERENT length! s1=%d s2=%d",
                    label, len(s1_resp), len(s2_resp),
                )
                return "different"

            # Check for any byte difference from step1
            if s2_resp != s1_resp:
                _LOGGER.warning("SDK [%s] STEP2: DIFFERENT content from step1!", label)
                # Show diff positions
                diffs = []
                for i in range(min(len(s1_resp), len(s2_resp))):
                    if s1_resp[i] != s2_resp[i]:
                        diffs.append(
                            f"off={i}: s1=0x{s1_resp[i]:02x} s2=0x{s2_resp[i]:02x}"
                        )
                _LOGGER.warning(
                    "SDK [%s] STEP2: diff positions: %s", label, diffs
                )
                return "different"

            return "failed"

        except (OSError, ConnectionError, asyncio.TimeoutError) as err:
            _LOGGER.warning("SDK [%s]: connection error: %s", label, err)
            return "error"
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # Alarm listener (post-login)
    # ------------------------------------------------------------------

    def _check_for_alarm(self, data: bytes) -> None:
        """Check received data for video intercom alarm."""
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
    # Main orchestration
    # ------------------------------------------------------------------

    async def connect_and_listen(self) -> None:
        """Run login probes, then maintain keepalive connection."""
        _LOGGER.warning(
            "SDK: starting v1.3.3 protocol discovery for %s:%d",
            self._host, self._port,
        )

        await self.probe_protocol()

        if self._session_id:
            _LOGGER.warning(
                "SDK: logged in with session 0x%08x, starting alarm listener",
                self._session_id,
            )
            await self._alarm_listen_loop()
        else:
            _LOGGER.warning(
                "SDK: login not yet achieved, entering passive listen mode"
            )
            await self._passive_listen_loop()

    async def _alarm_listen_loop(self) -> None:
        """Post-login: subscribe to alarms and listen."""
        while self._running:
            writer = None
            try:
                reader, writer = await _tcp_open(
                    self._host, self._port, timeout=10
                )
                _LOGGER.warning("SDK: alarm listener connected")

                # TODO: send alarm subscription command once login works
                # For now, just listen for events
                while self._running:
                    try:
                        data = await asyncio.wait_for(
                            reader.read(8192), timeout=60
                        )
                        if not data:
                            break
                        _LOGGER.warning(
                            "SDK: alarm RX %d B: %s",
                            len(data), _hexline(data),
                        )
                        self._check_for_alarm(data)
                    except asyncio.TimeoutError:
                        # Send keepalive
                        try:
                            writer.write(_build_header(cmd=0, datalen=0))
                            await writer.drain()
                        except (OSError, ConnectionError):
                            break

            except (OSError, asyncio.TimeoutError) as err:
                _LOGGER.warning("SDK: alarm connection error: %s", err)
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
        """Pre-login: keep connection open and monitor for events."""
        while self._running:
            writer = None
            try:
                reader, writer = await _tcp_open(
                    self._host, self._port, timeout=10
                )
                _LOGGER.warning("SDK: passive listener connected to %s:%d",
                                self._host, self._port)

                while self._running:
                    # Send header-only probe
                    try:
                        writer.write(_build_header(cmd=0, datalen=0))
                        await writer.drain()
                    except (OSError, ConnectionError):
                        break

                    try:
                        data = await asyncio.wait_for(
                            reader.read(8192), timeout=60
                        )
                        if not data:
                            _LOGGER.warning("SDK: passive connection closed")
                            break
                        _LOGGER.warning(
                            "SDK: passive RX %d B: %s",
                            len(data), _hexline(data),
                        )
                        self._check_for_alarm(data)
                    except asyncio.TimeoutError:
                        continue

            except (OSError, asyncio.TimeoutError) as err:
                _LOGGER.warning("SDK: passive connection error: %s", err)
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
