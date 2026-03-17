"""Pure Python implementation of the Hikvision SDK binary protocol.

Reverse-engineered from the HCNetSDK native library interface.
Communicates over TCP port 8000 using the Hikvision proprietary binary
protocol to receive real-time alarm events (DOORBELL_RINGING) without
needing the native C libraries.

v1.3.2 findings from v1.3.1 probes:
  - Device speaks LITTLE-ENDIAN.  The preamble 0x20 must be LE
    (bytes: 20 00 00 00), NOT big-endian (00 00 00 20).
  - Every BE-preamble probe returned the generic 16-byte error:
    00 00 00 10  00 00 00 0d  00 00 00 0d  00 00 00 00
    (size=16, err=13, suberr=13 -> "unrecognised format")
  - loginC (LE struct header + plaintext creds) returned a 127-byte
    response with challenge/salt bytes at the end.  This is the
    format to build on.
  - The NMAP_PROBE in v1.3.1 was a bug: Python implicit string
    concatenation turned it into 162 bytes instead of 32.

Protocol (LE, 32-byte header):
  Offset  Size  Field
  0       4     dwHeaderLen   always 0x20 (32)
  4       4     (varies)      error-code in response, flags in request
  8       4     dwCommand     command ID
  12      4     dwSessionID   0 for login
  16      4     (varies)      sub-command?
  20      4     dwPayloadLen  length of data after header
  24      4     reserved
  28      4     reserved
"""

import asyncio
import hashlib
import hmac
import logging
import struct
from typing import Callable, Coroutine

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

DEFAULT_SDK_PORT = 8000
HEADER_SIZE = 32

# Correct Nmap Hikvision probe: exactly 32 bytes.
# Preamble 0x20 in BIG-ENDIAN (Nmap standard), cmd=0x63.
# Note: the device returned a generic error for this (it wants LE),
# but we keep it for reference alongside the LE version.
NMAP_PROBE_BE = b"\x00\x00\x00\x20\x63" + b"\x00" * 27  # 32 bytes

# LE version of the Nmap probe (preamble 0x20 in little-endian)
NMAP_PROBE_LE = struct.pack("<8I", 0x20, 0, 0x63, 0, 0, 0, 0, 0)  # 32 bytes

# The LE header format that worked in v1.3.1 probes.
# struct.pack("<I I I I HH I I", 0x20, session, seq, 0, cmd, ver, datalen, 0)
# This is a 28-byte header; the device reads 32, so last 4 bytes spills.
# For v1.3.2 we use a proper 32-byte header (8 x uint32).

# Alarm commands
COMM_ALARM_V30 = 0x4000
COMM_ALARM_VIDEO_INTERCOM = 0x1133
COMM_UPLOAD_VIDEO_INTERCOM_EVENT = 0x1132
COMM_ISAPI_ALARM = 0x6009
COMM_ALARM_ACS = 0x5002

# Video intercom alarm types
ALARM_TYPE_DOORBELL_RINGING = 17
ALARM_TYPE_DISMISS_INCOMING_CALL = 18

# Credential field sizes
SERIALNO_LEN = 48
NAME_LEN = 32
PASS_LEN = 16  # some variants use 16-byte password field


class HikvisionSDKError(Exception):
    """Error in the SDK protocol communication."""


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _build_header(
    cmd: int,
    datalen: int,
    session: int = 0,
    status: int = 0,
    extra1: int = 0,
    extra2: int = 0,
    extra3: int = 0,
) -> bytes:
    """Build a 32-byte LE header (8 x uint32).

    Layout based on v1.3.1 discovery (loginC success):
      [0:4]   0x20  (header size / preamble, always 32)
      [4:8]   status/flags (0 for requests)
      [8:12]  command
      [12:16] session ID (0 for login)
      [16:20] extra1 (sub-command?)
      [20:24] payload length
      [24:28] extra2
      [28:32] extra3
    """
    return struct.pack(
        "<8I",
        HEADER_SIZE,  # 0x20
        status,
        cmd,
        session,
        extra1,
        datalen,
        extra2,
        extra3,
    )


def _parse_response_header(data: bytes) -> dict:
    """Parse first 32 bytes of a response as LE uint32 words."""
    if len(data) < 4:
        return {"raw_len": len(data)}
    fields = {}
    names = [
        "preamble", "status", "command", "session",
        "extra1", "payload_len", "extra2", "extra3",
    ]
    for i, name in enumerate(names):
        off = i * 4
        if off + 4 <= len(data):
            fields[name] = struct.unpack_from("<I", data, off)[0]
    return fields


async def _open_tcp(host: str, port: int, timeout: float = 10):
    """Open a new TCP connection."""
    return await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )


async def _send_recv(
    host: str, port: int, data: bytes, timeout: float = 8, label: str = ""
) -> bytes | None:
    """Open a FRESH TCP connection, send data, read response, close."""
    writer = None
    try:
        reader, writer = await _open_tcp(host, port, timeout=10)
    except (OSError, asyncio.TimeoutError) as err:
        _LOGGER.warning("SDK [%s]: TCP connect failed: %s", label, err)
        return None

    try:
        _LOGGER.warning("SDK [%s]: TX %d B: %s", label, len(data), data.hex())
        writer.write(data)
        await writer.drain()

        # Read all available data (some responses >128 bytes)
        chunks = []
        try:
            while True:
                chunk = await asyncio.wait_for(
                    reader.read(8192), timeout=timeout
                )
                if not chunk:
                    break
                chunks.append(chunk)
                # Short timeout for additional fragments
                timeout = 1.0
        except asyncio.TimeoutError:
            pass

        response = b"".join(chunks)
        if response:
            _LOGGER.warning(
                "SDK [%s]: RX %d B: %s", label, len(response), response.hex()
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


async def _send_recv_multi(
    host: str,
    port: int,
    packets: list[bytes],
    timeout: float = 8,
    label: str = "",
) -> list[bytes]:
    """Send multiple packets on ONE connection, reading after each.

    Used for multi-step handshakes (challenge-response).
    """
    writer = None
    responses: list[bytes] = []
    try:
        reader, writer = await _open_tcp(host, port, timeout=10)
    except (OSError, asyncio.TimeoutError) as err:
        _LOGGER.warning("SDK [%s]: TCP connect failed: %s", label, err)
        return responses

    try:
        for idx, pkt in enumerate(packets):
            step = f"{label}_step{idx}"
            _LOGGER.warning(
                "SDK [%s]: TX %d B: %s", step, len(pkt), pkt.hex()
            )
            writer.write(pkt)
            await writer.drain()

            chunks = []
            try:
                while True:
                    chunk = await asyncio.wait_for(
                        reader.read(8192), timeout=timeout
                    )
                    if not chunk:
                        break
                    chunks.append(chunk)
                    timeout = 1.0
            except asyncio.TimeoutError:
                pass

            resp = b"".join(chunks)
            if resp:
                _LOGGER.warning(
                    "SDK [%s]: RX %d B: %s", step, len(resp), resp.hex()
                )
            else:
                _LOGGER.warning("SDK [%s]: empty response", step)

            responses.append(resp)
            # Reset timeout for next step
            timeout = 8

    except (OSError, ConnectionError) as err:
        _LOGGER.warning("SDK [%s]: error: %s", label, err)
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    return responses


def _hexdump(label: str, data: bytes, max_bytes: int = 256) -> None:
    """Log a classic hex dump."""
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

    v1.3.2: Focused probing based on v1.3.1 discoveries.

    The device speaks LITTLE-ENDIAN with a 32-byte header starting with
    0x00000020 (LE).  loginC format (LE struct + plaintext creds) got a
    127-byte response with challenge data, confirming the header layout
    and suggesting a V40 challenge-response login flow.
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
    # Phase 1: Confirm LE format + map header fields
    # ------------------------------------------------------------------

    async def probe_protocol(self) -> dict[str, bytes]:
        """Targeted probes based on v1.3.1 findings."""

        results: dict[str, bytes] = {}
        h, p = self._host, self._port

        user_bytes = self._username.encode("utf-8")[:NAME_LEN].ljust(
            NAME_LEN, b"\x00"
        )
        pass_bytes = self._password.encode("utf-8")[:NAME_LEN].ljust(
            NAME_LEN, b"\x00"
        )
        creds = user_bytes + pass_bytes  # 64 bytes

        # ---------------------------------------------------------------
        # Group 1: Confirm the correct Nmap probe (fixed 32-byte version)
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK PROBE G1: Nmap probes (BE vs LE) %s:%d", h, p)

        resp = await _send_recv(h, p, NMAP_PROBE_BE, 8, "nmap_BE")
        if resp:
            results["nmap_BE"] = resp
            _hexdump("nmap_BE_resp", resp)

        resp = await _send_recv(h, p, NMAP_PROBE_LE, 8, "nmap_LE")
        if resp:
            results["nmap_LE"] = resp
            _hexdump("nmap_LE_resp", resp)

        # ---------------------------------------------------------------
        # Group 2: Reproduce the loginC success with proper 32-byte header
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK PROBE G2: LE login with 32-byte header %s:%d", h, p)

        # 2a: The EXACT loginC from v1.3.1 (28-byte header, the one
        #     that got the 127-byte response)
        hdr_28 = struct.pack(
            "<I I I I HH I I",
            0x20, 0, 1, 0, 0x0001, 0x0000, len(creds), 0,
        )
        resp = await _send_recv(h, p, hdr_28 + creds, 8, "loginC_repro_28B")
        if resp:
            results["loginC_repro"] = resp
            _hexdump("loginC_repro_resp", resp, 256)
            self._analyse_login_response("loginC_repro", resp)

        # 2b: Proper 32-byte header (8 x uint32).
        # Put command at different offsets to discover the real layout.

        # Layout A: cmd at offset 8
        hdr = _build_header(cmd=0x0001, datalen=len(creds))
        resp = await _send_recv(h, p, hdr + creds, 8, "login32_cmdOff8")
        if resp:
            results["login32_cmdOff8"] = resp
            _hexdump("login32_cmdOff8_resp", resp, 256)
            self._analyse_login_response("login32_cmdOff8", resp)

        # Layout B: cmd at offset 4 (swap status and command)
        hdr = struct.pack("<8I", 0x20, 0x0001, 0, 0, 0, len(creds), 0, 0)
        resp = await _send_recv(h, p, hdr + creds, 8, "login32_cmdOff4")
        if resp:
            results["login32_cmdOff4"] = resp
            _hexdump("login32_cmdOff4_resp", resp, 256)
            self._analyse_login_response("login32_cmdOff4", resp)

        # Layout C: cmd at offset 16
        hdr = struct.pack("<8I", 0x20, 0, 0, 0, 0x0001, len(creds), 0, 0)
        resp = await _send_recv(h, p, hdr + creds, 8, "login32_cmdOff16")
        if resp:
            results["login32_cmdOff16"] = resp
            _hexdump("login32_cmdOff16_resp", resp, 256)
            self._analyse_login_response("login32_cmdOff16", resp)

        # ---------------------------------------------------------------
        # Group 3: Header-only probes (no payload) in LE to test commands
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK PROBE G3: header-only LE commands %s:%d", h, p)

        for cmd_val in (0x0000, 0x0001, 0x0002, 0x0003, 0x0050,
                        0x0063, 0x0400, 0x0401, 0x0407, 0x0800,
                        0x1100, 0x1132, 0x1133):
            hdr = _build_header(cmd=cmd_val, datalen=0)
            lbl = f"hdr_cmd0x{cmd_val:04x}"
            resp = await _send_recv(h, p, hdr, 5, lbl)
            if resp:
                results[lbl] = resp
                hfields = _parse_response_header(resp)
                _LOGGER.warning(
                    "SDK [%s]: parsed header: %s", lbl, hfields
                )
                if resp != bytes.fromhex("000000100000000d0000000d00000000"):
                    _hexdump(f"{lbl}_resp", resp, 256)

        # ---------------------------------------------------------------
        # Group 4: Username-only login (V40 challenge-response step 1)
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK PROBE G4: username-only V40 step1 %s:%d", h, p)

        # 4a: 32-byte header + username only (32 bytes)
        hdr = _build_header(cmd=0x0001, datalen=len(user_bytes))
        resp = await _send_recv(h, p, hdr + user_bytes, 8, "v40_user_only_32")
        if resp:
            results["v40_user_only_32"] = resp
            _hexdump("v40_user_only_32_resp", resp, 256)
            self._analyse_login_response("v40_user_only_32", resp)

        # 4b: Username-only with NET_DVR_USER_LOGIN_INFO-like struct
        # sDeviceAddress(129) + padding(1) + wPort(2) + sUserName(64) +
        # sPassword(64) + BOOL bUseAsynLogin(4) + byLoginMode(1) + ...
        addr = self._host.encode("utf-8")[:129].ljust(129, b"\x00")
        login_struct = (
            addr
            + b"\x00"  # byUseTransport
            + struct.pack("<H", self._port)  # wPort
            + self._username.encode("utf-8")[:64].ljust(64, b"\x00")
            + b"\x00" * 64  # sPassword (empty for step 1)
            + struct.pack("<I", 0)  # bUseAsynLogin = 0
            + b"\x00"  # byLoginMode = 0 (SDK private)
            + b"\x00"  # byHttps
            + b"\x00" * 2  # padding
        )
        hdr = _build_header(cmd=0x0001, datalen=len(login_struct))
        resp = await _send_recv(h, p, hdr + login_struct, 8, "v40_loginstruct")
        if resp:
            results["v40_loginstruct"] = resp
            _hexdump("v40_loginstruct_resp", resp, 256)
            self._analyse_login_response("v40_loginstruct", resp)

        # ---------------------------------------------------------------
        # Group 5: Challenge-response using loginC salt bytes
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK PROBE G5: challenge-response login %s:%d", h, p)

        # First, re-do loginC to get fresh challenge bytes
        challenge_resp = await _send_recv(
            h, p, hdr_28 + creds, 8, "loginC_for_challenge"
        )
        if challenge_resp and len(challenge_resp) >= 124:
            await self._try_challenge_response(challenge_resp, results)

        # ---------------------------------------------------------------
        # Group 6: Vary the header field that was 'seq=1' in loginC
        #   to see if that field affects the response
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK PROBE G6: field variation probes %s:%d", h, p)

        # In the original loginC, struct.pack had seq=1 at offset 8.
        # Our 32-byte header puts cmd at offset 8.  Try different
        # command values to see which gives different responses.
        for cmd_val in (0x0001, 0x0002, 0x0050, 0x0100, 0x0400,
                        0x0401, 0x0402, 0x0403, 0x0407):
            hdr = _build_header(cmd=cmd_val, datalen=len(creds))
            lbl = f"login32_cmd0x{cmd_val:04x}"
            resp = await _send_recv(h, p, hdr + creds, 8, lbl)
            if resp:
                results[lbl] = resp
                hfields = _parse_response_header(resp)
                _LOGGER.warning("SDK [%s]: header: %s", lbl, hfields)
                if resp != bytes.fromhex("000000100000000d0000000d00000000"):
                    _hexdump(f"{lbl}_resp", resp, 256)
                    self._analyse_login_response(lbl, resp)

        return results

    # ------------------------------------------------------------------
    # Challenge-response helpers
    # ------------------------------------------------------------------

    async def _try_challenge_response(
        self, step1_resp: bytes, results: dict[str, bytes]
    ) -> None:
        """Use the salt from a login response to attempt challenge-response."""
        h, p = self._host, self._port

        # Extract potential challenge/salt bytes from the response
        # From v1.3.1 logs, non-zero data at offsets 112-126:
        #   112: 0a 00 00 00  (possibly retry count = 10)
        #   116: e8 e1 aa b5  (salt part 1)
        #   120: 98 e3 aa b5  (salt part 2)
        #   124: 06 00 00     (hash algo indicator?)

        # Log where all non-zero bytes are
        _LOGGER.warning("SDK CHALLENGE: scanning response for non-zero bytes:")
        for i in range(len(step1_resp)):
            if step1_resp[i] != 0:
                _LOGGER.warning(
                    "SDK CHALLENGE: offset %d (0x%02x): byte=0x%02x (%d)",
                    i, i, step1_resp[i], step1_resp[i],
                )

        # Extract the salt (8 bytes at offset 116-123)
        if len(step1_resp) >= 124:
            salt_8 = step1_resp[116:124]
            _LOGGER.warning("SDK CHALLENGE: salt_8 = %s", salt_8.hex())
        else:
            salt_8 = b"\x00" * 8
            _LOGGER.warning("SDK CHALLENGE: response too short for salt")

        # Extract potential hash algo indicator
        algo_byte = step1_resp[124] if len(step1_resp) > 124 else 0
        _LOGGER.warning("SDK CHALLENGE: algo indicator byte = 0x%02x", algo_byte)

        # Also try extracting salt from different offsets in case
        # the header is larger/smaller than expected
        salt_candidates = {
            "salt_116_8B": step1_resp[116:124] if len(step1_resp) >= 124 else b"",
            "salt_112_8B": step1_resp[112:120] if len(step1_resp) >= 120 else b"",
            "salt_108_16B": step1_resp[108:124] if len(step1_resp) >= 124 else b"",
        }
        for name, salt in salt_candidates.items():
            if salt:
                _LOGGER.warning("SDK CHALLENGE: %s = %s", name, salt.hex())

        pw = self._password.encode("utf-8")
        user = self._username.encode("utf-8")

        # Try multiple hash computations with the 8-byte salt
        hash_variants: list[tuple[str, bytes]] = []

        # MD5 variants
        hash_variants.append(("md5_pw_salt", hashlib.md5(pw + salt_8).digest()))
        hash_variants.append(("md5_salt_pw", hashlib.md5(salt_8 + pw).digest()))
        hash_variants.append(("md5_user_pw_salt",
                              hashlib.md5(user + pw + salt_8).digest()))
        hash_variants.append(("md5_pw", hashlib.md5(pw).digest()))

        # SHA-256 variants
        hash_variants.append(("sha256_pw_salt",
                              hashlib.sha256(pw + salt_8).digest()))
        hash_variants.append(("sha256_salt_pw",
                              hashlib.sha256(salt_8 + pw).digest()))

        # HMAC variants
        hash_variants.append(("hmac_md5_salt_pw",
                              hmac.new(salt_8, pw, hashlib.md5).digest()))
        hash_variants.append(("hmac_sha256_salt_pw",
                              hmac.new(salt_8, pw, hashlib.sha256).digest()))

        # Double-hash: MD5(MD5(password) + salt) - common pattern
        pw_md5 = hashlib.md5(pw).digest()
        hash_variants.append(("md5_md5pw_salt",
                              hashlib.md5(pw_md5 + salt_8).digest()))

        # MD5 hex-string + salt
        pw_md5_hex = hashlib.md5(pw).hexdigest().encode("ascii")
        hash_variants.append(("md5_hexmd5pw_salt",
                              hashlib.md5(pw_md5_hex + salt_8).digest()))

        _LOGGER.warning(
            "SDK CHALLENGE: trying %d hash variants",
            len(hash_variants),
        )

        user_bytes = user[:NAME_LEN].ljust(NAME_LEN, b"\x00")

        for hash_name, hashed_pw in hash_variants:
            # Build credentials: username(32) + hashed_password(32)
            hashed_creds = user_bytes + hashed_pw.ljust(NAME_LEN, b"\x00")

            # Use the same 28-byte header that worked in loginC
            hdr = struct.pack(
                "<I I I I HH I I",
                0x20, 0, 1, 0, 0x0001, 0x0000, len(hashed_creds), 0,
            )

            lbl = f"cr_{hash_name}"
            resp = await _send_recv(h, p, hdr + hashed_creds, 8, lbl)
            if resp:
                results[lbl] = resp
                hfields = _parse_response_header(resp)
                _LOGGER.warning("SDK [%s]: header: %s", lbl, hfields)
                if resp != bytes.fromhex("000000100000000d0000000d00000000"):
                    _hexdump(f"{lbl}_resp", resp, 256)
                    self._analyse_login_response(lbl, resp)

        # ---------------------------------------------------------------
        # Also try the two-step flow on a SINGLE connection:
        # Step 1: send login with password-empty -> get challenge
        # Step 2: send login with hashed password -> get session
        # ---------------------------------------------------------------
        _LOGGER.warning("SDK CHALLENGE: two-step flow on single connection")

        # Step 1 packet: username + empty password
        empty_creds = user_bytes + b"\x00" * NAME_LEN
        step1_pkt = struct.pack(
            "<I I I I HH I I",
            0x20, 0, 1, 0, 0x0001, 0x0000, len(empty_creds), 0,
        ) + empty_creds

        # We'll send step1 and then compute step2 from the response
        writer = None
        try:
            reader, writer = await _open_tcp(h, p, timeout=10)
            _LOGGER.warning("SDK [2step]: connected, sending step1")
            writer.write(step1_pkt)
            await writer.drain()

            # Read step1 response
            chunks = []
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=8)
                    if not chunk:
                        break
                    chunks.append(chunk)
            except asyncio.TimeoutError:
                pass

            s1_resp = b"".join(chunks)
            _LOGGER.warning(
                "SDK [2step]: step1 RX %d B: %s",
                len(s1_resp), s1_resp.hex() if s1_resp else "(empty)",
            )

            if s1_resp and len(s1_resp) >= 124:
                _hexdump("2step_s1", s1_resp, 256)
                # Extract fresh salt
                fresh_salt = s1_resp[116:124]
                _LOGGER.warning(
                    "SDK [2step]: fresh salt = %s", fresh_salt.hex()
                )

                # Try step 2 with each hash on the SAME connection
                for hash_name, hash_fn in [
                    ("md5_pw_salt", lambda: hashlib.md5(pw + fresh_salt).digest()),
                    ("md5_salt_pw", lambda: hashlib.md5(fresh_salt + pw).digest()),
                    ("md5_md5pw_salt", lambda: hashlib.md5(
                        hashlib.md5(pw).digest() + fresh_salt).digest()),
                    ("sha256_pw_salt", lambda: hashlib.sha256(
                        pw + fresh_salt).digest()),
                ]:
                    hashed = hash_fn()
                    step2_creds = user_bytes + hashed.ljust(NAME_LEN, b"\x00")
                    step2_pkt = struct.pack(
                        "<I I I I HH I I",
                        0x20, 0, 2, 0, 0x0001, 0x0000,
                        len(step2_creds), 0,
                    ) + step2_creds

                    _LOGGER.warning(
                        "SDK [2step_%s]: TX %d B: %s",
                        hash_name, len(step2_pkt), step2_pkt.hex(),
                    )
                    writer.write(step2_pkt)
                    await writer.drain()

                    chunks2 = []
                    try:
                        while True:
                            chunk = await asyncio.wait_for(
                                reader.read(8192), timeout=5
                            )
                            if not chunk:
                                break
                            chunks2.append(chunk)
                    except asyncio.TimeoutError:
                        pass

                    s2_resp = b"".join(chunks2)
                    _LOGGER.warning(
                        "SDK [2step_%s]: RX %d B: %s",
                        hash_name,
                        len(s2_resp),
                        s2_resp.hex() if s2_resp else "(empty)",
                    )
                    if s2_resp:
                        results[f"2step_{hash_name}"] = s2_resp
                        _hexdump(f"2step_{hash_name}_resp", s2_resp, 256)
                        self._analyse_login_response(
                            f"2step_{hash_name}", s2_resp
                        )
                        # Check if this response is different from step1
                        if s2_resp != s1_resp:
                            _LOGGER.warning(
                                "SDK [2step_%s]: *** DIFFERENT response! ***",
                                hash_name,
                            )
                    else:
                        _LOGGER.warning(
                            "SDK [2step_%s]: no response (connection may "
                            "have closed)", hash_name,
                        )
                        break  # Connection dead, no point continuing

        except (OSError, ConnectionError, asyncio.TimeoutError) as err:
            _LOGGER.warning("SDK [2step]: error: %s", err)
        finally:
            if writer:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        return

    # ------------------------------------------------------------------
    # Response analysis
    # ------------------------------------------------------------------

    def _analyse_login_response(self, label: str, data: bytes) -> None:
        """Deep analysis of a login response."""
        if len(data) < 16:
            return

        # Parse as LE header
        hfields = _parse_response_header(data)
        _LOGGER.warning("SDK [%s] ANALYSIS: header fields: %s", label, hfields)

        # Check if this is the generic error or a real response
        generic_err = bytes.fromhex("000000100000000d0000000d00000000")
        if data[:16] == generic_err:
            _LOGGER.warning("SDK [%s] ANALYSIS: generic error (format rejected)", label)
            return

        _LOGGER.warning(
            "SDK [%s] ANALYSIS: *** NON-ERROR response (%d bytes) ***",
            label, len(data),
        )

        # Scan ALL non-zero bytes
        nonzero = []
        for i in range(len(data)):
            if data[i] != 0:
                nonzero.append((i, data[i]))
        _LOGGER.warning(
            "SDK [%s] ANALYSIS: non-zero bytes (%d total): %s",
            label,
            len(nonzero),
            [(f"off={o}:0x{v:02x}", v) for o, v in nonzero],
        )

        # Try to find ASCII strings
        import re
        text = data.decode("ascii", errors="replace")
        strings = re.findall(r"[\x20-\x7e]{4,}", text)
        if strings:
            _LOGGER.warning(
                "SDK [%s] ANALYSIS: ASCII strings: %s", label, strings
            )

        # Look for serial number (48 bytes of digits)
        for off in (0, 4, 8, 32, 36):
            if off + SERIALNO_LEN <= len(data):
                chunk = data[off:off + SERIALNO_LEN]
                digits = sum(1 for b in chunk if 0x30 <= b <= 0x39)
                if digits > 8:
                    _LOGGER.warning(
                        "SDK [%s] ANALYSIS: possible serial at offset %d: %s",
                        label, off,
                        chunk.rstrip(b"\x00").decode("ascii", errors="replace"),
                    )

        # Check for NET_DVR_DEVICEINFO_V30 wDevType at common offsets
        for off in (48 + 11, 60, 62, 80 + 11):
            if off + 2 <= len(data):
                wdt = struct.unpack_from("<H", data, off)[0]
                if wdt in (602, 603, 605, 896, 31, 861, 10503, 10509, 10510):
                    _LOGGER.warning(
                        "SDK [%s] ANALYSIS: wDevType=%d at offset %d "
                        "(known Hikvision type!)",
                        label, wdt, off,
                    )

        # If the response contains a potential session_id (non-zero at offset 4)
        if "status" in hfields and hfields["status"] != 0:
            _LOGGER.warning(
                "SDK [%s] ANALYSIS: status/session? = 0x%08x (%d)",
                label, hfields["status"], hfields["status"],
            )

    # ------------------------------------------------------------------
    # Main orchestration
    # ------------------------------------------------------------------

    async def connect_and_listen(self) -> None:
        """Run targeted probes then keep a connection open for events."""
        _LOGGER.warning(
            "SDK: starting v1.3.2 protocol discovery for %s:%d",
            self._host, self._port,
        )

        probe_results = await self.probe_protocol()

        responding = [k for k, v in probe_results.items() if v]
        non_error = [
            k for k, v in probe_results.items()
            if v and v != bytes.fromhex("000000100000000d0000000d00000000")
        ]

        _LOGGER.warning(
            "SDK: discovery complete. %d responded, %d non-error: %s",
            len(responding), len(non_error), non_error,
        )

        # Stay connected with periodic keepalives using the LE probe
        await self._le_keepalive_loop()

    async def _le_keepalive_loop(self) -> None:
        """Persistent connection using LE headers for keepalive."""
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
                    # Send an LE header-only probe as keepalive
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
                            _LOGGER.warning("SDK: connection closed by device")
                            break
                        _LOGGER.warning(
                            "SDK: RX %d B: %s", len(data), data[:128].hex()
                        )
                        self._check_for_alarm(data)
                    except asyncio.TimeoutError:
                        _LOGGER.debug("SDK: 60s silence, sending keepalive")
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
                _LOGGER.warning("SDK: reconnecting in 30s ...")
                await asyncio.sleep(30)

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

            await proto.stop()
            self._protocol = None

            if self._running:
                _LOGGER.warning(
                    "SDK: reconnecting in %ds ...", self._reconnect_interval
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
