"""Hikvision HCNetSDK wrapper for native event detection via ctypes.

This module provides Python bindings for the Hikvision Device Network SDK,
using only the functions needed for doorbell ring detection:
- SDK initialization and cleanup
- Device login/logout
- Alarm callback registration
- Alarm channel subscription

The struct definitions match the Hikvision SDK C headers.
"""

import ctypes
import logging
import os
import platform
from ctypes import (
    CDLL,
    CFUNCTYPE,
    POINTER,
    Structure,
    Union,
    c_bool,
    c_byte,
    c_char,
    c_char_p,
    c_int,
    c_long,
    c_short,
    c_uint,
    c_ulong,
    c_ushort,
    c_void_p,
    cdll,
    sizeof,
)

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases matching Hikvision SDK C headers
# ---------------------------------------------------------------------------
BOOL = c_bool
WORD = c_ushort
LONG = c_long
BYTE = c_byte
SHORT = c_short
DWORD = c_uint if sizeof(c_ulong) != 4 else c_ulong
char = c_char

# ---------------------------------------------------------------------------
# Size constants from SDK headers
# ---------------------------------------------------------------------------
SERIALNO_LEN = 48
NAME_LEN = 32
MACADDR_LEN = 6
MAX_DEV_NUMBER_LEN = 32
MAX_ALARMOUT_V30 = 96   # MAX_ANALOG_ALARM_OUT + MAX_IP_ALARM_OUT
MAX_CHANNUM_V30 = 64    # MAX_ANALOG_CHANNUM + MAX_IP_CHANNUM
MAX_DISKNUM_V30 = 33

# ---------------------------------------------------------------------------
# SDK command constants (alarm callback command parameter)
# ---------------------------------------------------------------------------
COMM_ALARM_V30 = 0x4000
COMM_UPLOAD_VIDEO_INTERCOM_EVENT = 0x1132
COMM_ALARM_VIDEO_INTERCOM = 0x1133
COMM_ISAPI_ALARM = 0x6009
COMM_ALARM_ACS = 0x5002

# ---------------------------------------------------------------------------
# Video intercom alarm types (byAlarmType field)
# ---------------------------------------------------------------------------
ALARM_DOORBELL_RINGING = 17
ALARM_DISMISS_INCOMING_CALL = 18

# Motion detection alarm type (dwAlarmType in ALARMINFO_V30)
ALARM_MOTION_DETECTION = 3

# ---------------------------------------------------------------------------
# Struct definitions
# ---------------------------------------------------------------------------


class NET_DVR_TIME_EX(Structure):
    """Timestamp used in alarm structures."""
    _fields_ = [
        ("wYear", WORD),
        ("byMonth", BYTE),
        ("byDay", BYTE),
        ("byHour", BYTE),
        ("byMinute", BYTE),
        ("bySecond", BYTE),
        ("byRes", BYTE),
    ]


class NET_DVR_DEVICEINFO_V30(Structure):
    """Device info returned by NET_DVR_Login_V30."""
    _fields_ = [
        ("sSerialNumber", BYTE * SERIALNO_LEN),
        ("byAlarmInPortNum", BYTE),
        ("byAlarmOutPortNum", BYTE),
        ("byDiskNum", BYTE),
        ("byDVRType", BYTE),
        ("byChanNum", BYTE),
        ("byStartChan", BYTE),
        ("byAudioChanNum", BYTE),
        ("byIPChanNum", BYTE),
        ("byZeroChanNum", BYTE),
        ("byMainProto", BYTE),
        ("bySubProto", BYTE),
        ("bySupport", BYTE),
        ("bySupport1", BYTE),
        ("bySupport2", BYTE),
        ("wDevType", WORD),
        ("bySupport3", BYTE),
        ("byMultiStreamProto", BYTE),
        ("byStartDChan", BYTE),
        ("byStartDTalkChan", BYTE),
        ("byHighDChanNum", BYTE),
        ("bySupport4", BYTE),
        ("byLanguageType", BYTE),
        ("byVoiceInChanNum", BYTE),
        ("byStartVoiceInChanNo", BYTE),
        ("byRes3", BYTE * 2),
        ("byMirrorChanNum", BYTE),
        ("wStartMirrorChanNo", WORD),
    ]

    def serial_number(self) -> str:
        """Return serial number as string, stripping trailing zeros."""
        return "".join(str(b) for b in self.sSerialNumber if b != 0)


class NET_DVR_ALARMER(Structure):
    """Device info passed to alarm callbacks."""
    _fields_ = [
        ("byUserIDValid", BYTE),
        ("bySerialValid", BYTE),
        ("byVersionValid", BYTE),
        ("byDeviceNameValid", BYTE),
        ("byMacAddrValid", BYTE),
        ("byLinkPortValid", BYTE),
        ("byDeviceIPValid", BYTE),
        ("bySocketIPValid", BYTE),
        ("lUserID", LONG),
        ("sSerialNumber", BYTE * SERIALNO_LEN),
        ("dwDeviceVersion", DWORD),
        ("sDeviceName", char * NAME_LEN),
        ("byMacAddr", BYTE * MACADDR_LEN),
        ("wLinkPort", WORD),
        ("sDeviceIP", char * 128),
        ("sSocketIP", char * 128),
        ("byIpProtocol", BYTE),
        ("byRes2", BYTE * 6),
    ]

    def serial_number(self) -> str:
        """Return serial number as string, stripping trailing zeros."""
        return "".join(str(b) for b in self.sSerialNumber if b != 0)

    def device_ip(self) -> str:
        return self.sDeviceIP.decode("utf-8", errors="replace").rstrip("\x00")


# --- Alarm info structures ---

class NET_DVR_ALARMINFO_V30(Structure):
    """Generic alarm info (motion detection, etc.)."""
    _fields_ = [
        ("dwAlarmType", DWORD),
        ("dwAlarmInputNumber", DWORD),
        ("byAlarmOutputNumber", BYTE * MAX_ALARMOUT_V30),
        ("byAlarmRelateChannel", BYTE * MAX_CHANNUM_V30),
        ("byChannel", BYTE * MAX_CHANNUM_V30),
        ("byDiskNumber", BYTE * MAX_DISKNUM_V30),
    ]


class NET_DVR_ZONE_ALARM_INFO(Structure):
    _fields_ = [
        ("byZoneName", BYTE * NAME_LEN),
        ("dwZoneIndex", DWORD),
        ("byZoneType", BYTE),
        ("byRes", BYTE * 219),
    ]


class NET_DVR_VIDEO_INTERCOM_ALARM_INFO_UNION(Union):
    _fields_ = [
        ("byLen", BYTE * 256),
        ("struZoneAlarm", NET_DVR_ZONE_ALARM_INFO),
    ]


class NET_DVR_VIDEO_INTERCOM_ALARM(Structure):
    """Video intercom alarm event (includes doorbell ringing)."""
    _fields_ = [
        ("dwSize", DWORD),
        ("struTime", NET_DVR_TIME_EX),
        ("byDevNumber", BYTE * MAX_DEV_NUMBER_LEN),
        ("byAlarmType", BYTE),
        ("byRes1", BYTE * 3),
        ("uAlarmInfo", NET_DVR_VIDEO_INTERCOM_ALARM_INFO_UNION),
        ("wLockID", BYTE),
        ("byRes2", BYTE),
    ]


class NET_DVR_VIDEO_INTERCOM_EVENT_INFO_UNION(Union):
    _fields_ = [
        ("byLen", BYTE * 256),
    ]


class NET_DVR_VIDEO_INTERCOM_EVENT(Structure):
    """Video intercom event (unlock log, etc.)."""
    _fields_ = [
        ("dwSize", DWORD),
        ("struTime", NET_DVR_TIME_EX),
        ("byDevNumber", BYTE * MAX_DEV_NUMBER_LEN),
        ("byEventType", BYTE),
        ("byRes1", BYTE * 3),
        ("uEventInfo", NET_DVR_VIDEO_INTERCOM_EVENT_INFO_UNION),
        ("byRes2", BYTE * 256),
    ]


class NET_DVR_ALARM_ISAPI_INFO(Structure):
    """ISAPI alarm data passed through the SDK callback."""
    _fields_ = [
        ("pAlarmData", c_char_p),
        ("dwAlarmDataLen", DWORD),
        ("byDataType", BYTE),
        ("byPicturesNumber", BYTE),
        ("byRes", BYTE * 2),
        ("pPicPackData", c_void_p),
        ("byRes2", BYTE * 32),
    ]


class MessageCallbackAlarmInfoUnion(Union):
    """Union of all alarm info types passed to the callback."""
    _fields_ = [
        ("NET_DVR_ALARMINFO_V30", NET_DVR_ALARMINFO_V30),
        ("NET_DVR_VIDEO_INTERCOM_ALARM", NET_DVR_VIDEO_INTERCOM_ALARM),
        ("NET_DVR_VIDEO_INTERCOM_EVENT", NET_DVR_VIDEO_INTERCOM_EVENT),
        ("NET_DVR_ALARM_ISAPI_INFO", NET_DVR_ALARM_ISAPI_INFO),
    ]


class NET_DVR_SETUPALARM_PARAM_V50(Structure):
    """Parameters for setting up alarm channel subscription."""
    _fields_ = [
        ("dwSize", DWORD),
        ("byLevel", BYTE),
        ("byAlarmInfoType", BYTE),
        ("byRetAlarmTypeV40", BYTE),
        ("byRetDevInfoVersion", BYTE),
        ("byRetVQDAlarmType", BYTE),
        ("byFaceAlarmDetection", BYTE),
        ("bySupport", BYTE),
        ("byBrokenNetHttp", BYTE),
        ("wTaskNo", WORD),
        ("byDeployType", BYTE),
        ("byRes1", BYTE * 3),
        ("byAlarmTypeURL", BYTE),
        ("byCustomCtrl", BYTE),
        ("byRes4", BYTE * 128),
    ]


# ---------------------------------------------------------------------------
# Callback function type
# ---------------------------------------------------------------------------
fMessageCallBack = CFUNCTYPE(
    BOOL,
    LONG,
    POINTER(NET_DVR_ALARMER),
    POINTER(MessageCallbackAlarmInfoUnion),
    DWORD,
    c_void_p,
)


# ---------------------------------------------------------------------------
# SDK error
# ---------------------------------------------------------------------------
class HikvisionSDKError(Exception):
    """Error from the Hikvision SDK."""

    def __init__(self, message: str, error_code: int = 0, error_msg: str = ""):
        self.error_code = error_code
        self.error_msg = error_msg
        super().__init__(f"{message} (SDK error {error_code}: {error_msg})")


# ---------------------------------------------------------------------------
# SDK wrapper class
# ---------------------------------------------------------------------------
class HikvisionSDK:
    """Wrapper around the Hikvision HCNetSDK native library."""

    def __init__(self):
        self._lib: CDLL | None = None
        self._callback_ref = None  # prevent garbage collection of callback

    def load(self) -> None:
        """Load the SDK shared library for the current platform."""
        system = platform.system()
        machine = platform.machine()

        if system == "Linux":
            if machine == "x86_64":
                lib_dir = "lib-amd64"
            elif machine == "aarch64":
                lib_dir = "lib-aarch64"
            else:
                raise HikvisionSDKError(f"Unsupported architecture: {machine}")
            lib_path = os.path.join(lib_dir, "libhcnetsdk.so")
        elif system == "Windows":
            lib_path = os.path.join("lib-windows64", "HCNetSDK.dll")
        else:
            raise HikvisionSDKError(f"Unsupported OS: {system}")

        # Also check LD_LIBRARY_PATH for the component libraries
        if system == "Linux":
            ld_path = os.environ.get("LD_LIBRARY_PATH", "")
            if not ld_path:
                _LOGGER.warning(
                    "LD_LIBRARY_PATH is not set; SDK component libraries "
                    "may fail to load"
                )

        # Try the path directly and also from /usr/lib/hikvision (Docker)
        for candidate in (lib_path, "/usr/lib/hikvision/libhcnetsdk.so"):
            if os.path.exists(candidate):
                lib_path = candidate
                break
        else:
            raise HikvisionSDKError(
                f"SDK library not found. Expected at {lib_path} or "
                "/usr/lib/hikvision/libhcnetsdk.so"
            )

        _LOGGER.info("Loading Hikvision SDK from %s", lib_path)
        self._lib = cdll.LoadLibrary(lib_path)
        self._setup_function_types()

    def _setup_function_types(self) -> None:
        """Declare argument/return types for the SDK functions we use."""
        lib = self._lib
        lib.NET_DVR_Login_V30.argtypes = [
            c_char_p, WORD, c_char_p, c_char_p,
            POINTER(NET_DVR_DEVICEINFO_V30),
        ]
        lib.NET_DVR_Logout_V30.argtypes = [c_int]
        lib.NET_DVR_GetErrorMsg.argtypes = [POINTER(c_long)]
        lib.NET_DVR_GetErrorMsg.restype = c_char_p
        lib.NET_DVR_SetDVRMessageCallBack_V50.argtypes = [
            c_int, fMessageCallBack, c_void_p,
        ]
        lib.NET_DVR_SetupAlarmChan_V50.argtypes = [
            LONG, NET_DVR_SETUPALARM_PARAM_V50, c_char_p, DWORD,
        ]

    def _get_error(self) -> tuple[int, str]:
        """Get the last SDK error code and message."""
        code = self._lib.NET_DVR_GetLastError()
        msg = self._lib.NET_DVR_GetErrorMsg(c_long(code))
        return code, msg.decode("utf-8", errors="replace") if msg else ""

    def init(self) -> None:
        """Initialize the SDK. Must be called once before any other call."""
        if not self._lib.NET_DVR_Init():
            code, msg = self._get_error()
            raise HikvisionSDKError("Failed to initialize SDK", code, msg)
        self._lib.NET_DVR_SetValidIP(0, True)
        _LOGGER.info("Hikvision SDK initialized")

    def login(
        self, host: str, port: int, username: str, password: str
    ) -> tuple[int, NET_DVR_DEVICEINFO_V30]:
        """Login to a device.

        Returns (user_id, device_info).
        Raises HikvisionSDKError on failure.
        """
        device_info = NET_DVR_DEVICEINFO_V30()
        user_id = self._lib.NET_DVR_Login_V30(
            host.encode("utf-8"),
            port,
            username.encode("utf-8"),
            password.encode("utf-8"),
            ctypes.byref(device_info),
        )
        if user_id < 0:
            code, msg = self._get_error()
            raise HikvisionSDKError(
                f"Login failed for {host}:{port}", code, msg
            )
        _LOGGER.info(
            "Logged in to %s:%d (user_id=%d, serial=%s)",
            host, port, user_id, device_info.serial_number(),
        )
        return user_id, device_info

    def set_callback(self, callback_fn: fMessageCallBack) -> None:
        """Register the global alarm callback.

        The callback is invoked from a native C thread.
        """
        self._callback_ref = callback_fn  # prevent garbage collection
        result = self._lib.NET_DVR_SetDVRMessageCallBack_V50(
            0, callback_fn, None
        )
        if not result:
            code, msg = self._get_error()
            raise HikvisionSDKError("Failed to set alarm callback", code, msg)
        _LOGGER.info("Alarm callback registered")

    def setup_alarm(self, user_id: int) -> int:
        """Subscribe to alarm events for a device.

        Returns the alarm handle.
        """
        param = NET_DVR_SETUPALARM_PARAM_V50()
        param.dwSize = sizeof(param)
        param.byLevel = 1
        param.byAlarmInfoType = 1
        param.byRetAlarmTypeV40 = 1
        handle = self._lib.NET_DVR_SetupAlarmChan_V50(
            user_id, param, None, 0
        )
        if handle < 0:
            code, msg = self._get_error()
            raise HikvisionSDKError(
                f"Failed to setup alarm channel (user_id={user_id})",
                code, msg,
            )
        _LOGGER.info("Alarm channel active (handle=%d)", handle)
        return handle

    def close_alarm(self, handle: int) -> None:
        """Unsubscribe from alarm events."""
        if handle >= 0:
            self._lib.NET_DVR_CloseAlarmChan_V30(handle)

    def logout(self, user_id: int) -> None:
        """Logout from a device."""
        if user_id >= 0:
            self._lib.NET_DVR_Logout_V30(user_id)
            _LOGGER.info("Logged out (user_id=%d)", user_id)

    def cleanup(self) -> None:
        """Release all SDK resources."""
        if self._lib:
            self._lib.NET_DVR_Cleanup()
            _LOGGER.info("SDK cleaned up")
