"""Hikvision Doorbell SDK add-on entrypoint.

Reads add-on configuration, initializes the Hikvision SDK, logs in to each
configured doorbell, subscribes to alarm events, and bridges ring detections
to MQTT so the Home Assistant integration can pick them up.
"""

import asyncio
import ctypes
import json
import logging
import os
import signal
import sys

from hikvision_sdk import (
    ALARM_DOORBELL_RINGING,
    COMM_ALARM_VIDEO_INTERCOM,
    COMM_UPLOAD_VIDEO_INTERCOM_EVENT,
    NET_DVR_ALARMER,
    NET_DVR_VIDEO_INTERCOM_ALARM,
    HikvisionSDK,
    HikvisionSDKError,
    MessageCallbackAlarmInfoUnion,
    fMessageCallBack,
)
from mqtt_publisher import MQTTPublisher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
_LOGGER = logging.getLogger("hikvision_doorbell_sdk")

# Map user_id -> serial number (populated at login)
_USER_SERIAL_MAP: dict[int, str] = {}

# Global references
_mqtt: MQTTPublisher | None = None
_loop: asyncio.AbstractEventLoop | None = None


def _load_config() -> dict:
    """Load add-on options from /data/options.json."""
    config_path = "/data/options.json"
    if not os.path.exists(config_path):
        _LOGGER.error("Config file not found: %s", config_path)
        sys.exit(1)
    with open(config_path) as f:
        return json.load(f)


@fMessageCallBack
def _alarm_callback(command, alarm_device_p, alarm_info_p, buffer_len, user_p):
    """SDK alarm callback, invoked from a native C thread.

    We extract the relevant data and schedule MQTT publishing on the
    asyncio event loop (thread-safe).
    """
    try:
        device = alarm_device_p.contents
        serial = device.serial_number()
        ip = device.device_ip()

        if command == COMM_ALARM_VIDEO_INTERCOM:
            alarm = ctypes.cast(
                alarm_info_p,
                ctypes.POINTER(NET_DVR_VIDEO_INTERCOM_ALARM),
            ).contents

            alarm_type = int(alarm.byAlarmType)
            lock_id = int(alarm.wLockID)

            if alarm_type == ALARM_DOORBELL_RINGING:
                _LOGGER.info(
                    "Ring detected from %s (%s), lock_id=%d",
                    serial, ip, lock_id,
                )
                if _mqtt and _loop:
                    _loop.call_soon_threadsafe(
                        _mqtt.publish_ring, serial, lock_id
                    )
            else:
                _LOGGER.debug(
                    "Video intercom alarm type=%d from %s (%s)",
                    alarm_type, serial, ip,
                )
        elif command == COMM_UPLOAD_VIDEO_INTERCOM_EVENT:
            _LOGGER.debug(
                "Video intercom event from %s (%s)", serial, ip
            )
        else:
            _LOGGER.debug(
                "Alarm command=0x%04X from %s (%s)", command, serial, ip
            )
    except Exception:
        _LOGGER.exception("Error in alarm callback")

    return True


async def _run(config: dict) -> None:
    """Main async loop: init SDK, login, subscribe, wait for events."""
    global _mqtt, _loop
    _loop = asyncio.get_running_loop()

    doorbells = config.get("doorbells", [])
    if not doorbells:
        _LOGGER.error("No doorbells configured. Check add-on options.")
        return

    # Connect to MQTT
    _mqtt = MQTTPublisher()
    try:
        _mqtt.connect()
    except Exception:
        _LOGGER.exception("Failed to connect to MQTT broker")
        return

    # Initialize SDK
    sdk = HikvisionSDK()
    try:
        sdk.load()
        sdk.init()
    except HikvisionSDKError:
        _LOGGER.exception("Failed to load/initialize Hikvision SDK")
        _mqtt.disconnect()
        return

    # Register global callback
    sdk.set_callback(_alarm_callback)

    user_ids: list[int] = []
    alarm_handles: list[int] = []

    # Login to each doorbell and subscribe to alarms
    for bell in doorbells:
        host = bell.get("host", "")
        port = int(bell.get("port", 8000))
        username = bell.get("username", "admin")
        password = bell.get("password", "")
        name = bell.get("name", host)

        if not host or not password:
            _LOGGER.warning("Skipping doorbell '%s': missing host or password", name)
            continue

        try:
            user_id, device_info = sdk.login(host, port, username, password)
            serial = device_info.serial_number()
            _USER_SERIAL_MAP[user_id] = serial
            user_ids.append(user_id)

            _LOGGER.info("Doorbell '%s' logged in (serial=%s)", name, serial)
            _mqtt.publish_status(serial, online=True)

            handle = sdk.setup_alarm(user_id)
            alarm_handles.append(handle)

        except HikvisionSDKError:
            _LOGGER.exception("Failed to connect to doorbell '%s' (%s:%d)", name, host, port)
            continue

    if not user_ids:
        _LOGGER.error("No doorbells connected successfully")
        sdk.cleanup()
        _mqtt.disconnect()
        return

    _LOGGER.info(
        "Monitoring %d doorbell(s) for events. Waiting...",
        len(user_ids),
    )

    # Wait for shutdown signal
    stop_event = asyncio.Event()

    def _signal_handler():
        _LOGGER.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        _loop.add_signal_handler(sig, _signal_handler)

    await stop_event.wait()

    # Cleanup
    _LOGGER.info("Shutting down...")
    for handle in alarm_handles:
        sdk.close_alarm(handle)
    for uid in user_ids:
        serial = _USER_SERIAL_MAP.get(uid, "")
        if serial:
            _mqtt.publish_status(serial, online=False)
        sdk.logout(uid)
    sdk.cleanup()
    _mqtt.disconnect()
    _LOGGER.info("Shutdown complete")


def main():
    config = _load_config()
    asyncio.run(_run(config))


if __name__ == "__main__":
    main()
