"""MQTT publisher for bridging SDK events to Home Assistant.

Discovers the MQTT broker via the HA Supervisor API and publishes
doorbell events to well-known topics that the HACS integration
subscribes to.

Topic format:
  hikvision_doorbell/{serial}/ring    - doorbell ring event
  hikvision_doorbell/{serial}/status  - online/offline status
"""

import json
import logging
import os
import time
from urllib.request import Request, urlopen

import paho.mqtt.client as mqtt

_LOGGER = logging.getLogger(__name__)

TOPIC_PREFIX = "hikvision_doorbell"


def _discover_mqtt() -> dict:
    """Discover MQTT broker settings from the HA Supervisor API.

    Returns dict with host, port, username, password.
    Raises RuntimeError if discovery fails.
    """
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        raise RuntimeError(
            "SUPERVISOR_TOKEN not set. "
            "Ensure homeassistant_api is enabled in config.yaml."
        )

    req = Request(
        "http://supervisor/services/mqtt",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(req, timeout=10) as resp:  # noqa: S310
        data = json.loads(resp.read())

    if "data" not in data or "host" not in data["data"]:
        raise RuntimeError(f"Unexpected MQTT discovery response: {data}")

    info = data["data"]
    _LOGGER.info("Discovered MQTT broker at %s:%s", info["host"], info["port"])
    return info


class MQTTPublisher:
    """Publishes doorbell events to MQTT."""

    def __init__(self):
        self._client: mqtt.Client | None = None

    def connect(self) -> None:
        """Discover and connect to the MQTT broker."""
        broker = _discover_mqtt()

        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="hikvision_doorbell_sdk",
            clean_session=True,
        )
        self._client.username_pw_set(
            broker.get("username", ""),
            broker.get("password", ""),
        )
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect

        host = broker["host"]
        port = int(broker.get("port", 1883))
        self._client.connect(host, port, keepalive=60)
        self._client.loop_start()

    @staticmethod
    def _on_connect(client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            _LOGGER.info("Connected to MQTT broker")
        else:
            _LOGGER.error("MQTT connection failed: %s", reason_code)

    @staticmethod
    def _on_disconnect(client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            _LOGGER.warning(
                "Disconnected from MQTT broker (rc=%s), will reconnect",
                reason_code,
            )

    def publish_ring(self, serial: str, lock_id: int = 0) -> None:
        """Publish a doorbell ring event."""
        topic = f"{TOPIC_PREFIX}/{serial}/ring"
        payload = json.dumps({
            "event": "ring",
            "serial": serial,
            "lock_id": lock_id,
            "timestamp": int(time.time()),
        })
        self._client.publish(topic, payload, qos=1, retain=False)
        _LOGGER.info("Published ring event to %s", topic)

    def publish_status(self, serial: str, online: bool = True) -> None:
        """Publish device online/offline status."""
        topic = f"{TOPIC_PREFIX}/{serial}/status"
        payload = json.dumps({
            "online": online,
            "serial": serial,
            "timestamp": int(time.time()),
        })
        self._client.publish(topic, payload, qos=1, retain=True)

    def disconnect(self) -> None:
        """Disconnect from MQTT broker."""
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            _LOGGER.info("Disconnected from MQTT broker")
