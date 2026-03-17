"""Constants for the Hikvision Doorbell integration."""

DOMAIN = "hikvision_doorbell"
DEFAULT_SDK_PORT = 8000
SCAN_INTERVAL_SECONDS = 60  # Slow keepalive poll; ring detection via SDK protocol
MQTT_TOPIC_PREFIX = "hikvision_doorbell"
WEBHOOK_ID_PREFIX = "hikvision_doorbell"
