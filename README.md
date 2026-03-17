# Hikvision Doorbell

HACS integration for Home Assistant that connects to Hikvision DS-KV series door stations via ISAPI and publishes doorbell ring events to MQTT.

## Features

- Detects doorbell button presses by polling the ISAPI call status endpoint
- Captures a snapshot from the doorbell camera on each ring
- Publishes ring events and snapshots to MQTT for use in automations
- Exposes a binary sensor (ringing state) and image entity (latest snapshot) in Home Assistant

## Installation

1. Add this repository to HACS as a custom repository
2. Install "Hikvision Doorbell" from HACS
3. Restart Home Assistant
4. Go to Settings > Devices & Services > Add Integration > "Hikvision Doorbell"
5. Enter the doorbell IP, username, and password

## Configuration

The config flow asks for:

| Field    | Description                        | Default  |
|----------|------------------------------------|----------|
| Name     | Friendly name for the doorbell     | Doorbell |
| Host     | IP address of the doorbell         |          |
| Username | ISAPI username                     | admin    |
| Password | ISAPI password                     |          |

## MQTT Topics

When the doorbell rings, the integration publishes to these topics:

- `hikvision_doorbell/{name}/ring` with payload `ring`
- `hikvision_doorbell/{name}/snapshot` with payload containing the base64-encoded JPEG snapshot

## Example Automation

```yaml
automation:
  - alias: "Doorbell notification"
    trigger:
      - platform: mqtt
        topic: hikvision_doorbell/doorbell/ring
    action:
      - service: notify.mobile_app_your_phone
        data:
          title: "Doorbell"
          message: "Someone is at the door"
          data:
            entity_id: image.doorbell_snapshot
```

## Entities

| Entity                             | Type          | Description                              |
|------------------------------------|---------------|------------------------------------------|
| `binary_sensor.<name>_ringing`     | Binary sensor | ON while the doorbell is ringing         |
| `image.<name>_snapshot`            | Image         | Latest snapshot captured on ring         |

## Requirements

- Home Assistant 2024.1.0 or newer
- MQTT integration configured in Home Assistant
- Hikvision door station with ISAPI support (tested with DS-KV6113-WPE1(B))
