# Hikvision Doorbell SDK Add-on

This add-on provides native ring detection for Hikvision doorbells using the
official Hikvision HCNetSDK. It connects to your doorbell via the proprietary
SDK protocol (port 8000) and publishes ring events to MQTT, which the
Hikvision Doorbell integration picks up automatically.

## Why this add-on?

Some Hikvision doorbell firmware versions do not expose ring events via HTTP
ISAPI endpoints (callStatus returns 401, alertStream closes immediately). The
native SDK uses a different binary protocol that works on all firmware versions.

## Prerequisites

1. **Home Assistant OS** or **Home Assistant Supervised** (add-ons require the
   Supervisor)
2. **Mosquitto MQTT broker** add-on installed and running
3. **Hikvision Doorbell integration** (HACS) installed for HA entities
4. **Hikvision SDK libraries** (see below)

## Obtaining the SDK libraries

The Hikvision HCNetSDK is proprietary and cannot be bundled with this add-on.
You must obtain the libraries yourself:

1. Download the **Device Network SDK** from the
   [Hikvision Open Platform](https://open.hikvision.com/en/download)
2. Select the **Linux** version matching your architecture:
   - `amd64` for x86_64 systems
   - `aarch64` for ARM64 systems (Raspberry Pi 4/5, ODROID, etc.)
3. Extract the SDK archive
4. Copy the library files to the correct directory:
   - For amd64: `hikvision_doorbell_sdk/lib-amd64/`
   - For aarch64: `hikvision_doorbell_sdk/lib-aarch64/`
5. The directory should contain at minimum:
   - `libhcnetsdk.so` (main SDK library)
   - `libHCCore.so`
   - `libhpr.so`
   - `libcrypto.so` / `libcrypto.so.1.1`
   - `libssl.so` / `libssl.so.1.1`
   - `HCNetSDKCom/` subdirectory with component libraries

## Configuration

| Option     | Description                                      |
|------------|--------------------------------------------------|
| host       | IP address or hostname of the doorbell           |
| port       | SDK port (default: 8000)                         |
| username   | Admin username                                   |
| password   | Admin password                                   |
| name       | Friendly name (used in MQTT topics)              |

Multiple doorbells can be configured as a list.

## MQTT topics

The add-on publishes to:

- `hikvision_doorbell/{serial}/ring` - doorbell ring event (payload: JSON)
- `hikvision_doorbell/{serial}/motion` - motion detection event
- `hikvision_doorbell/{serial}/dismiss` - call dismissed
- `hikvision_doorbell/{serial}/status` - online/offline status

The Hikvision Doorbell integration automatically subscribes to the ring topic
when MQTT is available in Home Assistant.

## How it works

1. The add-on loads the Hikvision SDK native library via ctypes
2. It logs in to each configured doorbell on the SDK port (8000)
3. It registers an alarm callback with the SDK
4. When the doorbell rings, the SDK invokes the callback from a native thread
5. The callback publishes a ring event to MQTT
6. The HA integration receives the MQTT message and triggers the ring state
