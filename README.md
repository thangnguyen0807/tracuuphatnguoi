# VNeTraffic for Home Assistant

Home Assistant custom integration for querying traffic violation (phạt nguội) history from the official VNeTraffic citizen API.

## Installation

### HACS
1. Add this repository as a custom HACS repository (Integration).
2. Install **VNeTraffic**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration → VNeTraffic**.
5. Enter your VNeTraffic **username, password and license plate**.

### Important
The APK is not included in this repository. The integration was implemented from the API behavior recovered from the official VNeTraffic Android APK.

## Home Assistant entity

The integration creates a sensor whose state is the number of violation records. Detailed records are available in the entity attributes, including violation ID, code, name, date/time, address, detecting unit, handling unit and status.
