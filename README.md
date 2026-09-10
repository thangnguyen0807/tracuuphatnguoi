# VNeTraffic for Home Assistant

Home Assistant custom integration for querying traffic violation (phạt nguội) history from the official VNeTraffic citizen API.

## v0.2.1

- Removed the manual **Access Token** field.
- Login uses the same basic flow as the VNeTraffic Android app: **username + password**.
- The integration calls `/auth/logins` and keeps the returned access/refresh tokens internally.
- When the access token expires, it tries `/auth/refresh-token`; if refresh fails it logs in again.
- Traffic violation lookup uses `/property/vehicle-violation/history` with `licensePlate`.
- Credentials are stored in the Home Assistant config entry; tokens are not exposed as configuration fields.

## Installation

### HACS
1. Add this repository as a custom HACS repository (Integration).
2. Install **VNeTraffic**.
3. Restart Home Assistant.
4. Go to **Settings → Devices & services → Add integration → VNeTraffic**.
5. Enter your VNeTraffic **username, password and license plate**.

### Important
The APK is not included in this repository. The integration was implemented from the API behavior recovered from the official VNeTraffic Android APK.

## API
Official citizen API base URL recovered from the APK:

`https://citizen-api.vnetraffic.gov.vn/`

Authentication endpoints recovered from the APK:

- `POST /auth/logins`
- `POST /auth/refresh-token`

Violation endpoint:

- `GET /property/vehicle-violation/history`
- Query: `licensePlate`

## Home Assistant entity

The integration creates a sensor whose state is the number of violation records. Detailed records are available in the entity attributes, including violation ID, code, name, date/time, address, detecting unit, handling unit and status.
