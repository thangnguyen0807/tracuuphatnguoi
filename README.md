# VNeTraffic for Home Assistant

Custom Home Assistant integration for looking up traffic violations (phạt nguội) by license plate through the VNeTraffic citizen API used by the official Android application.

## What it does

- Creates a Home Assistant sensor for a license plate.
- Reads the VNeTraffic violation-history endpoint.
- Exposes violation count as the sensor state.
- Exposes detailed violation records as attributes: time/date, address, violation, detecting/handling unit and status.
- Supports an optional VNeTraffic Bearer access token when the API requires authentication.
- Uses a configurable polling interval (default 6 hours).

## Important

This project does **not** include or redistribute the VNeTraffic APK. The APK supplied for analysis was used only to identify the official API endpoint and parameter names. The integration calls the official API directly.

The VNeTraffic application is an official traffic information application associated with the Traffic Police / GTEL ecosystem. The official application describes traffic-violation lookup by license plate. API availability, authentication requirements and response formats can change at any time.

## Installation via HACS

1. HACS → Integrations → ⋮ → Custom repositories.
2. Add this repository URL as an **Integration**.
3. Install **VNeTraffic**.
4. Restart Home Assistant.
5. Settings → Devices & services → Add integration → VNeTraffic.
6. Enter the license plate without dots or hyphens, for example `30A12345`.

## Entity

Example:

`sensor.vnetraffic_30a12345_phat_nguoi`

The state is the number of violations. The `violations` attribute contains normalized records and `raw` contains the original record returned by the API.

## API recovered from VNeTraffic APK

The current Android APK contains the following violation service endpoint:

`GET /property/vehicle-violation/history`

Parameters recovered from the service definition:

- `licensePlate`
- `violationStatusCode` (optional)
- `timeRange` (optional, may be supplied twice as a range)
- `keySearch` (optional)

The APK also contains the official API base URL:

`https://citizen-api.vnetraffic.gov.vn/`

See `tools/apk_analysis.md` for the reverse-engineering notes.

## Authentication

The first version deliberately keeps authentication optional. If the official API responds with HTTP 401/403, enter a valid Bearer access token in the integration configuration. Do not put personal credentials, refresh tokens or private keys into GitHub.

## License

MIT. This project is an independent Home Assistant integration and is not affiliated with or endorsed by the VNeTraffic application owner.
