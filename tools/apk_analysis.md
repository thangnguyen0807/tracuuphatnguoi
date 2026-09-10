# VNeTraffic APK analysis notes

Source APK: `VNeTraffic.apk` supplied by the user.

The APK was unpacked and its DEX string tables / annotation metadata were inspected. The application package identifies the VNeTraffic Android app and contains the official citizen API base URL.

## Official API base URL recovered

`https://citizen-api.vnetraffic.gov.vn/`

## Violation service recovered

Kotlin source file name embedded in DEX: `ViolationService.kt`.

The Retrofit-style service definition has four methods. The lookup method is the GET method for:

`{root}/property/vehicle-violation/history`

Parameter annotations recovered from the DEX:

- `root` as an encoded path parameter
- `violationStatusCode` as a query parameter
- `timeRange` as a query parameter
- `timeRange` as a second query parameter
- `licensePlate` as a query parameter
- `keySearch` as a query parameter

The same service also exposes:

- `{root}/property/vehicle-violation/history/{violationHistoryId}`
- `{root}/property/vehicle/wanted`
- `{root}/property/deferred/fines`

The integration currently implements the primary lookup endpoint only. Optional filters are intentionally omitted from the first release to maximize compatibility with server-side defaults.
