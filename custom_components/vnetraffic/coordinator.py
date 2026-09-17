from __future__ import annotations

from datetime import timedelta
from typing import Any

from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import VNeTrafficApi, VNeTrafficError


class VNeTrafficCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(self, hass, api: VNeTrafficApi, license_plate: str, scan_interval: int):
        self.api = api
        self.license_plate = license_plate
        super().__init__(
            hass,
            logger=__import__("logging").getLogger(__name__),
            name=f"VNeTraffic {license_plate}",
            update_interval=timedelta(seconds=scan_interval),
        )

    async def _async_update_data(self):
        try:
            result = await self.api.lookup(self.license_plate)
        except VNeTrafficError as err:
            raise UpdateFailed(str(err)) from err
        raw = result.raw
        pending_rows = raw.get("_deferred_fine_rows_for_plate", []) if isinstance(raw, dict) else []
        return {
            "raw": raw,
            "violations": result.violations,
            "pending_violations": pending_rows,
            "total_violation_count": int(raw.get("_total_violation_count", len(result.violations))) if isinstance(raw, dict) else len(result.violations),
            "processed_violation_count": int(raw.get("_processed_violation_count", 0)) if isinstance(raw, dict) else 0,
            "unresolved_violation_count": int(raw.get("_unresolved_violation_count", len(pending_rows))) if isinstance(raw, dict) else len(pending_rows),
            "debug": result.debug,
        }
