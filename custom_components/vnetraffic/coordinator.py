from __future__ import annotations

import copy
import hashlib
import logging
from datetime import timedelta
from typing import Any

from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import VNeTrafficApi, VNeTrafficError

_LOGGER = logging.getLogger(__name__)
_STORE_VERSION = 1


def _store_key(plate: str) -> str:
    digest = hashlib.sha256(plate.encode("utf-8")).hexdigest()[:20]
    return f"vnetraffic.last_good.{digest}"


class VNeTrafficCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(self, hass, api: VNeTrafficApi, license_plate: str, scan_interval: int):
        self.api = api
        self.license_plate = license_plate
        self._store = Store(hass, _STORE_VERSION, _store_key(license_plate))
        self._last_good: dict[str, Any] | None = None
        self._store_loaded = False
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"VNeTraffic {license_plate}",
            update_interval=timedelta(seconds=scan_interval),
        )

    async def async_load_last_good(self) -> None:
        if self._store_loaded:
            return
        self._store_loaded = True
        try:
            stored = await self._store.async_load()
        except Exception as err:
            _LOGGER.warning("Unable to load saved VNeTraffic data for %s: %s", self.license_plate, err)
            stored = None
        if isinstance(stored, dict) and isinstance(stored.get("data"), dict):
            self._last_good = stored["data"]
            _LOGGER.debug("Loaded last-known-good VNeTraffic data for %s", self.license_plate)

    async def _save_last_good(self, data: dict[str, Any]) -> None:
        payload = {"data": copy.deepcopy(data)}
        try:
            await self._store.async_save(payload)
        except Exception as err:
            _LOGGER.warning("Unable to save VNeTraffic data for %s: %s", self.license_plate, err)

    async def _async_update_data(self):
        await self.async_load_last_good()
        try:
            result = await self.api.lookup(self.license_plate)
        except VNeTrafficError as err:
            if self._last_good:
                data = copy.deepcopy(self._last_good)
                debug = data.setdefault("debug", {})
                debug["served_from_last_good"] = True
                debug["last_good_reason"] = str(err)
                return data
            raise UpdateFailed(str(err)) from err

        raw = result.raw if isinstance(result.raw, dict) else {}
        pending_rows = raw.get("_deferred_fine_rows_for_plate", [])
        valid = bool(raw.get("_lookup_valid", False))

        if valid:
            data = {
                "raw": raw,
                "violations": result.violations,
                "pending_violations": pending_rows,
                "total_violation_count": int(raw.get("_total_violation_count", len(result.violations))),
                "processed_violation_count": int(raw.get("_processed_violation_count", 0)),
                "unresolved_violation_count": int(raw.get("_unresolved_violation_count", len(pending_rows))),
                "debug": result.debug,
            }
            self._last_good = copy.deepcopy(data)
            await self._save_last_good(data)
            return data

        if self._last_good:
            data = copy.deepcopy(self._last_good)
            debug = data.setdefault("debug", {})
            debug["served_from_last_good"] = True
            debug["last_good_reason"] = "Daily lookup did not return a valid data payload"
            debug["last_api_debug"] = result.debug
            return data

        # First-ever lookup failed or returned only an API error. Do not invent zeroes.
        raise UpdateFailed("VNeTraffic chưa trả về dữ liệu hợp lệ cho biển số này")
