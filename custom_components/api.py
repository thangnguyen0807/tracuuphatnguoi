from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import aiohttp

from .const import DEFAULT_BASE_URL


class VNeTrafficError(Exception):
    pass


@dataclass
class LookupResult:
    raw: dict[str, Any]
    violations: list[dict[str, Any]]


class VNeTrafficApi:
    def __init__(self, session: aiohttp.ClientSession, access_token: str | None = None,
                 base_url: str = DEFAULT_BASE_URL) -> None:
        self.session = session
        self.access_token = access_token.strip() if access_token else None
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "Home Assistant VNeTraffic Integration/0.1.0",
        }
        if self.access_token:
            token = self.access_token
            if not token.lower().startswith("bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token
        return headers

    async def lookup(self, license_plate: str) -> LookupResult:
        plate = normalize_plate(license_plate)
        if not plate:
            raise VNeTrafficError("Biển số xe không hợp lệ")

        url = f"{self.base_url}/property/vehicle-violation/history"
        # The endpoint and parameter names below were recovered from the
        # VNeTraffic Android APK. Optional filters are deliberately omitted;
        # the service can return the current violation history for the plate.
        params = {"licensePlate": plate}

        try:
            async with self.session.get(
                url, params=params, headers=self._headers(), timeout=aiohttp.ClientTimeout(total=20)
            ) as response:
                text = await response.text()
                if response.status in (401, 403):
                    raise VNeTrafficError("API yêu cầu xác thực (HTTP %s)" % response.status)
                if response.status >= 400:
                    raise VNeTrafficError(f"VNeTraffic API HTTP {response.status}: {text[:300]}")
                try:
                    data = await response.json(content_type=None)
                except Exception as err:
                    raise VNeTrafficError(f"API trả về dữ liệu không phải JSON: {text[:300]}") from err
        except aiohttp.ClientError as err:
            raise VNeTrafficError(f"Không kết nối được VNeTraffic API: {err}") from err

        if not isinstance(data, dict):
            data = {"data": data}
        return LookupResult(raw=data, violations=extract_violations(data))


def normalize_plate(value: str) -> str:
    return "".join(ch for ch in value.upper().strip() if ch.isalnum())


def extract_violations(data: Any) -> list[dict[str, Any]]:
    """Find violation records despite minor response-envelope changes."""
    found: list[dict[str, Any]] = []

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_l = str(key).lower()
                if key_l in {"violations", "violationlist", "violation_list", "items", "content", "list"}:
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and looks_like_violation(item):
                                found.append(item)
                            else:
                                walk(item, depth + 1)
                else:
                    walk(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)

    walk(data)
    # Deduplicate by stable id when present, otherwise by JSON representation.
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    import json
    for item in found:
        key = str(item.get("violationId") or item.get("violationHistoryId") or json.dumps(item, sort_keys=True, ensure_ascii=False))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def looks_like_violation(item: dict[str, Any]) -> bool:
    keys = {str(k).lower() for k in item}
    markers = {"violationid", "violationname", "violationcode", "violationaddress", "violationdate", "violationstatuscode"}
    return bool(keys & markers)


def first_value(item: dict[str, Any], *names: str) -> Any:
    lower = {str(k).lower(): v for k, v in item.items()}
    for name in names:
        if name.lower() in lower and lower[name.lower()] not in (None, ""):
            return lower[name.lower()]
    return None
