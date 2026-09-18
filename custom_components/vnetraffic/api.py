from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import uuid
import base64
import os
import asyncio
from datetime import datetime, timedelta, timezone

from homeassistant.util import dt as dt_util

import aiohttp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

from .firebase_remote_config import fetch_remote_config
from .const import (
    API_ROOT,
    API_VERSION,
    APP_VERSION,
    APP_VERSION_CODE,
    DEFAULT_BASE_URL,
    PLATFORM,
    VERSION,
    X_API_VERSION,
)

class VNeTrafficError(Exception):
    """Expected VNeTraffic API error."""


@dataclass
class LookupResult:
    raw: dict[str, Any]
    violations: list[dict[str, Any]]
    debug: dict[str, Any]


class VNeTrafficApi:
    """Client matching the official VNeTraffic Android API flow."""

    def __init__(self, session: aiohttp.ClientSession, username: str, password: str, base_url: str = DEFAULT_BASE_URL, vehicle_type: str = "auto") -> None:
        self.session = session
        self.username = username.strip()
        self.password = password
        self._vehicle_type = vehicle_type or "auto"
        self.base_url = _normalize_api_base_url(base_url)
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.device_id = _stable_device_id(self.username)
        self._public_key: str | None = None
        self._remote_config_loaded = False
        self._login_lock = asyncio.Lock()
        self._violation_detail_cache: dict[str, dict[str, Any] | None] = {}

    def _headers(self, authenticated: bool = False, include_app_headers: bool = True) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Platform": PLATFORM,
            "Ver": APP_VERSION,
            "VerCode": APP_VERSION_CODE,
            "App-Version": APP_VERSION,
            "X-API-VERSION": X_API_VERSION,
            "api-version": API_VERSION,
            "User-Agent": f"VNeTraffic/{APP_VERSION} (Home Assistant; {VERSION})",
        }
        # Keep the login request close to the APK's base header.
        if include_app_headers:
            headers["Device-Id"] = self.device_id
            headers["Device-Info"] = _device_info()
        if authenticated:
            # Present in the APK's authenticated header builder; empty is valid
            # when there is no active passcode token.
            headers["X-PASSCODE-TOKEN"] = ""
        if authenticated and self.access_token:
            token = self.access_token
            headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        return headers

    async def _load_remote_config(self) -> None:
        if self._remote_config_loaded and self._public_key:
            return
        config = await fetch_remote_config(self.session)
        self.base_url = _normalize_api_base_url(config.base_url)
        self._public_key = config.public_key
        self._remote_config_loaded = True

    async def login(self) -> None:
        if not self.username or not self.password:
            raise VNeTrafficError("Chưa cấu hình tài khoản hoặc mật khẩu VNeTraffic")

        # APK uses Retrofit {root}/auth/logins; {root} comes from Remote Config.
        await self._load_remote_config()
        url = f"{self.base_url}/auth/logins"
        payload = {
            "citizenIdentify": self.username,
            "password": self.password,
        }
        body, client_secret = encrypt_apk_payload(payload, self._public_key)
        headers = self._headers()
        headers["client-secret"] = client_secret
        try:
            async with self.session.post(
                url, json={"payload": body}, headers=headers, timeout=aiohttp.ClientTimeout(total=20)
            ) as response:
                text = await response.text()
                if response.status >= 400:
                    raise VNeTrafficError(
                        f"VNeTraffic API đăng nhập HTTP {response.status}: {_api_message(text)} (URL: {url})"
                    )
                try:
                    data = await response.json(content_type=None)
                except Exception as err:
                    raise VNeTrafficError("VNeTraffic trả về dữ liệu đăng nhập không hợp lệ") from err
        except aiohttp.ClientError as err:
            raise VNeTrafficError(f"Không kết nối được VNeTraffic API: {err}") from err

        access = find_first(data, "accessToken", "accessTKN", "token", "access_token")
        refresh = find_first(data, "refreshToken", "refreshTKN", "refresh_token")
        if not access:
            message = find_first(data, "message", "msg", "errorMessage", "error") or "Không nhận được access token"
            raise VNeTrafficError(f"Đăng nhập VNeTraffic không thành công: {message}")
        self.access_token = str(access)
        self.refresh_token = str(refresh) if refresh else None

    async def refresh(self) -> bool:
        if not self.refresh_token:
            return False
        await self._load_remote_config()
        url = f"{self.base_url}/auth/refresh-token"
        # RefreshTokenRequest.kt: refreshToken, fcmToken, latitude, longitude.
        payload = {"refreshToken": self.refresh_token}
        if not self._public_key:
            await self._load_remote_config()
        body, client_secret = encrypt_apk_payload(payload, self._public_key)
        headers = self._headers()
        headers["client-secret"] = client_secret
        try:
            async with self.session.post(
                url, json={"payload": body}, headers=headers, timeout=aiohttp.ClientTimeout(total=20)
            ) as response:
                text = await response.text()
                if response.status >= 400:
                    return False
                try:
                    data = await response.json(content_type=None)
                except Exception:
                    return False
        except aiohttp.ClientError:
            return False

        access = find_first(data, "accessToken", "accessTKN", "token", "access_token")
        refresh = find_first(data, "refreshToken", "refreshTKN", "refresh_token")
        if not access:
            return False
        self.access_token = str(access)
        if refresh:
            self.refresh_token = str(refresh)
        return True

    async def _ensure_authenticated(self) -> None:
        if self.access_token:
            return
        async with self._login_lock:
            if not self.access_token:
                await self.login()

    async def lookup(self, license_plate: str) -> LookupResult:
        plate = normalize_plate(license_plate)
        if not plate:
            raise VNeTrafficError("Biển số xe không hợp lệ")

        await self._ensure_authenticated()
        await self._load_remote_config()

        debug_requests: list[dict[str, Any]] = []
        history_data: Any = None
        deferred_data: Any = None
        history_text = ""
        deferred_text = ""
        history_status = 0
        deferred_status = 0

        async def get_json(path: str, params: list[tuple[str, str]] | None = None) -> tuple[int, Any, str]:
            url = f"{self.base_url}/{path.lstrip('/') }"
            try:
                async with self.session.get(
                    url,
                    params=params,
                    headers=self._headers(authenticated=True),
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as response:
                    text = await response.text()
                    try:
                        payload = await response.json(content_type=None)
                    except Exception:
                        payload = None
                    return response.status, payload, text
            except aiohttp.ClientError as err:
                raise VNeTrafficError(f"Không kết nối được VNeTraffic API: {err}") from err

        vehicle_code = _vehicle_type_code(self._vehicle_type)

        # EXACT v0.5.6 source for unresolved violations.
        deferred_params = [("licensePlate", plate), ("type", vehicle_code)]
        deferred_status, deferred_data, deferred_text = await get_json(
            "property/deferred/fines", deferred_params
        )
        deferred_rows = extract_httpdata_rows(deferred_data)
        if not deferred_rows and deferred_data is not None:
            deferred_rows = extract_violations(deferred_data)
        deferred_counts = _find_count_fields(deferred_data)
        deferred_meta_total = _meta_total(deferred_data)
        deferred_total = _effective_count(
            deferred_meta_total if deferred_meta_total is not None else deferred_counts.get("total"),
            deferred_rows,
        )
        if deferred_counts.get("unresolved") is not None:
            deferred_total = max(int(deferred_total or 0), int(deferred_counts["unresolved"]))
        if deferred_total is not None:
            deferred_counts["deferred_total"] = deferred_total
        debug_requests.append({
            "endpoint": "/property/deferred/fines",
            "profile": "v0.5.6-exact",
            "params": deferred_params,
            "http_status": deferred_status,
            "extracted_count": len(deferred_rows),
            "server_total": deferred_meta_total,
            "effective_total": deferred_total,
            "response_preview": deferred_text[:1600],
        })

        # EXACT v0.5.6 history query.
        history_params = _build_history_params(plate, self._vehicle_type, dt_util.now())
        history_status, history_data, history_text = await get_json(
            "property/vehicle-violation/history", history_params
        )
        history_rows = extract_httpdata_rows(history_data)
        if not history_rows and history_data is not None:
            history_rows = extract_violations(history_data)
        history_counts = _find_count_fields(history_data)
        history_meta_total = _meta_total(history_data)
        history_total = _effective_count(
            history_meta_total if history_meta_total is not None else history_counts.get("total"),
            history_rows,
        )
        if history_total is not None:
            history_counts["total"] = history_total
        debug_requests.append({
            "endpoint": "/property/vehicle-violation/history",
            "profile": "v0.5.6-exact",
            "params": history_params,
            "http_status": history_status,
            "extracted_count": len(history_rows),
            "server_total": history_meta_total,
            "effective_total": history_total,
            "response_preview": history_text[:1600],
        })

        # APK search-screen contract used by earlier VNeTraffic builds.
        # Only call it when the exact v0.5.6 history request returned no rows
        # and no positive count, so normal operation remains on the v0.5.6 path.
        search_rows: list[dict[str, Any]] = []
        search_data: Any = None
        search_text = ""
        search_status = 0
        search_total: int | None = None
        if not history_rows and not (history_total and history_total > 0):
            search_params = [
                ("violationStatusCode", ""),
                ("timeRange", ""),
                ("timeRange", ""),
                ("licensePlate", _vehicle_type_label(self._vehicle_type)),
                ("keySearch", plate),
            ]
            search_status, search_data, search_text = await get_json(
                "property/vehicle-violation/history", search_params
            )
            search_rows = extract_httpdata_rows(search_data)
            if not search_rows and search_data is not None:
                search_rows = extract_violations(search_data)
            search_counts = _find_count_fields(search_data)
            search_total = _effective_count(
                _meta_total(search_data) if _meta_total(search_data) is not None else search_counts.get("total"),
                search_rows,
            )
            if search_counts.get("resolved") is not None:
                search_total = max(int(search_total or 0), int(search_counts["resolved"]))
            debug_requests.append({
                "endpoint": "/property/vehicle-violation/history",
                "profile": "apk-search-fallback",
                "params": search_params,
                "http_status": search_status,
                "extracted_count": len(search_rows),
                "server_total": _meta_total(search_data),
                "effective_total": search_total,
                "response_preview": search_text[:1600],
            })

        effective_history_rows = history_rows if history_rows else search_rows
        effective_history_total = history_total if history_total is not None else search_total

        # The backend can legitimately return meta.total=0 while still returning
        # rows. Therefore all effective totals are based on max(server_total, rows).
        unresolved_count = max(
            int(deferred_total or 0),
            len(deferred_rows),
            int(deferred_counts.get("unresolved", 0) or 0),
        )
        total_candidates = [
            len(effective_history_rows),
            int(effective_history_total or 0),
            int(deferred_total or 0),
            len(deferred_rows),
        ]
        total_count = max(total_candidates)

        # IMPORTANT: the list endpoint can omit payment/handling state on some
        # backend responses, and the deferred/fines endpoint can be the only
        # source that contains the row used to derive the total. The APK also
        # exposes a detail endpoint: /property/vehicle-violation/history/{id}.
        # Use direct status on list/deferred rows first, then enrich ambiguous
        # rows from that detail endpoint. This avoids the old error where a
        # processed plate such as 17H00713 was total=1, deferred=1, processed=0.
        candidate_rows: list[dict[str, Any]] = []
        seen_candidate_ids: set[str] = set()
        for row in [*effective_history_rows, *deferred_rows]:
            row_id = first_value(row, "violationHistoryId", "vehicleViolationHistoryId", "violationId", "id")
            key = str(row_id) if row_id not in (None, "") else "json:" + json.dumps(row, sort_keys=True, ensure_ascii=False, default=str)
            if key not in seen_candidate_ids:
                seen_candidate_ids.add(key)
                candidate_rows.append(row)

        detail_debug: list[dict[str, Any]] = []
        detail_rows: dict[str, dict[str, Any]] = {}

        async def enrich_from_detail(row: dict[str, Any]) -> dict[str, Any]:
            row_id = first_value(row, "violationHistoryId", "vehicleViolationHistoryId", "violationId", "id")
            if row_id in (None, ""):
                return row
            key = str(row_id)
            if key in self._violation_detail_cache:
                detail = self._violation_detail_cache[key]
                if detail:
                    merged = dict(row)
                    merged.update(detail)
                    return merged
                return row

            path = f"property/vehicle-violation/history/{key}"
            d_status, d_data, d_text = await get_json(path)
            parsed: dict[str, Any] | None = None
            if d_status < 400 and d_data is not None:
                detail_candidates = extract_violations(d_data)
                if detail_candidates:
                    parsed = detail_candidates[0]
                elif isinstance(d_data, dict):
                    # Detail responses are sometimes the record itself or a
                    # record nested under data/result rather than an array.
                    direct = d_data.get("data")
                    if isinstance(direct, dict):
                        parsed = direct
                    elif isinstance(d_data.get("result"), dict):
                        parsed = d_data["result"]
                    elif _looks_like_violation_record(d_data):
                        parsed = d_data
            self._violation_detail_cache[key] = parsed
            detail_debug.append({
                "id": key,
                "endpoint": "/property/vehicle-violation/history/{violationHistoryId}",
                "http_status": d_status,
                "extracted": bool(parsed),
                "status": _status_values(parsed) if parsed else [],
                "response_preview": d_text[:1200],
            })
            if parsed:
                merged = dict(row)
                merged.update(parsed)
                detail_rows[key] = merged
                return merged
            return row

        enriched_rows: list[dict[str, Any]] = []
        for row in candidate_rows:
            # Only request detail when the list row is not already explicitly
            # resolved/unresolved; this keeps normal polling lightweight.
            if (not _has_explicit_resolved_status(row) and
                    not _has_explicit_unresolved_status(row)):
                row = await enrich_from_detail(row)
            enriched_rows.append(row)

        processed_from_rows = sum(
            1 for row in enriched_rows
            if _is_resolved_violation(row)
        )

        history_resolved = history_counts.get("resolved")
        deferred_resolved = deferred_counts.get("resolved")
        server_resolved = max(
            int(history_resolved or 0),
            int(deferred_resolved or 0),
        )
        processed_count = max(processed_from_rows, server_resolved)
        processed_count = min(processed_count, total_count) if total_count else 0

        data: dict[str, Any] = {
            "history_response": history_data,
            "history_search_response": search_data,
            "deferred_fines_response": deferred_data,
            "_history_counts": history_counts,
            "_deferred_fine_counts": deferred_counts,
            "_deferred_fine_rows_for_plate": deferred_rows,
            "_history_rows_for_plate": effective_history_rows,
            "_total_violation_count": int(total_count),
            "_processed_violation_count": int(processed_count),
            "_unresolved_violation_count": int(unresolved_count),
            "_effective_violation_source": (
                "property/vehicle-violation/history" if history_rows
                else "property/vehicle-violation/history?apk-search-fallback" if search_rows
                else "none"
            ),
            "_deferred_fine_effective_source": "property/deferred/fines" if deferred_rows else "none",
        }

        violations = effective_history_rows
        http_status = history_status or search_status or deferred_status
        raw_text_snapshot = history_text[:4000] if history_text else search_text[:4000] if search_text else deferred_text[:4000]
        last_error = None
        if history_status >= 400 and deferred_status >= 400 and (not search_status or search_status >= 400):
            last_error = f"History HTTP {history_status}; deferred/fines HTTP {deferred_status}; search fallback HTTP {search_status}"

        debug = build_response_debug(
            data=data,
            text=raw_text_snapshot,
            http_status=http_status,
            url=f"{self.base_url}/property/vehicle-violation/history",
            plate=plate,
            violations=violations,
        )
        debug["request_profiles"] = debug_requests
        debug["history_total"] = history_total
        debug["history_rows"] = len(history_rows)
        debug["search_total"] = search_total
        debug["search_rows"] = len(search_rows)
        debug["deferred_fine_total"] = deferred_total
        debug["deferred_fine_rows"] = len(deferred_rows)
        debug["total_violation_count"] = int(total_count)
        debug["processed_violation_count"] = int(processed_count)
        debug["unresolved_violation_count"] = int(unresolved_count)
        debug["processed_status_classification"] = [
            {
                "id": first_value(row, "violationHistoryId", "vehicleViolationHistoryId", "violationId", "id"),
                "processed": _is_resolved_violation(row),
                "status": _status_values(row),
                "paid_date": first_value(row, "paidDate", "paidDateText", "paymentDate", "paymentDateText"),
                "source": (
                    "history/deferred" if first_value(row, "violationHistoryId", "vehicleViolationHistoryId", "violationId", "id") not in detail_rows
                    else "history-detail"
                ),
            }
            for row in enriched_rows
        ]
        debug["processed_detail_requests"] = detail_debug
        debug["vehicle_type_code"] = vehicle_code

        # VNeTraffic sometimes returns HTTP 200 while embedding an application
        # error in JSON (for example status=500, CIT_042). Do not convert such a
        # failed lookup into a new set of zero counters: let DataUpdateCoordinator
        # keep the last successful state instead.
        body_errors: list[str] = []
        for label, payload, status_code in (
            ("deferred/fines", deferred_data, deferred_status),
            ("history", history_data, history_status),
            ("history-search", search_data, search_status),
        ):
            if status_code >= 400:
                body_errors.append(f"{label} HTTP {status_code}")
                continue
            app_status = _embedded_api_status(payload)
            if app_status is not None and app_status >= 400:
                code = find_first(payload, "code") or "API_ERROR"
                message = find_first(payload, "message", "msg", "errorMessage", "error") or "Lỗi API"
                body_errors.append(f"{label} {code}: {message}")

        if body_errors and not effective_history_rows and not search_rows and not deferred_rows and not total_count:
            raise VNeTrafficError("VNeTraffic API không trả được dữ liệu: " + " | ".join(body_errors[:3]))

        if last_error:
            debug["last_error"] = last_error
        if body_errors:
            debug["api_body_errors"] = body_errors
        return LookupResult(raw=data, violations=violations, debug=debug)



def encrypt_apk_payload(payload: dict[str, Any], public_key_pem: str) -> tuple[str, str]:
    """Reproduce APK AuthApiHelper.d(): AES payload + RSA-wrapped AES key."""
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    # Java KeyGenerator.getInstance("AES") + init(128) -> random 16-byte key.
    aes_key = os.urandom(16)
    aes_pad = sym_padding.PKCS7(128).padder()
    padded = aes_pad.update(plaintext.encode("utf-8")) + aes_pad.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    encrypted = cipher.update(padded) + cipher.finalize()
    payload_b64 = base64.b64encode(encrypted).decode("ascii")

    key_text = public_key_pem.strip()
    try:
        public_key = serialization.load_pem_public_key(key_text.encode("utf-8"))
    except (ValueError, TypeError) as err:
        raise VNeTrafficError("Khóa bảo mật VNeTraffic không hợp lệ") from err
    wrapped = public_key.encrypt(
        base64.b64encode(aes_key),
        rsa_padding.PKCS1v15(),
    )
    client_secret = base64.b64encode(wrapped).decode("ascii")
    return payload_b64, client_secret

def _vehicle_type_code(vehicle_type: str) -> str:
    return {
        "auto": "1",
        "motorcycle": "2",
        "other": "3",
    }.get(vehicle_type or "auto", "1")


def _embedded_api_status(data: Any) -> int | None:
    """Read application-level HTTP status from VNeTraffic JSON wrappers.

    The API can return transport HTTP 200 with a body such as
    {"code":"CIT_042", "status":500, ...}. That is an API failure, not an
    empty result set.
    """
    if not isinstance(data, dict):
        return None
    value = data.get("status")
    try:
        ivalue = int(value)
        return ivalue
    except (TypeError, ValueError):
        pass
    for key in ("data", "result", "response", "error"):
        nested = data.get(key)
        if isinstance(nested, dict):
            status = nested.get("status")
            try:
                return int(status)
            except (TypeError, ValueError):
                continue
    return None


def _meta_total(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    meta = data.get("meta")
    if isinstance(meta, dict):
        try:
            return max(0, int(meta.get("total")))
        except (TypeError, ValueError):
            pass
    return None


def extract_httpdata_rows(data: Any) -> list[dict[str, Any]]:
    """Extract list rows from the APK response wrappers.

    v0.5.6 intentionally used the two known wrappers (data / result.data).
    Keep those paths first, then recurse through the same JSON response so a
    backend wrapper change cannot turn a populated response into a false zero.
    """
    root = _flatten_embedded_json(data)

    def only_dicts(value: Any) -> list[dict[str, Any]]:
        return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []

    if isinstance(root, dict):
        rows = only_dicts(root.get("data"))
        if rows:
            return rows
        nested = root.get("result")
        if isinstance(nested, dict):
            rows = only_dicts(nested.get("data"))
            if rows:
                return rows

    preferred = {
        "data", "result", "items", "content", "records", "rows",
        "results", "list", "violations", "violationlist",
        "violationhistory", "pending", "fines", "fineList",
    }
    candidates: list[list[dict[str, Any]]] = []

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 12:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, list):
                    rows2 = only_dicts(value)
                    if rows2 and str(key).strip().lower().replace("_", "") in {x.lower().replace("_", "") for x in preferred}:
                        candidates.append(rows2)
                    walk(value, depth + 1)
                elif isinstance(value, dict):
                    walk(value, depth + 1)
        elif isinstance(obj, list):
            for value in obj:
                walk(value, depth + 1)

    walk(root)
    if candidates:
        return max(candidates, key=len)
    return []


def _effective_count(server_total: int | None, rows: list[dict[str, Any]]) -> int | None:
    """Never let an explicit server-side zero hide populated response rows."""
    row_count = len(rows)
    if server_total is None:
        return row_count or None
    return max(0, int(server_total), row_count)


def _build_history_params(plate: str, vehicle_type: str, now_local: datetime) -> list[tuple[str, str]]:
    """Build the exact five @Query values used by ViolationService.d()."""
    vehicle_code = _vehicle_type_code(vehicle_type)
    start_local = _calendar_add_months(now_local, -1)
    return [
        ("violationStatusCode", ""),
        ("timeRange", _format_apk_utc(start_local)),
        ("timeRange", _format_apk_utc(now_local)),
        ("licensePlate", vehicle_code),
        ("keySearch", plate),
    ]


def _vehicle_type_label(vehicle_type: str) -> str:
    return {
        "auto": "Ôtô",
        "motorcycle": "Mô tô",
        "other": "Xe đạp điện",
    }.get(vehicle_type or "auto", "Ôtô")


def _calendar_add_months(value: datetime, months: int) -> datetime:
    """Match java.util.Calendar.add(Calendar.MONTH, months) for HA timestamps."""
    year = value.year + (value.month - 1 + months) // 12
    month = (value.month - 1 + months) % 12 + 1

    # Java Calendar clamps an overflowing day to the last valid day of target month.
    if month == 12:
        next_month = datetime(year + 1, 1, 1, tzinfo=value.tzinfo)
    else:
        next_month = datetime(year, month + 1, 1, tzinfo=value.tzinfo)
    last_day = (next_month - timedelta(days=1)).day
    return value.replace(year=year, month=month, day=min(value.day, last_day))


def _format_apk_utc(value: datetime) -> str:
    """Match BaseAppUtils.convertToUTCString(Calendar): UTC, second precision, Z suffix."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt_util.DEFAULT_TIME_ZONE)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _device_info() -> str:
    """Keep the APK's `MANUFACTURER - MODEL - RELEASE` shape for server compatibility."""
    import platform
    return f"Home Assistant - {platform.machine()} - {platform.release()}"


def _normalize_api_base_url(value: str) -> str:
    """Return the effective API root reconstructed from the APK.

    Static APK analysis shows the encrypted API_ROOT is a short prefix and
    App.onCreate() appends the literal ``v2`` to it. The known plaintext
    prefix used by the same APK's citizen API routes is ``api/citizens/``,
    yielding ``api/citizens/v2`` as the effective Retrofit root.
    """
    base = str(value or "").strip().rstrip("/")
    if not base:
        base = DEFAULT_BASE_URL

    lower = base.lower()
    if lower.endswith("/api/citizens/v2"):
        return base
    if lower.endswith("/api/citizens"):
        return f"{base}/v2"
    return f"{base}/api/citizens/v2"


def _stable_device_id(username: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "vnetraffic-ha:" + username))


def normalize_plate(value: str) -> str:
    return "".join(ch for ch in value.upper().strip() if ch.isalnum())


def find_first(data: Any, *names: str) -> Any:
    wanted = {n.lower() for n in names}
    def walk(obj: Any, depth: int = 0) -> Any:
        if depth > 8:
            return None
        if isinstance(obj, dict):
            for key, value in obj.items():
                if str(key).lower() in wanted and value not in (None, ""):
                    return value
            for value in obj.values():
                result = walk(value, depth + 1)
                if result not in (None, ""):
                    return result
        elif isinstance(obj, list):
            for value in obj:
                result = walk(value, depth + 1)
                if result not in (None, ""):
                    return result
        return None
    return walk(data)


def first_value(data: Any, *names: str) -> Any:
    """Backward-compatible helper used by sensor.py."""
    return find_first(data, *names)


def _api_message(text: str) -> str:
    try:
        data = json.loads(text)
        message = find_first(data, "message", "msg", "errorMessage", "error", "error_message")
        if message:
            return str(message)[:300]
    except Exception:
        pass
    return text[:300] or "Lỗi không xác định"


def _parse_json_string(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    if not candidate or candidate[0] not in "[{":
        return value
    try:
        return json.loads(candidate)
    except Exception:
        return value


def _key_norm(key: Any) -> str:
    return str(key).strip().lower().replace("-", "").replace("_", "")


def _looks_like_violation_record(item: dict[str, Any]) -> bool:
    keys = {_key_norm(k) for k in item}
    exact = {
        "violationid", "violationhistoryid", "vehicleviolationhistoryid",
        "violationname", "violationcode", "violationaddress",
        "violationdate", "violationat", "violationtime",
        "violationstatuscode", "violationstatusname", "violationtypename",
        "violationtype", "violationreason", "licenseplate", "licenseplateencrypt",
    }
    if keys & exact:
        # Do not accept a summary object merely because it contains a count field.
        return len(keys & {"violationid", "violationhistoryid", "vehicleviolationhistoryid",
                           "violationname", "violationcode", "violationtype", "violationreason"}) > 0

    id_keys = {"id", "idcrypt", "idencrypt", "recordid"}
    time_keys = {"date", "datetime", "createdat", "updatedat", "violationdate", "violationat", "violationtime"}
    type_keys = {"type", "name", "reason", "description", "content", "violation"}
    status_keys = {"status", "statuscode", "statusname", "paymentstatus", "paymentstatuscode", "paymentstatusname"}
    plate_keys = {"plate", "licenseplate", "licenseplateencrypt", "vehicleplate"}
    if (keys & id_keys) and ((keys & time_keys) or (keys & type_keys) or (keys & status_keys)):
        return True
    if (keys & plate_keys) and ((keys & time_keys) or (keys & type_keys) or (keys & status_keys)):
        return True
    return False


def looks_like_violation(item: dict[str, Any]) -> bool:
    return _looks_like_violation_record(item)


def _flatten_embedded_json(obj: Any, depth: int = 0) -> Any:
    if depth > 8:
        return obj
    obj = _parse_json_string(obj)
    if isinstance(obj, dict):
        return {k: _flatten_embedded_json(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_flatten_embedded_json(v, depth + 1) for v in obj]
    return obj


def extract_violations(data: Any) -> list[dict[str, Any]]:
    """Extract violation rows from all common VNeTraffic response shapes.

    The official app/backend has changed wrappers over time (data/result/content/items,
    nested pagination, or JSON encoded strings). We flatten embedded JSON, prioritize
    arrays with violation-like names, and also inspect generic records.
    """
    root = _flatten_embedded_json(data)
    found: list[dict[str, Any]] = []
    preferred_array_names = {
        "violations", "violationlist", "violationhistory", "records", "items",
        "content", "results", "result", "data", "list", "rows",
    }

    def walk(obj: Any, depth: int = 0, preferred: bool = False) -> None:
        if depth > 14:
            return
        if isinstance(obj, dict):
            if _looks_like_violation_record(obj):
                found.append(obj)
            for key, value in obj.items():
                name = _key_norm(key)
                child_preferred = preferred or name in {_key_norm(x) for x in preferred_array_names}
                if isinstance(value, (dict, list)):
                    walk(value, depth + 1, child_preferred)
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, dict) and (_looks_like_violation_record(item) or preferred):
                    if isinstance(item, dict):
                        found.append(item) if _looks_like_violation_record(item) else None
                walk(item, depth + 1, preferred)

    walk(root)

    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in found:
        key_value = find_first(
            item,
            "violationHistoryId", "vehicleViolationHistoryId", "violationId",
            "idEncrypt", "id", "recordId",
        )
        if key_value not in (None, ""):
            key = f"id:{key_value}"
        else:
            key = "json:" + json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _collect_shape_paths(obj: Any, path: str = "$", out: list[dict[str, Any]] | None = None, depth: int = 0) -> list[dict[str, Any]]:
    if out is None:
        out = []
    if depth > 8:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}"
            if isinstance(v, list):
                out.append({"path": p, "type": "list", "length": len(v)})
            elif isinstance(v, dict):
                out.append({"path": p, "type": "dict", "keys": list(v.keys())[:30]})
            elif isinstance(v, str) and v[:1] in "[{":
                try:
                    parsed = json.loads(v)
                    out.append({"path": p, "type": "json_string", "parsed_type": type(parsed).__name__})
                except Exception:
                    pass
            _collect_shape_paths(v, p, out, depth + 1)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):
            _collect_shape_paths(v, f"{path}[{i}]", out, depth + 1)
    return out


def build_response_debug(
    data: dict[str, Any],
    text: str,
    http_status: int,
    url: str,
    plate: str,
    violations: list[dict[str, Any]],
) -> dict[str, Any]:
    keys = list(data.keys())[:50]
    shapes = _collect_shape_paths(data)
    counts = _find_count_fields(data)
    return {
        "http_status": http_status,
        "url": url,
        "license_plate": plate,
        "top_level_keys": keys,
        "violation_count_extracted": len(violations),
        "server_count_fields": counts,
        "shape_paths": shapes[:120],
        "raw_response_preview": text[:4000],
    }


def _status_values(violation: dict[str, Any]) -> list[tuple[str, Any]]:
    values: list[tuple[str, Any]] = []
    status_names = {
        "violationstatusname", "violationstatuscode",
        "statusname", "statuscode", "status", "statustext",
        "paymentstatusname", "paymentstatuscode", "paymentstatus",
        "processstatus", "processstatusname",
        "handlingstatus", "handlingstatusname",
        "paidstatus", "paid", "ispaid", "ispayed",
        "resolved", "isresolved", "processed", "isprocessed",
        "handled", "ishandled",
        # Confirmed in the APK's History.kt model.
        "chargestatusname", "statustype", "statustypetext",
    }
    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                nk = _key_norm(key)
                if nk in status_names or any(token in nk for token in ("status", "paid", "resolved", "processed", "handled")):
                    if not isinstance(value, (dict, list)):
                        values.append((str(key), value))
                elif isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(obj, list):
            for value in obj:
                walk(value, depth + 1)
    walk(violation)
    return values


def _norm_text(value: Any) -> str:
    return "" if value is None else str(value).strip().lower()


def _status_debug(violation: dict[str, Any]) -> dict[str, Any]:
    return {"id": first_value(violation, "violationHistoryId", "vehicleViolationHistoryId", "violationId", "id"),
            "status": _status_values(violation)}


def _is_explicit_resolved(status: str) -> bool:
    status = _norm_text(status)
    return any(marker in status for marker in (
        "đã xử phạt", "da xu phat", "đã nộp phạt", "da nop phat", "đã thanh toán", "da thanh toan",
        "đã giải quyết", "da giai quyet", "đã xử lý", "da xu ly",
        "đã chấp hành", "da chap hanh", "đã hoàn thành", "da hoan thanh",
        "đã nộp tiền", "da nop tien",
        "paid", "resolved", "processed", "handled", "settled", "finished",
        "completed", "true", "complete",
    ))


def _is_explicit_unresolved(status: str) -> bool:
    status = _norm_text(status)
    return any(marker in status for marker in (
        "chưa xử phạt", "chua xu phat", "chưa nộp phạt", "chua nop phat",
        "chưa xử lý", "chua xu ly", "chưa giải quyết", "chua giai quyet",
        "chưa thanh toán", "chua thanh toan", "chưa hoàn tất", "chua hoan tat",
        "chưa chấp hành", "chua chap hanh", "chờ xử lý", "cho xu ly",
        "pending", "unpaid", "unresolved", "outstanding", "waiting", "new",
        "not handled", "unhandled", "false",
    ))


def _has_explicit_resolved_status(violation: dict[str, Any]) -> bool:
    values = _status_values(violation)
    for _, value in values:
        text = _norm_text(value)
        if text and _is_explicit_resolved(text):
            return True
    return False


def _has_explicit_unresolved_status(violation: dict[str, Any]) -> bool:
    values = _status_values(violation)
    for _, value in values:
        text = _norm_text(value)
        if text and _is_explicit_unresolved(text):
            return True
    return False


def _is_unresolved_violation(violation: dict[str, Any]) -> bool:
    values = _status_values(violation)
    if not values:
        return True
    unresolved_seen = False
    resolved_seen = False
    meaningful = 0
    for _, value in values:
        status = _norm_text(value)
        if not status:
            continue
        meaningful += 1
        if _is_explicit_unresolved(status):
            unresolved_seen = True
        elif _is_explicit_resolved(status):
            resolved_seen = True
    if unresolved_seen:
        return True
    if meaningful and resolved_seen:
        return False
    return True


def _is_resolved_violation(violation: dict[str, Any]) -> bool:
    """Return True only when the APK-style record explicitly indicates payment/handling.

    Confirmed field names from the official VNeTraffic APK include:
    isPaid, paidDate, paidDateText, paymentStatus, violationStatusCode,
    and violationStatusName. The explicit payment fields take precedence over
    generic status text because a record may contain both current processing
    status and payment metadata.
    """
    values = _status_values(violation)

    # isPaid is the strongest signal when the backend provides it.
    for key, value in values:
        if _key_norm(key) == "ispaid":
            if isinstance(value, bool):
                return value
            text = _norm_text(value)
            if text in {"true", "1", "yes", "paid", "paidtrue"}:
                return True
            if text in {"false", "0", "no", "unpaid", "unpaidfalse"}:
                return False

    # A non-empty paid date is an explicit paid signal from the APK model.
    # Check this before paymentStatus because some backend responses can carry
    # a stale/generic UNPAID status while still providing the actual paid date.
    for key in ("paidDate", "paidDateText"):
        value = find_first(violation, key)
        if value not in (None, ""):
            return True

    # The APK contains PaymentStatus values PAID / UNPAID.
    payment_values = [
        value for key, value in values
        if _key_norm(key) in {"paymentstatus", "paymentstatuscode", "paymentstatusname"}
    ]
    for value in payment_values:
        text = _norm_text(value)
        compact = text.replace("_", "").replace("-", "")
        if compact in {"paid", "dapaid", "daxuphat", "danopphat", "dathanhtoan"}:
            return True
        if compact in {"unpaid", "unpaidstatus", "chuaxuphat", "chuanopphat", "chuathanhtoan"}:
            return False

    # Finally use the broader resolved/unresolved status classifier.
    return bool(values) and not _is_unresolved_violation(violation)


def _find_count_fields(obj: Any) -> dict[str, int]:
    out: dict[str, int] = {}
    unresolved_tokens = (
        "unresolved", "unprocessed", "unhandled", "pending", "unpaid",
        "pendingcount", "unresolvedcount", "unprocessedcount", "unhandledcount",
        "notprocessed", "notprocessedcount", "notpaid", "notpaidcount",
        "chua_xu_phat", "chuaxuphat", "chua_xu_ly", "chuaxuly",
        "chua_nop_phat", "chuanopphat", "chua_thanh_toan", "chuathanhtoan",
    )
    resolved_tokens = (
        "resolved", "processed", "handled", "paid", "settled", "completed",
        "processedviolations", "paidviolations", "handledviolations",
    )
    total_tokens = (
        "totalviolations", "violationcount", "totalviolationcount", "total",
        "totalelements", "totalcount", "count", "numberofelements",
    )

    def walk(x: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(x, dict):
            for key, value in x.items():
                k = _key_norm(key)
                if isinstance(value, bool):
                    continue
                try:
                    iv = int(value)
                except (TypeError, ValueError):
                    iv = None
                if iv is not None:
                    if any(tok.replace("_", "") in k for tok in unresolved_tokens):
                        out["unresolved"] = max(out.get("unresolved", 0), iv)
                    elif any(tok.replace("_", "") in k for tok in resolved_tokens):
                        out["resolved"] = max(out.get("resolved", 0), iv)
                    elif any(tok.replace("_", "") == k for tok in total_tokens):
                        out["total"] = max(out.get("total", 0), iv)
                if isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(x, list):
            for item in x:
                walk(item, depth + 1)
    walk(obj)
    return out


def _unresolved_items_and_count(raw: dict[str, Any], violations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, dict[str, int]]:
    unresolved = [v for v in violations if _is_unresolved_violation(v)]
    counts = _find_count_fields(raw)
    if "unresolved" in counts:
        return unresolved, max(0, counts["unresolved"]), counts
    if "total" in counts and "resolved" in counts:
        return unresolved, max(0, counts["total"] - counts["resolved"]), counts
    return unresolved, len(unresolved), counts


def _build_violation_attributes(violation: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": first_value(violation, "violationId", "violationHistoryId", "vehicleViolationHistoryId", "idEncrypt", "id"),
        "code": first_value(violation, "violationCode"),
        "name": first_value(violation, "violationName", "violationTypeName", "violationReason"),
        "date": first_value(violation, "violationDate", "violationAt", "violationTime"),
        "address": first_value(violation, "violationAddress", "address"),
        "detecting_unit": first_value(violation, "violationDetectingUnit"),
        "handling_unit": first_value(violation, "violationHandlingUnit"),
        "status": first_value(
            violation,
            "violationStatusName", "violationStatusCode", "statusName", "statusCode", "status",
            "paymentStatusName", "paymentStatusCode", "paymentStatus", "processStatus", "handlingStatus",
        ),
        "raw": violation,
    }
