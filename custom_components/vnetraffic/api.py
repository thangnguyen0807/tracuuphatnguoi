from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import hashlib
import uuid

import aiohttp

from .const import (
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


class VNeTrafficApi:
    """Client matching the official VNeTraffic Android API flow."""

    def __init__(self, session: aiohttp.ClientSession, username: str, password: str, base_url: str = DEFAULT_BASE_URL) -> None:
        self.session = session
        self.username = username.strip()
        self.password = password
        self.base_url = base_url.rstrip("/")
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.device_id = _stable_device_id(self.username)

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
            headers["Device-Info"] = "Home Assistant"
        if authenticated and self.access_token:
            token = self.access_token
            headers["Authorization"] = token if token.lower().startswith("bearer ") else f"Bearer {token}"
        return headers

    async def login(self) -> None:
        if not self.username or not self.password:
            raise VNeTrafficError("Chưa cấu hình tài khoản hoặc mật khẩu VNeTraffic")

        url = f"{self.base_url}/auth/logins"
        # AuthRequest.kt: citizenIdentify, password, fcmToken, latitude, longitude.
        # Gson omits nulls by default, so optional APK fields are omitted here.
        payload = {
            "citizenIdentify": self.username,
            "password": self.password,
        }
        try:
            async with self.session.post(
                url, json=payload, headers=self._headers(), timeout=aiohttp.ClientTimeout(total=20)
            ) as response:
                text = await response.text()
                if response.status >= 400:
                    message = _api_message(text)
                    raise VNeTrafficError(f"VNeTraffic API đăng nhập HTTP {response.status}: {message}")
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
        url = f"{self.base_url}/auth/refresh-token"
        # RefreshTokenRequest.kt: refreshToken, fcmToken, latitude, longitude.
        payload = {"refreshToken": self.refresh_token}
        try:
            async with self.session.post(
                url, json=payload, headers=self._headers(), timeout=aiohttp.ClientTimeout(total=20)
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
        if not self.access_token:
            await self.login()

    async def lookup(self, license_plate: str) -> LookupResult:
        plate = normalize_plate(license_plate)
        if not plate:
            raise VNeTrafficError("Biển số xe không hợp lệ")

        await self._ensure_authenticated()
        url = f"{self.base_url}/property/vehicle-violation/history"
        params = {"licensePlate": plate}

        for attempt in range(2):
            try:
                async with self.session.get(
                    url, params=params, headers=self._headers(authenticated=True), timeout=aiohttp.ClientTimeout(total=20)
                ) as response:
                    text = await response.text()
                    if response.status in (401, 403) and attempt == 0:
                        if await self.refresh():
                            continue
                        self.access_token = None
                        await self.login()
                        continue
                    if response.status >= 400:
                        raise VNeTrafficError(f"VNeTraffic API HTTP {response.status}: {_api_message(text)}")
                    try:
                        data = await response.json(content_type=None)
                    except Exception as err:
                        raise VNeTrafficError(f"API trả về dữ liệu không phải JSON: {text[:300]}") from err
                    break
            except aiohttp.ClientError as err:
                raise VNeTrafficError(f"Không kết nối được VNeTraffic API: {err}") from err
        else:
            raise VNeTrafficError("Không thể xác thực với VNeTraffic API")

        if not isinstance(data, dict):
            data = {"data": data}
        return LookupResult(raw=data, violations=extract_violations(data))


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


def _api_message(text: str) -> str:
    try:
        data = json.loads(text)
        message = find_first(data, "message", "msg", "errorMessage", "error", "error_message")
        if message:
            return str(message)[:300]
    except Exception:
        pass
    return text[:300] or "Lỗi không xác định"


def extract_violations(data: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            if looks_like_violation(obj):
                found.append(obj)
            for value in obj.values():
                walk(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)
    walk(data)
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in found:
        key = str(item.get("violationId") or item.get("violationHistoryId") or json.dumps(item, sort_keys=True, ensure_ascii=False))
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def looks_like_violation(item: dict[str, Any]) -> bool:
    keys = {str(k).lower() for k in item}
    return bool(keys & {
        "violationid", "violationhistoryid", "violationname", "violationcode",
        "violationaddress", "violationdate", "violationstatuscode",
    })
