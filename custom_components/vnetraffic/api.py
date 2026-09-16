from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import json
import uuid
import base64
import os

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


class VNeTrafficApi:
    """Client matching the official VNeTraffic Android API flow."""

    def __init__(self, session: aiohttp.ClientSession, username: str, password: str, base_url: str = DEFAULT_BASE_URL) -> None:
        self.session = session
        self.username = username.strip()
        self.password = password
        self.base_url = _normalize_api_base_url(base_url)
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.device_id = _stable_device_id(self.username)
        self._public_key: str | None = None
        self._remote_config_loaded = False

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
        if not self.access_token:
            await self.login()

    async def lookup(self, license_plate: str) -> LookupResult:
        plate = normalize_plate(license_plate)
        if not plate:
            raise VNeTrafficError("Biển số xe không hợp lệ")

        await self._ensure_authenticated()
        await self._load_remote_config()
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
