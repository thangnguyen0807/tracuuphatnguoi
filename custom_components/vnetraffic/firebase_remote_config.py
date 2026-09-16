from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any
import re

from cryptography.hazmat.primitives import serialization

import aiohttp

FIREBASE_PROJECT_ID = "c08-patrol"
FIREBASE_APP_ID = "1:518739442817:android:94bded8ac9881b3c886180"
# This is the Firebase API key embedded in the official APK. The APK's
# Firebase configuration may be restricted/rotated, so Firebase must not be
# a hard dependency for Home Assistant login.
FIREBASE_API_KEY = "AIzaSyC1uifpFWuDrO-W-ueF18S2pxd9nQ-61dI"
FIREBASE_PACKAGE = "com.ots.c08.vnetraffic"
# SHA-1 of the official APK signing certificate extracted from the APK v2 signing block.
FIREBASE_ANDROID_CERT_SHA1 = "21DA623AF5D6AD7653ECE2062C44A98A71C94C23"
RC_FETCH_URL = (
    "https://firebaseremoteconfig.googleapis.com"
    f"/v1/projects/{FIREBASE_PROJECT_ID}/namespaces/firebase:fetch"
)
FIS_URL = f"https://firebaseinstallations.googleapis.com/v1/projects/{FIREBASE_PROJECT_ID}/installations"

# RSA public key recovered directly from the bundled VNeTraffic APK.
# This is intentionally public material and is used as the offline fallback
# when Firebase Installations/Remote Config is unavailable or rejects the APK
# Firebase API key.
EMBEDDED_VNETRAFFIC_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkJWd47Jbrj8vpOw5dHA5
5zihr5638Xac75xkOLxoHzG+R/auY1wmaTZf7NFyq4wh0NSi8dx50MXET14JFLMY
gXnJZkfAvG9X9uT6E3hd/3T7wNmH2nJw1Brn2QCspc4yAuWWcgHLt8fszJpK6X5R
EwRPobOy0TclnuRmJfXCVIE73wGiL8yo8B8jFYTHqx3ozqRs+zHpJxnoIPhFvGp7
R4Yuj33s9RCCLVZYuGh5ZQRgU7OlKrqlnacyDEUIQQ+xvb8Ejl9RmsGMwu4spmM2
JohTL9s7w6eFMcFkfozN+YcSFddTvmmsPcrRWFdKfrqTn17ic/6k97H3TXHotqBR
lQIDAQAB
-----END PUBLIC KEY-----
"""


class FirebaseRemoteConfigError(Exception):
    """Raised when Firebase Installation/Remote Config cannot be used."""


@dataclass(frozen=True)
class VNeTrafficRemoteConfig:
    base_url: str
    public_key: str


def _new_fid() -> str:
    # Firebase Installation IDs are 22-character URL-safe identifiers.
    return base64.urlsafe_b64encode(secrets.token_bytes(17)).decode("ascii").rstrip("=")[:22]


async def fetch_remote_config(session: aiohttp.ClientSession) -> VNeTrafficRemoteConfig:
    """Fetch the two runtime values used by the APK, with APK fallbacks."""
    try:
        values = await _fetch_from_firebase(session)
        base_url = str(values.get("VNeTRAFFIC_baseUrlAPI") or "").strip().rstrip("/")
        public_key = _normalize_public_key(values.get("VNeTRAFFIC_public_key"))
        if not base_url or not public_key:
            raise FirebaseRemoteConfigError("Firebase Remote Config thiếu cấu hình VNeTraffic")
        return VNeTrafficRemoteConfig(base_url=base_url, public_key=public_key)
    except FirebaseRemoteConfigError:
        return VNeTrafficRemoteConfig(
            base_url="https://citizen-api.vnetraffic.gov.vn",
            public_key=EMBEDDED_VNETRAFFIC_PUBLIC_KEY,
        )


async def _fetch_from_firebase(session: aiohttp.ClientSession) -> dict[str, Any]:
    """Fetch VNeTRAFFIC_baseUrlAPI and VNeTRAFFIC_public_key."""
    fid = _new_fid()
    fis_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-goog-api-key": FIREBASE_API_KEY,
        "X-Android-Package": FIREBASE_PACKAGE,
        "X-Android-Cert": FIREBASE_ANDROID_CERT_SHA1,
        "User-Agent": "VNeTraffic/1.1.44 (Home Assistant)",
    }
    fis_body = {
        "fid": fid,
        "authVersion": "FIS_v2",
        "appId": FIREBASE_APP_ID,
        "sdkVersion": "a:18.0.0",
    }

    try:
        async with session.post(
            FIS_URL,
            json=fis_body,
            headers=fis_headers,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise FirebaseRemoteConfigError(
                    f"Firebase Installations HTTP {resp.status}: {text[:500]}"
                )
            data = json.loads(text)
    except (aiohttp.ClientError, json.JSONDecodeError) as err:
        raise FirebaseRemoteConfigError(f"Firebase Installations lỗi: {err}") from err

    registered_fid = str(data.get("fid") or fid)
    auth = data.get("authToken") or {}
    auth_token = auth.get("token") if isinstance(auth, dict) else None
    if not auth_token:
        raise FirebaseRemoteConfigError("Firebase không trả về installation auth token")

    rc_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "If-None-Match": "*",
        "X-Goog-Api-Key": FIREBASE_API_KEY,
        "X-Android-Package": FIREBASE_PACKAGE,
        "X-Android-Cert": FIREBASE_ANDROID_CERT_SHA1,
        "X-Goog-Firebase-Installations-Auth": auth_token,
        "User-Agent": "VNeTraffic/1.1.44 (Home Assistant)",
    }
    rc_body = {
        "sdk_version": "a:18.0.0",
        "app_instance_id": registered_fid,
        "app_instance_id_token": auth_token,
        "app_id": FIREBASE_APP_ID,
        "language_code": "vi",
    }
    url = RC_FETCH_URL

    try:
        async with session.post(
            url,
            json=rc_body,
            headers=rc_headers,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as resp:
            text = await resp.text()
            if resp.status >= 400:
                raise FirebaseRemoteConfigError(
                    f"Firebase Remote Config HTTP {resp.status}: {text[:700]}"
                )
            data = json.loads(text)
    except (aiohttp.ClientError, json.JSONDecodeError) as err:
        raise FirebaseRemoteConfigError(f"Firebase Remote Config lỗi: {err}") from err

    if data.get("state") == "NO_TEMPLATE":
        raise FirebaseRemoteConfigError("Firebase Remote Config chưa có template")

    entries = data.get("entries")
    public_key = _find_key(entries, "VNeTRAFFIC_public_key")
    base_url = _find_key(entries, "VNeTRAFFIC_baseUrlAPI")
    if not public_key or not base_url:
        raise FirebaseRemoteConfigError(
            "Không tìm thấy VNeTRAFFIC_baseUrlAPI hoặc VNeTRAFFIC_public_key"
        )
    return {
        "VNeTRAFFIC_baseUrlAPI": str(base_url),
        "VNeTRAFFIC_public_key": str(public_key),
    }


def _normalize_public_key(value: Any) -> str | None:
    """Normalize Firebase public-key values to a valid PEM string.

    Remote Config may return the value JSON-escaped, quoted, or as base64 DER.
    Invalid values are rejected so the caller can safely fall back to the APK key.
    """
    if value is None:
        return None

    text = str(value).strip()
    candidates = [text]

    # Handle JSON-style quoted/escaped strings and literal backslash-n sequences.
    try:
        decoded = json.loads(text) if text[:1] in {'"', "'"} else text
    except Exception:
        decoded = text
    candidates.append(str(decoded).strip().replace("\\n", "\n"))

    # Some Firebase values can contain surrounding quotes or whitespace.
    candidates.append(candidates[-1].strip('\"\'').strip())

    for candidate in candidates:
        if "-----BEGIN" not in candidate or "-----END" not in candidate:
            continue
        try:
            key = serialization.load_pem_public_key(candidate.encode("utf-8"))
        except (ValueError, TypeError):
            continue
        if not hasattr(key, "encrypt"):
            continue
        return candidate

    # Fallback for a base64-encoded DER SubjectPublicKeyInfo value.
    compact = re.sub(r"\s+", "", text.strip('\"\''))
    try:
        raw = base64.b64decode(compact, validate=True)
        key = serialization.load_der_public_key(raw)
    except Exception:
        return None
    if hasattr(key, "encrypt"):
        return serialization.public_bytes(key) if False else _der_to_pem(key)
    return None


def _der_to_pem(key: Any) -> str:
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _find_key(value: Any, key: str) -> Any:
    wanted = key.casefold()
    if isinstance(value, dict):
        for k, v in value.items():
            if str(k).casefold() == wanted and v not in (None, ""):
                return v
        for v in value.values():
            result = _find_key(v, key)
            if result not in (None, ""):
                return result
    elif isinstance(value, list):
        for v in value:
            result = _find_key(v, key)
            if result not in (None, ""):
                return result
    return None


async def fetch_public_key(session: aiohttp.ClientSession) -> str:
    """Compatibility wrapper returning the APK/Firebase RSA key."""
    return (await fetch_remote_config(session)).public_key
