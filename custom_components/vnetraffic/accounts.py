"""Account selection helpers for independent vehicle configuration entries.

Each vehicle continues to own a standard HA config entry. Credentials can be
in the original entry data or in options after the user switches accounts.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .const import CONF_LICENSE_PLATE, CONF_PASSWORD, CONF_USERNAME, DOMAIN


def effective_credentials(entry: Any) -> tuple[str, str]:
    """Get the active credentials, including an Options Flow account change."""
    options = entry.options or {}
    data = entry.data or {}
    return (
        str(options.get(CONF_USERNAME, data.get(CONF_USERNAME, ""))).strip(),
        str(options.get(CONF_PASSWORD, data.get(CONF_PASSWORD, ""))),
    )


def account_identity(username: str, password: str) -> str:
    """Keep distinct authentication sessions for different credential pairs."""
    encoded = f"{username.strip().casefold()}\x00{password}".encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def available_accounts(hass: Any) -> dict[str, str]:
    """Map representative config-entry IDs to safe, human-readable labels.

    Duplicate credentials are shown once. An account remains available if the
    original vehicle entry is removed but other vehicles still use it.
    """
    choices: dict[str, str] = {}
    seen: set[str] = set()
    for entry in hass.config_entries.async_entries(DOMAIN):
        username, password = effective_credentials(entry)
        if not username or not password:
            continue
        identity = account_identity(username, password)
        if identity in seen:
            continue
        seen.add(identity)
        plate = entry.data.get(CONF_LICENSE_PLATE, "")
        choices[entry.entry_id] = f"{username} (xe {plate})" if plate else username
    return choices


def credentials_from_entry_id(hass: Any, entry_id: str) -> tuple[str, str] | None:
    for entry in hass.config_entries.async_entries(DOMAIN):
        if entry.entry_id == entry_id:
            username, password = effective_credentials(entry)
            if username and password:
                return username, password
    return None
