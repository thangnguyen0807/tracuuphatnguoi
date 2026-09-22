from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import CONF_LICENSE_PLATE, CONF_PASSWORD, CONF_SCAN_INTERVAL, CONF_USERNAME, CONF_VEHICLE_TYPE, DOMAIN
from .coordinator import VNeTrafficCoordinator

PLATFORMS = ["sensor"]
_ACCOUNTS_KEY = "_accounts"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    from .api import VNeTrafficApi

    session = async_get_clientsession(hass)
    domain_data = hass.data.setdefault(DOMAIN, {})
    accounts = domain_data.setdefault(_ACCOUNTS_KEY, {})
    account_key = entry.data[CONF_USERNAME].strip().lower()
    account = accounts.get(account_key)
    if account is None:
        api = VNeTrafficApi(
            session,
            username=entry.data[CONF_USERNAME],
            password=entry.data[CONF_PASSWORD],
            vehicle_type=entry.data.get(CONF_VEHICLE_TYPE, "auto"),
        )
        account = {"api": api, "refs": 0}
        accounts[account_key] = account
    else:
        api = account["api"]
    account["refs"] += 1

    coordinator = VNeTrafficCoordinator(
        hass,
        api,
        entry.data[CONF_LICENSE_PLATE],
        86400,  # Exactly one automatic lookup cycle per vehicle per day
    )
    await coordinator.async_config_entry_first_refresh()
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        domain_data = hass.data.get(DOMAIN, {})
        domain_data.pop(entry.entry_id, None)
        accounts = domain_data.get(_ACCOUNTS_KEY, {})
        account_key = entry.data.get(CONF_USERNAME, "").strip().lower()
        account = accounts.get(account_key)
        if account:
            account["refs"] = max(0, int(account.get("refs", 1)) - 1)
            if account["refs"] == 0:
                accounts.pop(account_key, None)
    return unload_ok
