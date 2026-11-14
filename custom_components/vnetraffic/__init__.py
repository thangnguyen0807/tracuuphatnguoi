from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .accounts import account_identity, effective_credentials
from .const import CONF_LICENSE_PLATE, CONF_VEHICLE_TYPE, DOMAIN
from .coordinator import VNeTrafficCoordinator

PLATFORMS = ["sensor"]
_ACCOUNTS_KEY = "_accounts"
_ENTRY_ACCOUNTS_KEY = "_entry_accounts"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    from .api import VNeTrafficApi

    session = async_get_clientsession(hass)
    domain_data = hass.data.setdefault(DOMAIN, {})
    accounts = domain_data.setdefault(_ACCOUNTS_KEY, {})
    username, password = effective_credentials(entry)
    account_key = account_identity(username, password)
    account = accounts.get(account_key)
    if account is None:
        api = VNeTrafficApi(
            session,
            username=username,
            password=password,
            vehicle_type=entry.data.get(CONF_VEHICLE_TYPE, "auto"),
        )
        account = {"api": api, "refs": 0}
        accounts[account_key] = account
    else:
        api = account["api"]
    account["refs"] += 1

    try:
        coordinator = VNeTrafficCoordinator(
            hass,
            api,
            entry.data[CONF_LICENSE_PLATE],
            86400,  # Exactly one automatic lookup cycle per vehicle per day
            vehicle_type=entry.data.get(CONF_VEHICLE_TYPE, "auto"),
        )
        await coordinator.async_config_entry_first_refresh()
        domain_data[entry.entry_id] = coordinator
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    except Exception:
        domain_data.pop(entry.entry_id, None)
        account["refs"] -= 1
        if account["refs"] == 0:
            accounts.pop(account_key, None)
        raise
    domain_data.setdefault(_ENTRY_ACCOUNTS_KEY, {})[entry.entry_id] = account_key
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        domain_data = hass.data.get(DOMAIN, {})
        domain_data.pop(entry.entry_id, None)
        accounts = domain_data.get(_ACCOUNTS_KEY, {})
        # Options may already contain the *new* credentials during a reload.
        # Release the account actually used before the change, not the new one.
        account_key = domain_data.get(_ENTRY_ACCOUNTS_KEY, {}).pop(entry.entry_id, None)
        account = accounts.get(account_key)
        if account:
            account["refs"] = max(0, int(account.get("refs", 1)) - 1)
            if account["refs"] == 0:
                accounts.pop(account_key, None)
    return unload_ok
