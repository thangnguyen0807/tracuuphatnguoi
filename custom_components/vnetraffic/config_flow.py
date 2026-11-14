"""VNeTraffic vehicle and per-vehicle account flows, with real login verification."""
from __future__ import annotations

import asyncio

import aiohttp
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .accounts import available_accounts, credentials_from_entry_id, effective_credentials
from .api import VNeTrafficApi, VNeTrafficError, VNeTrafficLoginRejected
from .const import (
    CONF_LICENSE_PLATE,
    CONF_SCAN_INTERVAL,
    CONF_VEHICLE_TYPE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    VEHICLE_TYPES,
)

CONF_ACCOUNT_MODE = "account_mode"
CONF_ACCOUNT_SELECTION = "account_selection"
MODE_EXISTING = "existing"
MODE_NEW = "new"
MODE_CHECK_CURRENT = "check_current"


def _vehicle_schema(*, with_credentials: bool = False, with_account_mode: bool = False):
    fields = {
        vol.Required(CONF_LICENSE_PLATE): str,
        vol.Optional(CONF_VEHICLE_TYPE, default="auto"): vol.In(VEHICLE_TYPES),
        vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
            vol.Coerce(int), vol.Range(min=86400, max=86400)
        ),
    }
    if with_credentials:
        fields[vol.Required(CONF_USERNAME)] = str
        fields[vol.Required(CONF_PASSWORD)] = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))
    if with_account_mode:
        fields[vol.Required(CONF_ACCOUNT_MODE, default=MODE_EXISTING)] = vol.In(
            {MODE_EXISTING: "Dùng tài khoản đã lưu", MODE_NEW: "Đăng nhập tài khoản khác"}
        )
    return vol.Schema(fields)


def _account_mode_schema():
    return vol.Schema({
        vol.Required(CONF_ACCOUNT_MODE, default=MODE_EXISTING): vol.In({
            MODE_EXISTING: "Chọn tài khoản đã lưu",
            MODE_NEW: "Đăng nhập tài khoản khác",
            MODE_CHECK_CURRENT: "Kiểm tra lại tài khoản hiện tại",
        })
    })


def _new_account_schema():
    return vol.Schema({
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
    })


def _account_selection_schema(accounts: dict[str, str]):
    return vol.Schema({vol.Required(CONF_ACCOUNT_SELECTION): vol.In(accounts)})


def _normalized_plate(value: str) -> str:
    return str(value).strip().upper()


async def _verify_login(hass, username: str, password: str) -> str | None:
    """Verify credentials with the login endpoint, never performing a fine lookup.

    Return a translated form error, or None only when a real access token was
    issued. No tokens, raw responses or passwords are included in HA flow errors.
    """
    client = VNeTrafficApi(async_get_clientsession(hass), username=username, password=password)
    try:
        await client.login()
    except VNeTrafficLoginRejected:
        return "login_rejected"
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return "cannot_connect"
    except VNeTrafficError:
        return "cannot_verify"
    except Exception:
        # Do not log unexpected response payloads or account information.
        return "cannot_verify"
    return None if client.access_token else "cannot_verify"


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    # Keep v3 config entry data and unique IDs backward compatible.
    VERSION = 3

    def __init__(self):
        super().__init__()
        self._pending_vehicle: dict = {}
        self._verified_credentials: tuple[str, str] | None = None

    async def async_step_user(self, user_input=None):
        errors = {}
        accounts = available_accounts(self.hass)

        if user_input is not None:
            plate = _normalized_plate(user_input.get(CONF_LICENSE_PLATE, ""))
            if not plate or not plate.replace(" ", ""):
                errors[CONF_LICENSE_PLATE] = "invalid_plate"
            else:
                await self.async_set_unique_id(plate.replace(" ", ""))
                self._abort_if_unique_id_configured()
                self._pending_vehicle = {
                    CONF_LICENSE_PLATE: plate,
                    CONF_VEHICLE_TYPE: user_input.get(CONF_VEHICLE_TYPE, "auto"),
                    CONF_SCAN_INTERVAL: user_input.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                }
                if not accounts:
                    username = str(user_input.get(CONF_USERNAME, "")).strip()
                    password = str(user_input.get(CONF_PASSWORD, ""))
                    if not username:
                        errors[CONF_USERNAME] = "required"
                    if not password.strip():
                        errors[CONF_PASSWORD] = "required"
                    if not errors:
                        error = await _verify_login(self.hass, username, password)
                        if error:
                            errors["base"] = error
                        else:
                            return self._confirm_credentials(username, password)
                elif user_input.get(CONF_ACCOUNT_MODE) == MODE_NEW:
                    return await self.async_step_new_account()
                else:
                    return await self.async_step_existing_account()

        return self.async_show_form(
            step_id="user",
            data_schema=_vehicle_schema(
                with_credentials=not accounts,
                with_account_mode=bool(accounts),
            ),
            errors=errors,
        )

    def _confirm_credentials(self, username: str, password: str):
        self._verified_credentials = (username, password)
        return self.async_show_form(
            step_id="confirm_credentials", data_schema=vol.Schema({}),
            description_placeholders={"account": username},
        )

    async def async_step_confirm_credentials(self, user_input=None):
        if self._verified_credentials is None:
            return await self.async_step_user()
        if user_input is not None:
            username, password = self._verified_credentials
            self._verified_credentials = None
            return self.async_create_entry(
                title=f"VNeTraffic {self._pending_vehicle[CONF_LICENSE_PLATE]}",
                data={**self._pending_vehicle, CONF_USERNAME: username, CONF_PASSWORD: password},
            )
        return self._confirm_credentials(*self._verified_credentials)

    async def async_step_existing_account(self, user_input=None):
        accounts = available_accounts(self.hass)
        if not accounts:
            return await self.async_step_new_account()
        errors = {}
        if user_input is not None:
            credentials = credentials_from_entry_id(
                self.hass, user_input.get(CONF_ACCOUNT_SELECTION, "")
            )
            if credentials is None:
                errors[CONF_ACCOUNT_SELECTION] = "account_not_found"
            else:
                error = await _verify_login(self.hass, *credentials)
                if error:
                    errors["base"] = error
                else:
                    return self._confirm_credentials(*credentials)
        return self.async_show_form(
            step_id="existing_account",
            data_schema=_account_selection_schema(accounts),
            errors=errors,
        )

    async def async_step_new_account(self, user_input=None):
        errors = {}
        if user_input is not None:
            username = str(user_input.get(CONF_USERNAME, "")).strip()
            password = str(user_input.get(CONF_PASSWORD, ""))
            if not username:
                errors[CONF_USERNAME] = "required"
            if not password.strip():
                errors[CONF_PASSWORD] = "required"
            if not errors:
                error = await _verify_login(self.hass, username, password)
                if error:
                    errors["base"] = error
                else:
                    return self._confirm_credentials(username, password)
        return self.async_show_form(
            step_id="new_account", data_schema=_new_account_schema(), errors=errors
        )

    @staticmethod
    def async_get_options_flow(config_entry):
        return VNeTrafficOptionsFlow()


class VNeTrafficOptionsFlow(config_entries.OptionsFlowWithReload):
    """Verify existing credentials or switch account without altering plate/data."""

    def __init__(self):
        super().__init__()
        self._verified_credentials: tuple[str, str] | None = None

    async def async_step_init(self, user_input=None):
        accounts = available_accounts(self.hass)
        if user_input is not None:
            mode = user_input.get(CONF_ACCOUNT_MODE)
            if mode == MODE_CHECK_CURRENT:
                return await self.async_step_check_current()
            if mode == MODE_NEW or not accounts:
                return await self.async_step_new_account()
            return await self.async_step_existing_account()
        return self.async_show_form(step_id="init", data_schema=_account_mode_schema())

    async def async_step_check_current(self, user_input=None):
        errors = {}
        if user_input is not None:
            username, password = effective_credentials(self.config_entry)
            if not username or not password:
                errors["base"] = "credentials_missing"
            else:
                error = await _verify_login(self.hass, username, password)
                if error:
                    errors["base"] = error
                else:
                    # A successful check must not save options/reload the vehicle.
                    return self.async_abort(reason="credentials_valid")
        return self.async_show_form(
            step_id="check_current", data_schema=vol.Schema({}), errors=errors,
        )

    async def async_step_existing_account(self, user_input=None):
        accounts = available_accounts(self.hass)
        if not accounts:
            return await self.async_step_new_account()
        errors = {}
        if user_input is not None:
            credentials = credentials_from_entry_id(
                self.hass, user_input.get(CONF_ACCOUNT_SELECTION, "")
            )
            if credentials is None:
                errors[CONF_ACCOUNT_SELECTION] = "account_not_found"
            else:
                error = await _verify_login(self.hass, *credentials)
                if error:
                    errors["base"] = error
                else:
                    return self._confirm_account(*credentials)
        return self.async_show_form(
            step_id="existing_account",
            data_schema=_account_selection_schema(accounts), errors=errors,
        )

    async def async_step_new_account(self, user_input=None):
        errors = {}
        if user_input is not None:
            username = str(user_input.get(CONF_USERNAME, "")).strip()
            password = str(user_input.get(CONF_PASSWORD, ""))
            if not username:
                errors[CONF_USERNAME] = "required"
            if not password.strip():
                errors[CONF_PASSWORD] = "required"
            if not errors:
                error = await _verify_login(self.hass, username, password)
                if error:
                    errors["base"] = error
                else:
                    return self._confirm_account(username, password)
        return self.async_show_form(
            step_id="new_account", data_schema=_new_account_schema(), errors=errors
        )

    def _confirm_account(self, username: str, password: str):
        self._verified_credentials = (username, password)
        return self.async_show_form(
            step_id="confirm_account", data_schema=vol.Schema({}),
            description_placeholders={"account": username},
        )

    async def async_step_confirm_account(self, user_input=None):
        if self._verified_credentials is None:
            return await self.async_step_init()
        if user_input is not None:
            username, password = self._verified_credentials
            self._verified_credentials = None
            # No config-entry data or sensor IDs are touched. HA reloads only
            # this vehicle after persisting the options.
            return self.async_create_entry(
                title="", data={CONF_USERNAME: username, CONF_PASSWORD: password}
            )
        return self._confirm_account(*self._verified_credentials)
