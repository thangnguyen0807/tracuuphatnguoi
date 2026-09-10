from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_NAME

from .const import (
    CONF_ACCESS_TOKEN,
    CONF_LICENSE_PLATE,
    CONF_SCAN_INTERVAL,
    CONF_VEHICLE_TYPE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    VEHICLE_TYPES,
)


class VNeTrafficConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            plate = user_input[CONF_LICENSE_PLATE].strip().upper()
            unique = plate.replace(" ", "")
            await self.async_set_unique_id(unique)
            self._abort_if_unique_id_configured()
            user_input[CONF_LICENSE_PLATE] = plate
            return self.async_create_entry(
                title=f"VNeTraffic {plate}",
                data=user_input,
            )

        schema = vol.Schema({
            vol.Required(CONF_LICENSE_PLATE): str,
            vol.Optional(CONF_VEHICLE_TYPE, default="auto"): vol.In(VEHICLE_TYPES),
            vol.Optional(CONF_ACCESS_TOKEN, default=""): str,
            vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(vol.Coerce(int), vol.Range(min=300, max=86400)),
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
