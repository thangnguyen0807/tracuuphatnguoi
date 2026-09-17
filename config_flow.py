from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

from .const import (
    CONF_LICENSE_PLATE,
    CONF_SCAN_INTERVAL,
    CONF_VEHICLE_TYPE,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    VEHICLE_TYPES,
)


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 3

    async def async_step_user(self, user_input=None):
        errors = {}
        existing = [
            e for e in self.hass.config_entries.async_entries(DOMAIN)
            if e.data.get(CONF_USERNAME) and e.data.get(CONF_PASSWORD)
        ]

        # First setup: authenticate once and save the credentials in the account entry.
        if not existing:
            if user_input is not None:
                plate = user_input[CONF_LICENSE_PLATE].strip().upper()
                unique = plate.replace(" ", "")
                if not unique:
                    errors[CONF_LICENSE_PLATE] = "invalid_plate"
                else:
                    await self.async_set_unique_id(unique)
                    self._abort_if_unique_id_configured()
                    user_input[CONF_LICENSE_PLATE] = plate
                    return self.async_create_entry(
                        title=f"VNeTraffic {plate}",
                        data=user_input,
                    )

            schema = vol.Schema({
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Required(CONF_LICENSE_PLATE): str,
                vol.Optional(CONF_VEHICLE_TYPE, default="auto"): vol.In(VEHICLE_TYPES),
                vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
                    vol.Coerce(int), vol.Range(min=300, max=86400)
                ),
            })
            return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

        # Additional vehicles: reuse the first saved VNeTraffic account.
        account = existing[0]
        if user_input is not None:
            plate = user_input[CONF_LICENSE_PLATE].strip().upper()
            unique = plate.replace(" ", "")
            if not unique:
                errors[CONF_LICENSE_PLATE] = "invalid_plate"
            else:
                await self.async_set_unique_id(unique)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"VNeTraffic {plate}",
                    data={
                        CONF_USERNAME: account.data[CONF_USERNAME],
                        CONF_PASSWORD: account.data[CONF_PASSWORD],
                        CONF_LICENSE_PLATE: plate,
                        CONF_VEHICLE_TYPE: user_input.get(CONF_VEHICLE_TYPE, "auto"),
                        CONF_SCAN_INTERVAL: user_input.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    },
                )

        schema = vol.Schema({
            vol.Required(CONF_LICENSE_PLATE): str,
            vol.Optional(CONF_VEHICLE_TYPE, default="auto"): vol.In(VEHICLE_TYPES),
            vol.Optional(CONF_SCAN_INTERVAL, default=DEFAULT_SCAN_INTERVAL): vol.All(
                vol.Coerce(int), vol.Range(min=300, max=86400)
            ),
        })
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            description_placeholders={"account": str(account.data[CONF_USERNAME])},
            errors=errors,
        )
