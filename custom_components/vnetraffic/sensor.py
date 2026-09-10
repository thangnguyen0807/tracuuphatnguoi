from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import first_value
from .const import DOMAIN, NAME, CONF_LICENSE_PLATE, CONF_VEHICLE_TYPE
from .coordinator import VNeTrafficCoordinator


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: VNeTrafficCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([VNeTrafficSensor(coordinator, entry.data)], update_before_add=True)


class VNeTrafficSensor(CoordinatorEntity[VNeTrafficCoordinator], SensorEntity):
    _attr_icon = "mdi:car-search"
    _attr_has_entity_name = True

    def __init__(self, coordinator, config):
        super().__init__(coordinator)
        self._attr_unique_id = f"{DOMAIN}_{config[CONF_LICENSE_PLATE].replace(' ', '').lower()}"
        self._attr_name = "Phạt nguội"
        self.plate = config[CONF_LICENSE_PLATE]
        self.vehicle_type = config.get(CONF_VEHICLE_TYPE, "auto")

    @property
    def native_value(self) -> int:
        return len(self.coordinator.data.get("violations", [])) if self.coordinator.data else 0

    @property
    def native_unit_of_measurement(self) -> str:
        return "vi phạm"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        violations = self.coordinator.data.get("violations", []) if self.coordinator.data else []
        latest = []
        for v in violations:
            latest.append({
                "id": first_value(v, "violationId", "violationHistoryId"),
                "code": first_value(v, "violationCode"),
                "name": first_value(v, "violationName", "violationTypeName", "violationReason"),
                "date": first_value(v, "violationDate", "violationAt", "violationTime"),
                "address": first_value(v, "violationAddress"),
                "detecting_unit": first_value(v, "violationDetectingUnit"),
                "handling_unit": first_value(v, "violationHandlingUnit"),
                "status": first_value(v, "violationStatusName", "violationStatusCode"),
                "raw": v,
            })
        return {
            "license_plate": self.plate,
            "vehicle_type": self.vehicle_type,
            "violation_count": len(latest),
            "violations": latest,
            "source": "VNeTraffic official citizen API",
        }
