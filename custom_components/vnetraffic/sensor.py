from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import first_value, _status_debug
from .const import DOMAIN, CONF_LICENSE_PLATE, CONF_VEHICLE_TYPE
from .coordinator import VNeTrafficCoordinator


def _build_violation_attributes(violation: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": first_value(violation, "violationId", "violationHistoryId", "vehicleViolationHistoryId", "idEncrypt", "id"),
        "code": first_value(violation, "violationCode"),
        "name": first_value(violation, "violationName", "violationTypeName", "violationReason"),
        "date": first_value(violation, "violationDate", "violationAt", "violationTime"),
        "address": first_value(violation, "violationAddress", "address"),
        "detecting_unit": first_value(violation, "violationDetectingUnit"),
        "handling_unit": first_value(violation, "violationHandlingUnit"),
        "status": first_value(
            violation,
            "violationStatusName", "violationStatusCode", "statusName", "statusCode",
            "status", "paymentStatusName", "paymentStatusCode", "paymentStatus",
        ),
        "raw": violation,
    }


def _counts(data: dict[str, Any]) -> tuple[int, int, int]:
    """Read the three effective counters calculated by api.py."""
    return (
        max(0, int(data.get("total_violation_count", 0) or 0)),
        max(0, int(data.get("processed_violation_count", 0) or 0)),
        max(0, int(data.get("unresolved_violation_count", 0) or 0)),
    )


def _attributes(coordinator: VNeTrafficCoordinator, plate: str, vehicle_type: str) -> dict[str, Any]:
    data = coordinator.data or {}
    raw = data.get("raw", {}) if isinstance(data, dict) else {}
    violations = data.get("violations", []) if isinstance(data, dict) else []
    pending = data.get("pending_violations", []) if isinstance(data, dict) else []
    total, processed, unresolved = _counts(data if isinstance(data, dict) else {})
    return {
        "license_plate": plate,
        "vehicle_type": vehicle_type,
        "violation_count": total,
        "processed_violation_count": processed,
        "unresolved_violation_count": unresolved,
        "violations": [_build_violation_attributes(v) for v in violations],
        "unresolved_violations": [_build_violation_attributes(v) for v in pending],
        "unresolved_status_debug": [_status_debug(v) for v in violations],
        "api_debug": data.get("debug", {}) if isinstance(data, dict) else {},
        "source": "VNeTraffic official citizen API",
    }


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: VNeTrafficCoordinator = hass.data[DOMAIN][entry.entry_id]
    config = entry.data
    async_add_entities(
        [
            VNeTrafficSensor(coordinator, config),
            VNeTrafficProcessedSensor(coordinator, config),
            VNeTrafficUnresolvedSensor(coordinator, config),
        ],
        update_before_add=True,
    )


class VNeTrafficSensor(CoordinatorEntity[VNeTrafficCoordinator], SensorEntity):
    _attr_icon = "mdi:car-search"
    _attr_has_entity_name = True
    _attr_native_unit_of_measurement = "vi phạm"

    def __init__(self, coordinator, config):
        super().__init__(coordinator)
        plate = config[CONF_LICENSE_PLATE]
        self._attr_unique_id = f"{DOMAIN}_{plate.replace(' ', '').lower()}"
        self._attr_name = "Số lần vi phạm"
        self.plate = plate
        self.vehicle_type = config.get(CONF_VEHICLE_TYPE, "auto")

    @property
    def native_value(self) -> int:
        return _counts(self.coordinator.data or {})[0]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return _attributes(self.coordinator, self.plate, self.vehicle_type)


class VNeTrafficProcessedSensor(CoordinatorEntity[VNeTrafficCoordinator], SensorEntity):
    _attr_icon = "mdi:check-circle"
    _attr_has_entity_name = True
    _attr_native_unit_of_measurement = "vi phạm"

    def __init__(self, coordinator, config):
        super().__init__(coordinator)
        plate = config[CONF_LICENSE_PLATE]
        self._attr_unique_id = f"{DOMAIN}_{plate.replace(' ', '').lower()}_processed"
        self._attr_name = "Đã xử phạt"
        self.plate = plate
        self.vehicle_type = config.get(CONF_VEHICLE_TYPE, "auto")

    @property
    def native_value(self) -> int:
        return _counts(self.coordinator.data or {})[1]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return _attributes(self.coordinator, self.plate, self.vehicle_type)


class VNeTrafficUnresolvedSensor(CoordinatorEntity[VNeTrafficCoordinator], SensorEntity):
    _attr_icon = "mdi:alert-circle"
    _attr_has_entity_name = True
    _attr_native_unit_of_measurement = "vi phạm"

    def __init__(self, coordinator, config):
        super().__init__(coordinator)
        plate = config[CONF_LICENSE_PLATE]
        self._attr_unique_id = f"{DOMAIN}_{plate.replace(' ', '').lower()}_unresolved"
        self._attr_name = "Số lần phạt nguội"
        self.plate = plate
        self.vehicle_type = config.get(CONF_VEHICLE_TYPE, "auto")

    @property
    def native_value(self) -> int:
        return _counts(self.coordinator.data or {})[2]

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return _attributes(self.coordinator, self.plate, self.vehicle_type)
