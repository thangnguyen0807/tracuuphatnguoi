from __future__ import annotations

from typing import Any

from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .api import first_value, _status_debug


def _status_values(violation: dict[str, Any]) -> list[tuple[str, Any]]:
    """Collect status/payment fields from one violation record."""
    wanted = (
        "violationstatus", "status", "paymentstatus", "processingstatus",
        "handlingstatus", "penaltystatus", "enforcementstatus",
        "resolved", "processed", "paid", "settled", "handled", "unhandled",
    )
    result: list[tuple[str, Any]] = []
    seen: set[str] = set()

    def walk(obj: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                low = str(key).lower().replace("_", "").replace("-", "")
                if any(token in low for token in wanted) and value not in (None, ""):
                    marker = f"{key}:{repr(value)}"
                    if marker not in seen:
                        seen.add(marker)
                        result.append((str(key), value))
                if isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                walk(item, depth + 1)

    walk(violation)
    return result


def _norm_text(value: Any) -> str:
    return str(value if value is not None else "").strip().lower().replace("_", " ").replace("-", " ")


def _is_explicit_resolved(status: str) -> bool:
    status = _norm_text(status)
    return any(marker in status for marker in (
        "đã xử phạt", "da xu phat", "đã nộp phạt", "da nop phat",
        "đã xử lý", "da xu ly", "đã giải quyết", "da giai quyet",
        "đã thanh toán", "da thanh toan", "đã hoàn tất", "da hoan tat",
        "đã chấp hành", "da chap hanh", "paid", "resolved", "processed",
        "completed", "closed", "settled", "handled", "finished",
    ))


def _is_explicit_unresolved(status: str) -> bool:
    status = _norm_text(status)
    return any(marker in status for marker in (
        "chưa xử phạt", "chua xu phat", "chưa nộp phạt", "chua nop phat",
        "chưa xử lý", "chua xu ly", "chưa giải quyết", "chua giai quyet",
        "chưa thanh toán", "chua thanh toan", "chưa hoàn tất", "chua hoan tat",
        "chưa chấp hành", "chua chap hanh", "chờ xử lý", "cho xu ly",
        "pending", "unpaid", "unresolved", "outstanding", "waiting", "new",
        "not handled", "unhandled", "false",
    ))


def _is_unresolved_violation(violation: dict[str, Any]) -> bool:
    """Determine whether a single violation is still unresolved."""
    values = _status_values(violation)
    if not values:
        # The history endpoint can omit status for open violations. Do not drop it.
        return True

    unresolved_seen = False
    resolved_seen = False
    meaningful = 0
    for _, value in values:
        status = _norm_text(value)
        if not status:
            continue
        meaningful += 1
        if _is_explicit_unresolved(status):
            unresolved_seen = True
        elif _is_explicit_resolved(status):
            resolved_seen = True

    if unresolved_seen:
        return True
    if meaningful and resolved_seen:
        return False
    return True


def _find_count_fields(obj: Any) -> dict[str, int]:
    """Find explicit unresolved/processed/total violation counters in raw API data.

    Some VNeTraffic backend revisions return counts in a summary object instead of
    putting the processing state on every row. We therefore inspect both shapes.
    """
    out: dict[str, int] = {}
    unresolved_tokens = (
        "unresolved", "unprocessed", "unhandled", "pending", "unpaid",
        "notprocessed", "not_processed", "notpaid", "not_paid",
        "chua_xu_phat", "chuaxuphat", "chua_xu_ly", "chuaxuly",
        "chua_nop_phat", "chuanopphat", "chua_thanh_toan", "chuathanhtoan",
    )
    resolved_tokens = (
        "resolved", "processed", "handled", "paid", "settled", "completed",
        "processedviolations", "paidviolations", "handledviolations",
    )
    total_tokens = ("totalviolations", "violationcount", "totalviolationcount")

    def walk(x: Any, depth: int = 0) -> None:
        if depth > 10:
            return
        if isinstance(x, dict):
            for key, value in x.items():
                k = str(key).lower().replace("-", "").replace("_", "")
                if isinstance(value, bool):
                    continue
                try:
                    iv = int(value)
                except (TypeError, ValueError):
                    iv = None
                if iv is not None:
                    if any(tok.replace("_", "") in k for tok in unresolved_tokens):
                        out.setdefault("unresolved", iv)
                    elif any(tok.replace("_", "") in k for tok in resolved_tokens):
                        out.setdefault("resolved", iv)
                    elif any(tok.replace("_", "") == k for tok in total_tokens):
                        out.setdefault("total", iv)
                if isinstance(value, (dict, list)):
                    walk(value, depth + 1)
        elif isinstance(x, list):
            for item in x:
                walk(item, depth + 1)
    walk(obj)
    return out


def _unresolved_items_and_count(raw: dict[str, Any], violations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, dict[str, int]]:
    """Return unresolved rows plus the most reliable unresolved count available."""
    unresolved = [v for v in violations if _is_unresolved_violation(v)]
    counts = _find_count_fields(raw)

    # Prefer an explicit server-provided unresolved count when available.
    if "unresolved" in counts:
        return unresolved, max(0, counts["unresolved"]), counts

    if "total" in counts and "resolved" in counts:
        return unresolved, max(0, counts["total"] - counts["resolved"]), counts

    return unresolved, len(unresolved), counts


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
            "violationStatusName",
            "violationStatusCode",
            "statusName",
            "statusCode",
            "status",
            "paymentStatusName",
            "paymentStatusCode",
            "paymentStatus",
        ),
        "raw": violation,
    }
from .const import DOMAIN, NAME, CONF_LICENSE_PLATE, CONF_VEHICLE_TYPE
from .coordinator import VNeTrafficCoordinator


def _server_count(data: dict[str, Any] | None, key: str) -> int | None:
    if not isinstance(data, dict):
        return None
    for container_key in ("_history_counts", "_deferred_fine_counts", "_pending_fine_counts", "_dashboard_violations_counts"):
        counts = data.get(container_key)
        if isinstance(counts, dict) and isinstance(counts.get(key), int):
            return max(0, counts[key])
    return None


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator: VNeTrafficCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(
        [
            VNeTrafficSensor(coordinator, entry.data),
            VNeTrafficUnresolvedSensor(coordinator, entry.data),
        ],
        update_before_add=True,
    )


class VNeTrafficSensor(CoordinatorEntity[VNeTrafficCoordinator], SensorEntity):
    _attr_icon = "mdi:car-search"
    _attr_has_entity_name = True

    def __init__(self, coordinator, config):
        super().__init__(coordinator)
        self._attr_unique_id = f"{DOMAIN}_{config[CONF_LICENSE_PLATE].replace(' ', '').lower()}"
        self._attr_name = "Số lần vi phạm"
        self.plate = config[CONF_LICENSE_PLATE]
        self.vehicle_type = config.get(CONF_VEHICLE_TYPE, "auto")

    @property
    def native_value(self) -> int:
        data = self.coordinator.data or {}
        rows = data.get("violations", [])
        server_total = _server_count(data, "total")
        if server_total is not None and (server_total > 0 or not rows):
            return server_total
        return len(rows)

    @property
    def native_unit_of_measurement(self) -> str:
        return "vi phạm"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        violations = self.coordinator.data.get("violations", []) if self.coordinator.data else []
        latest = [_build_violation_attributes(v) for v in violations]
        raw = self.coordinator.data.get("raw", {}) if self.coordinator.data else {}
        pending_rows = self.coordinator.data.get("pending_violations", []) if self.coordinator.data else []
        unresolved, unresolved_count, summary_counts = _unresolved_items_and_count(raw, violations)
        deferred_total = _server_count(self.coordinator.data, "deferred_total")
        if pending_rows:
            unresolved = pending_rows
            unresolved_count = deferred_total if deferred_total is not None else len(pending_rows)
        elif deferred_total is not None:
            unresolved_count = deferred_total
        return {
            "license_plate": self.plate,
            "vehicle_type": self.vehicle_type,
            "violation_count": _server_count(self.coordinator.data, "total") if _server_count(self.coordinator.data, "total") is not None else len(latest),
            "unresolved_violation_count": unresolved_count,
            "server_violation_counts": summary_counts,
            "violations": latest,
            "unresolved_violations": [_build_violation_attributes(v) for v in unresolved],
            "unresolved_status_debug": [_status_debug(v) for v in violations],
            "source": "VNeTraffic official citizen API",
            "api_debug": self.coordinator.data.get("debug", {}) if self.coordinator.data else {},
        }


class VNeTrafficUnresolvedSensor(CoordinatorEntity[VNeTrafficCoordinator], SensorEntity):
    _attr_icon = "mdi:alert-circle"
    _attr_has_entity_name = True
    _attr_native_unit_of_measurement = "vi phạm"

    def __init__(self, coordinator, config):
        super().__init__(coordinator)
        plate = config[CONF_LICENSE_PLATE].replace(" ", "").lower()
        self._attr_unique_id = f"{DOMAIN}_{plate}_unresolved"
        self._attr_name = "Số lần phạt nguội"
        self.plate = config[CONF_LICENSE_PLATE]
        self.vehicle_type = config.get(CONF_VEHICLE_TYPE, "auto")

    @property
    def native_value(self) -> int:
        data = self.coordinator.data or {}
        pending_rows = data.get("pending_violations", [])
        deferred_total = _server_count(data, "deferred_total")
        if deferred_total is not None:
            return deferred_total
        if pending_rows:
            return len(pending_rows)
        violations = data.get("violations", [])
        raw = data.get("raw", {})
        _unresolved, unresolved_count, _counts = _unresolved_items_and_count(raw, violations)
        return unresolved_count

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        violations = self.coordinator.data.get("violations", []) if self.coordinator.data else []
        raw = self.coordinator.data.get("raw", {}) if self.coordinator.data else {}
        unresolved_raw, unresolved_count, summary_counts = _unresolved_items_and_count(raw, violations)
        pending_rows = self.coordinator.data.get("pending_violations", []) if self.coordinator.data else []
        deferred_total = _server_count(self.coordinator.data, "deferred_total")
        if pending_rows:
            unresolved_raw = pending_rows
            unresolved_count = deferred_total if deferred_total is not None else len(pending_rows)
        elif deferred_total is not None:
            unresolved_count = deferred_total
        unresolved = [_build_violation_attributes(v) for v in unresolved_raw]
        return {
            "license_plate": self.plate,
            "vehicle_type": self.vehicle_type,
            "violation_count": unresolved_count,
            "deferred_fine_count": deferred_total,
            "server_violation_counts": summary_counts,
            "violations": unresolved,
            "status_debug": [_status_debug(v) for v in violations],
            "source": "VNeTraffic official citizen API",
            "api_debug": self.coordinator.data.get("debug", {}) if self.coordinator.data else {},
        }
