"""Source time configuration for yearless RFC3164-style authentication logs."""

import re
from datetime import datetime, timedelta, timezone
from typing import Any


def parse_utc_offset(value: str) -> timezone:
    if value in ("UTC", "Z"):
        return timezone.utc
    if not isinstance(value, str) or not re.fullmatch(r"[+-]\d{2}:\d{2}", value):
        raise ValueError("Source timezone must be UTC or a numeric offset such as +09:00")
    hours, minutes = int(value[1:3]), int(value[4:6])
    if hours > 23 or minutes > 59:
        raise ValueError("Invalid source timezone offset")
    return timezone(timedelta(minutes=(hours * 60 + minutes) * (-1 if value[0] == "-" else 1)))


def raw_time_context(
    source: dict[str, Any], *, default_timezone: str = "UTC",
) -> tuple[datetime, timezone, dict[str, Any]]:
    event = source.get("event", {})
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    field = "event.created" if "created" in event else "@timestamp"
    value = event.get("created") if field == "event.created" else source.get("@timestamp")
    if not isinstance(value, str):
        raise ValueError("Raw event needs a stable, timezone-aware reference timestamp")
    reference = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if reference.utcoffset() is None:
        raise ValueError("Raw reference timestamp must contain a timezone")
    explicit = "timezone" in event
    zone = parse_utc_offset(event["timezone"] if explicit else default_timezone)
    return reference, zone, {
        "reference_field": field,
        "reference_time": reference.isoformat(),
        "year_inferred": True,
        "timezone_source": "event.timezone" if explicit else "configured_default",
    }
