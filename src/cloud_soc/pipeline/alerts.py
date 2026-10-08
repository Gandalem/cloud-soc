import hashlib
import json
from typing import Any

from cloud_soc.detection.risk import calculate_risk


def make_stable_id(*values: str) -> str:
    # Preserve existing normalized document IDs; do not reindex old data implicitly.
    return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


def make_alert_id(detection: dict[str, Any]) -> str:
    identity = {
        "rule_id": detection["rule_id"],
        "rule_version": detection["rule_version"],
        "group": detection["group"],
        "window_start": detection["window_start"],
        "window_end": detection["window_end"],
        "evidence": detection["evidence"],
    }
    return hashlib.sha256(json.dumps(
        identity, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def build_security_alert(detection: dict[str, Any]) -> dict[str, Any]:
    alert = detection.get("alert", {})
    organization_id = detection["organization_id"]
    if (not isinstance(organization_id, str) or not organization_id.strip()
            or detection["group"].get("organization.id") != organization_id):
        raise ValueError("Detection organization scope is missing or inconsistent")
    document = {
        "@timestamp": detection["window_end"],
        "event": {"kind": "alert", "category": [alert.get("category", "authentication")]},
        "rule": {"id": detection["rule_id"], "name": detection["rule_name"]},
        "organization": {"id": organization_id},
        "cloud_soc": {
            "alert_title": alert.get("title", detection["rule_name"]),
            "severity": detection["severity"],
            "event_count": detection["event_count"],
            "threshold": detection["threshold"],
            "time_window_seconds": detection["time_window_seconds"],
            "window_start": detection["window_start"],
            "window_end": detection["window_end"],
            # Stored in _source only: do not dynamically map arbitrary rule values.
            "provenance": {
                "schema_version": 1,
                "engine_version": detection["engine_version"],
                "rule_version": detection["rule_version"],
                "rule_snapshot": detection["rule_snapshot"],
                "evidence": detection["evidence"],
                "evidence_status": detection["evidence_status"],
            },
        },
        "message": alert.get("message", detection["rule_name"]),
        "tags": alert.get("tags", []),
        "mitre": detection.get("mitre", {}),
    }
    document["cloud_soc"].update(calculate_risk(detection))
    if source_ip := detection["group"].get("source.ip"):
        document["source"] = {"ip": source_ip}
    return document
