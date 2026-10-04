"""Replayable, bounded snapshot bridge for the existing AUTH-001 rule."""

from copy import deepcopy
from datetime import datetime, timezone

from cloud_soc.detection.engine import detect_events, event_evidence
from cloud_soc.detection.rule_loader import load_rules, PROJECT_ROOT
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping, save_security_alert
from cloud_soc.main import build_security_alert, make_alert_id
from cloud_soc.processing.contract import NORMALIZED, STATUS
from cloud_soc.portal.log_contract import document_reference

ALERTS = "security-alerts"


def approved_rules(*, include_cloud=False):
    rules = [rule for rule in load_rules() if rule["id"] == "AUTH-001"]
    if len(rules) != 1:
        raise ValueError("Existing AUTH-001 must be enabled")
    if include_cloud:
        rules += load_rules(PROJECT_ROOT / 'rules' / 'cloud.yml')
        if len({rule['id'] for rule in rules}) != len(rules):
            raise ValueError('Duplicate rule IDs across profiles')
    return rules


def normalized_snapshot(client, max_documents):
    # Refuse aliases/data streams so every evidence reference identifies the
    # intended concrete normalized index. The runtime key cannot create it.
    resolved = client.indices.resolve_index(name=NORMALIZED)
    if (resolved.get("aliases") or resolved.get("data_streams")
            or [row["name"] for row in resolved.get("indices", [])] != [NORMALIZED]):
        raise ValueError("Expected concrete normalized index")
    hits = fetch_all_hits(client, index=NORMALIZED, page_size=500,
                          max_documents=max_documents)
    events = []
    for hit in hits:
        if hit.get("_index") != NORMALIZED or not hit.get("_id"):
            raise ValueError("Unexpected normalized reference")
        event = deepcopy(hit["_source"])
        event["_cloud_soc_meta"] = {"index": NORMALIZED, "document_id": hit["_id"]}
        if not event_evidence(event)["complete"]:
            raise ValueError("Normalized event has no complete provenance")
        raw = event["cloud_soc"]["provenance"]["raw"]
        document_reference(raw["index"], raw["id"])
        events.append(event)
    return events


def run_once(client, *, max_documents=20000, include_cloud=False):
    """Read completely, detect completely, then create immutable alerts.

    No time cursor: a threshold window may cross any two normalizer batches.
    Identical snapshots/rules produce identical IDs across process restarts.
    This is not an incremental engine or semantic exactly-once delivery.
    """
    if type(max_documents) is not int or not 1 <= max_documents <= 100000:
        raise ValueError("max_documents must be between 1 and 100000")

    def status(state, **extra):
        stamp = datetime.now(timezone.utc).isoformat()
        document = {"@timestamp": stamp, "state": state, "detection": 'AUTH-001,cloud' if include_cloud else 'AUTH-001', **extra}
        if state == "success":
            document["last_success"] = stamp
        client.index(index=STATUS, id="detector", document=document, refresh=False)

    try:
        status("running")
        rules = approved_rules(include_cloud=include_cloud)
        if set(client.indices.get_mapping(index=ALERTS)) != {ALERTS}:
            raise ValueError("Expected concrete alert index")
        ensure_provenance_mapping(client, ALERTS)
        events = normalized_snapshot(client, max_documents)
        rejected = []
        detections = detect_events(events, rules, rejected=rejected)
        if rejected:
            raise ValueError("Invalid normalized detection input")
        alerts = [(make_alert_id(row), build_security_alert(row)) for row in detections]
        counts = {"events": len(events), "created": 0, "existing": 0}
        for document_id, document in alerts:
            result = save_security_alert(client, document, index_name=ALERTS,
                                         document_id=document_id, refresh=False,
                                         index_prepared=True)
            if result["result"] not in ("created", "existing"):
                raise RuntimeError("Unexpected immutable write result")
            counts[result["result"]] += 1
        status("success")
        return counts
    except Exception:
        try:
            status("failed", error="detection_cycle_failed")
        except Exception:
            pass  # Do not mask the original failure or print raw payloads.
        raise RuntimeError("detection_cycle_failed; retry the complete snapshot") from None
