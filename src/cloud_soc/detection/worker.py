"""Replayable, bounded snapshot bridge for the existing AUTH-001 rule."""

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
from typing import Any

from cloud_soc.detection.engine import detect_events, event_evidence
from cloud_soc.detection.rule_loader import PROJECT_ROOT, RuleReloader, load_rules
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping, save_security_alert
from cloud_soc.main import build_security_alert, make_alert_id
from cloud_soc.portal.log_contract import document_reference
from cloud_soc.processing.contract import NORMALIZED, STATUS

ALERTS = "security-alerts"


def _resolve_rules_dir(rules_dir: str | Path | None = None) -> Path | None:
    if rules_dir is not None:
        return Path(rules_dir)
    env_dir = os.getenv("CLOUD_SOC_RULES_DIR")
    return Path(env_dir) if env_dir else None


def approved_rules(
    *,
    include_cloud=False,
    include_sequence=False,
    include_attacks=False,
    include_patterns=False,
    isolated_all=False,
    rule_ids=None,
    additional_rule_ids=None,
    rules_dir: str | Path | None = None,
    reloader: RuleReloader | None = None,
):
    if reloader is not None:
        reloader.reload_if_changed()
        loaded = reloader.rules
        if rule_ids is not None:
            by_id = {rule["id"]: rule for rule in loaded}
            missing = [rid for rid in rule_ids if rid not in by_id]
            if missing:
                raise ValueError("Unknown rule IDs in reloaded ruleset: " + ", ".join(missing))
            return [by_id[rid] for rid in rule_ids]
        return loaded

    if additional_rule_ids is not None:
        if any((include_cloud, include_sequence, include_attacks, include_patterns, isolated_all)) or rule_ids is not None:
            raise ValueError("Conflicting additional rule profile")
        from cloud_soc.detection.profiles import select
        return select(rule_ids=additional_rule_ids, retain_auth=False)
    if isolated_all or rule_ids is not None:
        if any((include_cloud, include_sequence, include_attacks, include_patterns)):
            raise ValueError("Conflicting rule profiles")
        from cloud_soc.detection.profiles import select
        return select(isolated_all=isolated_all, rule_ids=rule_ids)

    custom_dir = _resolve_rules_dir(rules_dir)
    if custom_dir is None:
        # 기존 단위 테스트의 load_rules() 무인자 몽키패치 호환성 유지
        rules = [rule for rule in load_rules() if rule["id"] == "AUTH-001"]
        base_dir = PROJECT_ROOT / "rules"
    else:
        rules = [rule for rule in load_rules(custom_dir / "authentication.yml") if rule["id"] == "AUTH-001"]
        base_dir = custom_dir

    if len(rules) != 1:
        raise ValueError("Existing AUTH-001 must be enabled")
    if include_cloud:
        rules += load_rules(base_dir / "cloud.yml")
    if include_sequence:
        rules += load_rules(base_dir / "authentication_sequence.yml")
    if include_attacks:
        rules += load_rules(base_dir / "attacks.yml")
    if include_patterns:
        rules += load_rules(base_dir / "metadata_patterns.yml")
    if len({rule["id"] for rule in rules}) != len(rules):
        raise ValueError("Duplicate rule IDs across profiles")
    return rules


def normalized_snapshot(client, max_documents):
    # Refuse aliases/data streams so every evidence reference identifies the
    # intended concrete normalized index. The runtime key cannot create it.
    resolved = client.indices.resolve_index(name=NORMALIZED)
    if (
        resolved.get("aliases")
        or resolved.get("data_streams")
        or [row["name"] for row in resolved.get("indices", [])] != [NORMALIZED]
    ):
        raise ValueError("Expected concrete normalized index")
    hits = fetch_all_hits(client, index=NORMALIZED, page_size=500, max_documents=max_documents)
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


def run_once(
    client,
    *,
    max_documents=20000,
    include_cloud=False,
    include_sequence=False,
    include_attacks=False,
    include_patterns=False,
    isolated_all=False,
    rule_ids=None,
    rules_dir: str | Path | None = None,
    reloader: RuleReloader | None = None,
):
    """Read completely, detect completely, then create immutable alerts.

    No time cursor: a threshold window may cross any two normalizer batches.
    Identical snapshots/rules produce identical IDs across process restarts.
    This is not an incremental engine or semantic exactly-once delivery.
    """
    if type(max_documents) is not int or not 1 <= max_documents <= 100000:
        raise ValueError("max_documents must be between 1 and 100000")

    rules = approved_rules(
        include_cloud=include_cloud,
        include_sequence=include_sequence,
        include_attacks=include_attacks,
        include_patterns=include_patterns,
        isolated_all=isolated_all,
        rule_ids=rule_ids,
        rules_dir=rules_dir,
        reloader=reloader,
    )

    def status(state, **extra):
        from cloud_soc.detection.telemetry import runtime_manifest

        stamp = datetime.now(timezone.utc).isoformat()
        document: dict[str, Any] = {
            "@timestamp": stamp,
            "state": state,
            "runtime": runtime_manifest(rules, "snapshot"),
            "detection": ",".join(rule["id"] for rule in rules),
            **extra,
        }
        if reloader is not None:
            document["rules_fingerprint"] = reloader.fingerprint[:12]
        if state == "success":
            document["last_success"] = stamp
        client.index(index=STATUS, id="detector", document=document, refresh=False)

    try:
        status("running")
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
            result = save_security_alert(
                client,
                document,
                index_name=ALERTS,
                document_id=document_id,
                refresh=False,
                index_prepared=True,
            )
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