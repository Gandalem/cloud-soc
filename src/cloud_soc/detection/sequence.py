"""Failure-to-success sequence, scoped by organization/host/account/source IP."""
from collections import deque
from copy import deepcopy
from datetime import timedelta
import json
from typing import Any

from cloud_soc.correlation.sequence_store import SequenceStateStore, resolve_sequence_store
from cloud_soc.detection.engine import (
    build_group_key,
    event_evidence,
    event_fingerprint,
    event_matches_rule,
    get_field_value,
    mall_observation_identity,
    observation_identity,
    parse_event_timestamp,
    rule_engine_version,
    rule_revision,
    ssh_collection_mirror,
)

DEFAULT_MAX_RETAINED_FAILURES = 200


def retention_seconds(rule: dict[str, Any]) -> int:
    return rule["time_window"]["seconds"] + rule.get("success_window", {}).get("seconds", 0)


def state_ttl_seconds(rule: dict[str, Any]) -> int:
    cooldown_sec = rule.get("cooldown", {}).get("seconds", 0)
    return max(retention_seconds(rule), cooldown_sec) + 60


def _select_qualifying_burst(
    earlier: list[tuple[Any, dict[str, Any]]],
    window_seconds: int,
    success_window_seconds: int,
    threshold_count: int,
    success_stamp: Any,
) -> list[dict[str, Any]]:
    """success_window가 설정된 룰에서 유효한 실패 버스트를 추출합니다."""
    window: deque[tuple[Any, dict[str, Any]]] = deque()
    burst: list[dict[str, Any]] = []
    window_delta = timedelta(seconds=window_seconds)
    success_delta = timedelta(seconds=success_window_seconds)

    for candidate_time, candidate in earlier:
        while window and candidate_time - window[0][0] > window_delta:
            window.popleft()
        window.append((candidate_time, candidate))
        if len(window) >= threshold_count and success_stamp - candidate_time <= success_delta:
            burst = [ev for _, ev in window]
    return burst


def detect_sequence(
    events: list[dict[str, Any]],
    rule: dict[str, Any],
    runtime: dict[str, Any] | SequenceStateStore | None,
    *,
    strict_order: bool = True,
) -> list[dict[str, Any]]:
    store = resolve_sequence_store(runtime)
    result: list[dict[str, Any]] = []
    fields = list(dict.fromkeys(["organization.id", *rule["group_by"]]))
    seconds = rule["time_window"]["seconds"]
    retention_delta = timedelta(seconds=retention_seconds(rule))
    cooldown_seconds = rule.get("cooldown", {}).get("seconds", 0)
    ttl = state_ttl_seconds(rule)
    max_failures = int(rule.get("max_retained_failures", DEFAULT_MAX_RETAINED_FAILURES))
    version = rule_revision(rule)
    seen: set[str] = set()

    # 배치 내 타임스탬프를 1회만 파싱해 정렬 비용 절감
    ordered = sorted(
        ((parse_event_timestamp(e), event_fingerprint(e), e) for e in events),
        key=lambda item: (item[0], item[1]),
    )

    for stamp, _, event in ordered:
        if not event_matches_rule(event, rule):
            continue
        key = build_group_key(event, fields)
        if key is None or any(get_field_value(event, f) in (None, "") for f in fields):
            continue

        fingerprint = observation_identity(event)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)

        key_json = json.dumps(key)
        outcome = get_field_value(event, "event.outcome")

        with store.lock(rule["id"], key_json):
            state = store.load(rule["id"], key_json)
            raw_failures = state.get("failures", [])

            # 만료된 실패 이력 제거 (타임스탬프 1회 파싱)
            timed_failures = [
                (ts, item)
                for item in raw_failures
                if (ts := parse_event_timestamp(item)) >= stamp - retention_delta
            ]

            if timed_failures and stamp < timed_failures[-1][0]:
                if strict_order:
                    raise ValueError("Sequence runtime requires finalized event order")
                # 분산 환경에서 미세한 지연 도착 허용 시 시간순 재정렬
                timed_failures.sort(key=lambda pair: pair[0])

            if outcome == "failure":
                existing_ids = {observation_identity(item) for _, item in timed_failures}
                if fingerprint not in existing_ids and not any(
                    ssh_collection_mirror(event, item) for _, item in timed_failures
                ):
                    timed_failures.append((stamp, deepcopy(event)))
                    if not strict_order:
                        timed_failures.sort(key=lambda pair: pair[0])
                    # 대량 Brute Force 시 메모리·Redis 비대화 방지 (최신 N건 유지)
                    if len(timed_failures) > max_failures:
                        timed_failures = timed_failures[-max_failures:]

                state["failures"] = [item for _, item in timed_failures]
                store.save(rule["id"], key_json, state, ttl)
                continue

            if outcome != "success":
                continue

            # Same-timestamp ordering cannot establish a preceding failure.
            earlier_timed = [(ts, item) for ts, item in timed_failures if ts < stamp]
            if "success_window" in rule:
                earlier = _select_qualifying_burst(
                    earlier=earlier_timed,
                    window_seconds=seconds,
                    success_window_seconds=rule["success_window"]["seconds"],
                    threshold_count=rule["threshold"]["count"],
                    success_stamp=stamp,
                )
            else:
                earlier = [item for _, item in earlier_timed]

            last = parse_event_timestamp({"@timestamp": state["last_alert"]}) if state.get("last_alert") else None
            suppressed = last is not None and cooldown_seconds > 0 and (stamp - last) < timedelta(seconds=cooldown_seconds)

            if len(earlier) >= rule["threshold"]["count"] and not suppressed:
                evidence = [event_evidence(e) for e in earlier + [event]]
                alert_doc = {
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule.get("severity", "high"),
                    "group": dict(zip(fields, key)),
                    "organization_id": get_field_value(event, "organization.id"),
                    "rule_version": version,
                    "rule_snapshot": deepcopy(rule),
                    "engine_version": rule_engine_version(rule),
                    "event_count": len(earlier) + 1,
                    "threshold": rule["threshold"]["count"],
                    "time_window_seconds": seconds,
                    "window_start": earlier[0]["@timestamp"],
                    "window_end": stamp.isoformat(),
                    "alert": rule.get("alert", {}),
                    "mitre": rule.get("mitre", {}),
                    "evidence": evidence,
                    "evidence_status": "complete" if all(e["complete"] for e in evidence) else "incomplete_legacy",
                }
                if (rule.get("identity_anchor") == "mall" or rule["id"] == "WEB-AUTH-01") and mall_observation_identity(event):
                    alert_doc["identity_anchor"] = mall_observation_identity(event)
                result.append(alert_doc)

                # 버그 수정: success_window 또는 cooldown이 설정된 모든 룰에서 last_alert 기록
                if "success_window" in rule or cooldown_seconds > 0:
                    state["last_alert"] = stamp.isoformat()

            state["failures"] = []
            store.save(rule["id"], key_json, state, ttl)

    return result