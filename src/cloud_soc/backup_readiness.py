"""Offline backup preparation and read-only health checks; no activation or deletion."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import PurePosixPath
import re

from cloud_soc.capacity import compare, integer, MAX_INDICES, stamp, timestamp, validate_report

POLICY_ID = "cloud-soc-p2-daily"
PROFILE = "p2-balanced-v1"
CRON_UTC = "0 0 18 * * ?"
SNAPSHOT_PREFIX = "cloud-soc-p2-"
MAX_SNAPSHOTS = 10
REPOSITORY_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}\Z")
SNAPSHOT_NAME = re.compile(r"cloud-soc-p2-[a-z0-9][a-z0-9_.-]{0,180}\Z")
SCOPES = (
    ("host", "soc-host-raw-", 30),
    ("network", "soc-network-", 14),
    ("health", "soc-agent-health-", 14),
)
INDEX_PATTERNS = [prefix + "*" for _, prefix, _ in SCOPES]
KST = timezone(timedelta(hours=9))


def exact_repository(name):
    if not isinstance(name, str) or not REPOSITORY_NAME.fullmatch(name):
        raise ValueError("Exact repository name required")
    return name


def slm_candidate(repository):
    return {
        "schedule": CRON_UTC, "name": "<cloud-soc-p2-{now/d}>",
        "repository": exact_repository(repository),
        "config": {"indices": list(INDEX_PATTERNS), "ignore_unavailable": False,
                   "include_global_state": False, "feature_states": ["none"],
                   "partial": False, "metadata": {"cloud_soc_profile": PROFILE}},
        "retention": {"expire_after": "14d", "min_count": 1},
    }


def repository_candidate(settings):
    if not isinstance(settings, dict):
        raise ValueError("Repository configuration required")
    kind = settings.get("type")
    if kind == "unconfigured" and set(settings) == {"type"}:
        return None
    if kind == "fs" and set(settings) == {"type", "location"}:
        location = settings["location"]
        if (not isinstance(location, str) or len(location) > 256 or not location.startswith("/")
                or ".." in location.split("/") or "//" in location
                or not re.fullmatch(r"/[a-zA-Z0-9_./-]+", location)
                or len(PurePosixPath(location).parts) < 3):
            raise ValueError("Explicit absolute repository mount required")
        return {"type": "fs", "settings": {"location": location, "compress": True}}
    if kind == "s3" and set(settings) == {"type", "bucket", "base_path"}:
        bucket, base = settings["bucket"], settings["base_path"]
        if (not isinstance(bucket, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket)
                or any(value in bucket for value in ("..", ".-", "-."))
                or bucket.startswith(("xn--", "sthree-", "amzn-s3-demo-"))
                or bucket.endswith(("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"))):
            raise ValueError("Invalid S3 bucket")
        try:
            ip_address(bucket)
        except ValueError:
            pass
        else:
            raise ValueError("Bucket must not be an IP address")
        if (not isinstance(base, str) or len(base) > 200
                or not re.fullmatch(r"[a-z0-9_-]+(?:/[a-z0-9_-]+)*", base)):
            raise ValueError("Scoped S3 prefix required")
        return {"type": "s3", "settings": {"bucket": bucket, "base_path": base,
                                             "compress": True, "server_side_encryption": True}}
    raise ValueError("Unsupported repository settings; credentials and endpoints are not accepted")


def plan(settings=None, *, repository="cloud-soc-p2-backup"):
    exact_repository(repository)
    candidate = repository_candidate(settings if settings is not None else {"type": "unconfigured"})
    blockers = ["storage_independence_encryption_permissions_and_cost_unverified",
                "repository_registration_and_integrity_test_pending",
                "operational_snapshot_and_isolated_restore_pending",
                "portal_config_and_secret_encrypted_backup_pending",
                "alert_delivery_and_monitor_schedule_pending",
                "activation_and_snapshot_expiry_approval_pending"]
    if candidate is None:
        blockers.insert(0, "backup_destination_not_configured")
    return {
        "schema": 1, "profile": PROFILE, "status": "prepared",
        "activation_ready": False, "writes_performed": False, "automatic_log_deletion": False,
        "schedule": {"timezone": "Asia/Seoul", "daily_at": "03:00", "cron_utc": CRON_UTC},
        "backup_retention_days": 14, "minimum_successful_snapshots": 1,
        "goals": {"rpo_hours": 24, "rto_hours": 4, "restore_drill_interval_days": 30},
        "repository_name": repository, "repository_candidate": candidate,
        "slm_policy_id": POLICY_ID, "slm_candidate": slm_candidate(repository),
        "log_retention_days": {**{name: days for name, _, days in SCOPES}, "alerts_cases": 90},
        "incident_evidence": "hold_until_explicit_release", "blockers": blockers,
        "limitations": ["candidate_not_installed", "minimum_snapshot_floor_may_exceed_14_days",
                        "snapshot_expiry_not_exact_deletion_time", "backups_may_retain_expired_source_logs",
                        "collection_scope_only_no_processing_or_global_configuration",
                        "oci_and_aws_not_in_this_backup_profile", "rpo_rto_are_unverified_targets"],
    }


def balanced_capacity(previous, current):
    old, new = validate_report(previous), validate_report(current)
    if timestamp(current["measured_at"]) <= timestamp(previous["measured_at"]):
        raise ValueError("Ordered samples required")
    # Compare each source separately so a growing source cannot mask another's shrinkage.
    groups = []
    for name, prefix, days in SCOPES:
        before = [row for index, row in old.items() if index.startswith(prefix)]
        after = [row for index, row in new.items() if index.startswith(prefix)]
        group = {"source": name, "retention_days": days,
                 "current_primary_bytes": sum(row["primary_bytes"] for row in after)}
        if not before or not after:
            result = {"status": "unknown", "reason": "source_not_observed_in_both_samples"}
        else:
            result = compare({**previous, "indices": before}, {**current, "indices": after}, proposed_days=days)
            if result["status"] == "estimate" and not result["representative_24_hour_sample"]:
                result = {"status": "unknown", "reason": "sample_under_24_hours"}
        groups.append({**group, "estimate": result})
    if previous["cluster_uuid"] != current["cluster_uuid"]:
        for group in groups:
            group["estimate"] = {"status": "unknown", "reason": "cluster_changed"}
    complete = all(group["estimate"]["status"] == "estimate" for group in groups)
    return {
        "schema": 1, "profile": PROFILE, "status": "estimate" if complete else "incomplete",
        "automatic_log_deletion": False, "sources": groups,
        "projected_net_primary_bytes": sum(group["estimate"]["proposed_net_primary_bytes"] for group in groups) if complete else None,
        "excluded_index_count": sum(not any(index.startswith(prefix) for _, prefix, _ in SCOPES) for index in new),
        "limitations": ["net_growth_not_gross_ingestion", "24_hour_sample_not_weekly_representativeness",
                        "replicas_translog_merge_snapshots_and_other_services_excluded",
                        "alerts_cases_and_incident_hold_capacity_not_measured",
                        "new_indices_may_contain_historical_data"],
    }


def expected_collection_indices(report):
    rows = validate_report(report)
    names = [index for index in rows if any(index.startswith(prefix) for _, prefix, _ in SCOPES)]
    validate_expected_indices(names)
    return sorted(names)


def validate_expected_indices(names):
    from cloud_soc.capacity import INDEX_NAME

    if (not isinstance(names, list) or not 1 <= len(names) <= MAX_INDICES
            or any(not isinstance(name, str) or not INDEX_NAME.fullmatch(name)
                   or not any(name.startswith(prefix) for _, prefix, _ in SCOPES) for name in names)
            or len(set(names)) != len(names)):
        raise ValueError("Explicit Windows/Linux collection indices required")


def backup_health(client, *, repository, expected_indices, now=None):
    exact_repository(repository)
    validate_expected_indices(expected_indices)
    now = now or datetime.now(timezone.utc)
    checked = stamp(now)
    base = {"schema": 1, "profile": PROFILE, "checked_at": checked,
            "repository": repository, "status": "attention", "alert_required": True,
            "notification_sent": False, "restore_verified": False,
            "last_success_at": None, "age_hours": None,
            "limitations": ["metadata_not_restore_proof", "bounded_latest_policy_snapshots_only",
                            "scheduler_and_retention_execution_not_verified", "portal_and_secrets_not_checked",
                            "repository_topology_encryption_and_access_not_verified",
                            "expected_inventory_must_match_snapshot_time"]}
    try:
        es = client.options(request_timeout=10, max_retries=0)
        response = es.snapshot.get(repository=repository, snapshot=SNAPSHOT_PREFIX + "*",
                                   slm_policy_filter=POLICY_ID, size=MAX_SNAPSHOTS,
                                   sort="start_time", order="desc", verbose=True,
                                   index_names=True, include_repository=True,
                                   ignore_unavailable=False, master_timeout="5s",
                                   filter_path=["responses.error.type", "snapshots.snapshot", "snapshots.repository",
                                                "snapshots.metadata.policy", "snapshots.metadata.cloud_soc_profile",
                                                "snapshots.start_time", "snapshots.end_time", "snapshots.state",
                                                "snapshots.indices", "snapshots.shards", "snapshots.failures.shard_id"])
        rows = response.get("snapshots")
        if not isinstance(rows, list) or len(rows) > MAX_SNAPSHOTS or response.get("responses"):
            raise ValueError("Incomplete repository response")
        successes, failures, active, seen = [], [], [], set()
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get("snapshot"), str)
                    or not SNAPSHOT_NAME.fullmatch(row["snapshot"]) or row.get("repository") != repository
                    or row.get("metadata", {}).get("policy") != POLICY_ID
                    or row.get("metadata", {}).get("cloud_soc_profile") != PROFILE):
                raise ValueError("Snapshot identity mismatch")
            if row["snapshot"] in seen:
                raise ValueError("Duplicate snapshot identity")
            seen.add(row["snapshot"])
            start = timestamp(row["start_time"])
            if start > now:
                raise ValueError("Future snapshot")
            state = row.get("state")
            if state == "IN_PROGRESS":
                active.append(start)
                continue
            end = timestamp(row["end_time"])
            if end < start or end > now:
                raise ValueError("Invalid snapshot times")
            if state in ("FAILED", "PARTIAL", "INCOMPATIBLE"):
                failures.append(end)
                continue
            if state != "SUCCESS":
                raise ValueError("Unknown snapshot state")
            shards, indices = row.get("shards", {}), row.get("indices")
            if (integer(shards.get("failed")) != 0 or integer(shards.get("successful")) != integer(shards.get("total"))
                    or integer(shards.get("total")) == 0 or row.get("failures")
                    or not isinstance(indices, list) or len(indices) > MAX_INDICES
                    or any(not isinstance(index, str) or len(index) > 256 for index in indices)
                    or len(set(indices)) != len(indices)):
                raise ValueError("Incomplete snapshot")
            successes.append((end, start, set(indices)))
        if not successes:
            reasons = ["no_verified_success_in_recent_snapshots"]
        else:
            end, start, indices = max(successes, key=lambda item: item[0])
            age = (now - start).total_seconds() / 3600
            reasons = []
            if age > 24:
                reasons.append("recovery_point_older_than_24_hours")
            if not set(expected_indices).issubset(indices):
                reasons.append("missing_expected_indices")
            if any(not any(index.startswith(prefix) for _, prefix, _ in SCOPES) for index in indices):
                reasons.append("unexpected_snapshot_scope")
            if failures and max(failures) >= end:
                reasons.append("latest_completed_attempt_failed")
            base.update(last_success_at=stamp(end), age_hours=round(age, 3))
        if any((now - start).total_seconds() > 4 * 3600 for start in active):
            reasons.append("snapshot_running_over_4_hours")
        return {**base, "status": "attention" if reasons else "metadata_ok",
                "alert_required": bool(reasons), "reasons": reasons,
                "active_snapshots": len(active), "checked_snapshots": len(rows)}
    except Exception:
        return {**base, "status": "unknown", "reasons": ["backup_lookup_or_validation_failed"]}


def next_measurement(report):
    validate_report(report)
    due = timestamp(report["measured_at"]) + timedelta(days=1)
    return {"not_before_utc": stamp(due), "not_before_kst": due.astimezone(KST).isoformat(),
            "preferred_sample_count": 3, "note": "same_scope_at_least_24_hours_apart_no_schedule_installed"}
