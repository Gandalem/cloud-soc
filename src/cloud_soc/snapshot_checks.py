"""Read-only snapshot metadata and isolated synthetic restore checks."""
from datetime import datetime, timezone
import re

from cloud_soc.capacity import INDEX_NAME, MAX_INDICES, complete, integer, stamp, timestamp

NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}\Z")
RESTORE_INDEX = re.compile(r"soc-host-raw-p2-restore-[a-f0-9]{12}\Z")
FIXTURE_ID = re.compile(r"p2-fixture-[a-f0-9]{32}\Z")


def inspect_snapshot(client, *, repository, snapshot, expected_indices, max_age_hours=48, now=None):
    if (not isinstance(repository, str) or not NAME.fullmatch(repository)
            or not isinstance(snapshot, str) or not NAME.fullmatch(snapshot)):
        raise ValueError("Exact repository and snapshot names required")
    if (not isinstance(expected_indices, list) or not 1 <= len(expected_indices) <= MAX_INDICES
            or len(set(expected_indices)) != len(expected_indices)
            or any(not isinstance(name, str) or not INDEX_NAME.fullmatch(name) for name in expected_indices)):
        raise ValueError("Exact collection index scope required")
    if type(max_age_hours) is not int or not 1 <= max_age_hours <= 8760:
        raise ValueError("Invalid snapshot age")
    now = now or datetime.now(timezone.utc)
    stamp(now)
    result = client.options(request_timeout=10, max_retries=0).snapshot.get(
        repository=repository, snapshot=snapshot, verbose=True, ignore_unavailable=False, master_timeout="5s")
    rows = result.get("snapshots")
    if not isinstance(rows, list) or len(rows) != 1:
        raise ValueError("Snapshot unavailable or ambiguous")
    row = rows[0]
    if row.get("snapshot") != snapshot:
        raise ValueError("Snapshot identity mismatch")
    indices = row.get("indices")
    if not isinstance(indices, list) or len(indices) > MAX_INDICES or any(not isinstance(name, str) for name in indices):
        raise ValueError("Invalid snapshot scope")
    reasons = []
    if row.get("state") != "SUCCESS":
        reasons.append("snapshot_not_successful")
    shards = row.get("shards", {})
    if (integer(shards.get("failed")) or integer(shards.get("successful")) != integer(shards.get("total"))
            or integer(shards.get("total")) == 0):
        reasons.append("incomplete_shards")
    if row.get("failures"):
        reasons.append("snapshot_failures")
    if not set(expected_indices).issubset(indices):
        reasons.append("missing_expected_indices")
    end = row.get("end_time")
    if end is None:
        reasons.append("missing_end_time")
        age = None
    else:
        age = (now - timestamp(end)).total_seconds() / 3600
        if age < 0 or age > max_age_hours:
            reasons.append("snapshot_future_or_stale")
    return {"schema": 1, "checked_at": stamp(now), "repository": repository, "snapshot": snapshot,
            "status": "metadata_ok" if not reasons else "attention", "reasons": reasons,
            "age_hours": round(age, 3) if age is not None else None,
            "expected_index_count": len(expected_indices), "covered_expected_indices": len(set(expected_indices) & set(indices)),
            "restore_verified": False, "repository_integrity_verified": False,
            "limitations": ["metadata_not_restore_proof", "snapshot_may_include_other_indices",
                            "portal_ca_keys_and_agent_queues_not_included"]}


def verify_fixture_restore(client, *, restored_index, fixture_id):
    if (not isinstance(restored_index, str) or not RESTORE_INDEX.fullmatch(restored_index)
            or not isinstance(fixture_id, str) or not FIXTURE_ID.fullmatch(fixture_id)):
        raise ValueError("Isolated fixture names required")
    es = client.options(request_timeout=5, max_retries=0)
    result = es.count(index=restored_index)
    complete(result, "_shards")
    if integer(result.get("count")) != 1:
        raise ValueError("Restored fixture count mismatch")
    doc = es.get(index=restored_index, id=fixture_id)
    if (doc.get("_index") != restored_index or doc.get("_id") != fixture_id
            or doc.get("found") is not True or doc.get("_source") != {"p2_fixture": fixture_id}):
        raise ValueError("Restored fixture mismatch")
    return {"schema": 1, "status": "synthetic_restore_verified", "documents": 1,
            "limitations": ["readback_only_requires_separate_snapshot_provenance",
                            "one_synthetic_document_not_full_production_restore"]}
