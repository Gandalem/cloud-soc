"""Bounded, read-only capacity measurements. No retention or cluster writes."""
from datetime import datetime, timedelta, timezone
import re
import time

INDEX_PATTERNS = "soc-host-raw-*,soc-network-*,soc-agent-health-*,soc-cloud-aws-*,soc-cloud-oci-*"
INDEX_NAME = re.compile(r"soc-(?:host-raw|network|agent-health|cloud-aws|cloud-oci)-[a-z0-9][a-z0-9_.-]{0,180}\Z")
MAX_INDICES = 500
MAX_SECONDS = 60


def integer(value):
    if type(value) is not int or not 0 <= value <= 2**63 - 1:
        raise ValueError("Invalid counter")
    return value


def stamp(value):
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("Timezone required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid measurement time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    stamp(parsed)
    return parsed.astimezone(timezone.utc)


def complete(response, field):
    parts = response.get(field)
    if (not isinstance(parts, dict) or integer(parts.get("failed")) != 0
            or integer(parts.get("successful")) != integer(parts.get("total"))):
        raise ValueError("Incomplete measurement")


def thresholds(warning, critical):
    if type(warning) is not int or type(critical) is not int or not 1 <= warning < critical <= 99:
        raise ValueError("Invalid proposed thresholds")


def collect(client, *, hours=24, warning=75, critical=85, now=None):
    if type(hours) is not int or not 1 <= hours <= 168:
        raise ValueError("Invalid observation window")
    thresholds(warning, critical)
    now = now or datetime.now(timezone.utc)
    end = stamp(now)
    start = stamp(now - timedelta(hours=hours))
    deadline = time.monotonic() + MAX_SECONDS

    def budget():
        if time.monotonic() >= deadline:
            raise ValueError("Measurement budget exceeded")

    es = client.options(request_timeout=5, max_retries=0)
    info = es.info()
    cluster = info.get("cluster_uuid")
    if not isinstance(cluster, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", cluster) or cluster == "_na_":
        raise ValueError("Missing cluster identity")
    budget()
    stats = es.indices.stats(index=INDEX_PATTERNS, metric="docs,store,indexing", expand_wildcards="open")
    complete(stats, "_shards")
    entries = stats.get("indices")
    if not isinstance(entries, dict) or len(entries) > MAX_INDICES:
        raise ValueError("Index limit exceeded")
    rows = []
    for name, values in sorted(entries.items()):
        budget()
        if not INDEX_NAME.fullmatch(name):
            raise ValueError("Unexpected index")
        identity = values.get("uuid")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", identity):
            raise ValueError("Missing index identity")
        result = es.search(index=name, size=0, source=False, track_total_hits=True,
                           timeout="4s", allow_partial_search_results=False,
                           aggs={"received": {"filter": {"range": {"event.ingested": {"gte": start, "lt": end}}}},
                                 "missing_receipt": {"filter": {"bool": {"must_not": {"exists": {"field": "event.ingested"}}}}}})
        complete(result, "_shards")
        if result.get("timed_out") is not False or result["hits"]["total"].get("relation") != "eq":
            raise ValueError("Incomplete count")
        docs = integer(result["hits"]["total"]["value"])
        received = integer(result["aggregations"]["received"]["doc_count"])
        missing = integer(result["aggregations"]["missing_receipt"]["doc_count"])
        if received + missing > docs:
            raise ValueError("Inconsistent counts")
        primary = values["primaries"]
        primary_bytes = integer(primary["store"]["size_in_bytes"])
        total_bytes = integer(values["total"]["store"]["size_in_bytes"])
        if total_bytes < primary_bytes:
            raise ValueError("Inconsistent storage")
        rows.append({"index": name, "uuid": identity, "documents": docs,
                     "received_documents": received, "missing_receipt_documents": missing,
                     "primary_bytes": primary_bytes, "total_bytes": total_bytes,
                     "index_operations": integer(primary["indexing"]["index_total"])})
    budget()
    nodes = es.nodes.stats(metric="fs")
    complete(nodes, "_nodes")
    values = nodes.get("nodes")
    if not isinstance(values, dict) or not 1 <= len(values) <= 100:
        raise ValueError("Invalid node count")
    disks = []
    for node, value in sorted(values.items()):
        if not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", node):
            raise ValueError("Invalid node identity")
        fs = value["fs"]["total"]
        total, free = integer(fs["total_in_bytes"]), integer(fs["available_in_bytes"])
        if total == 0 or free > total:
            raise ValueError("Invalid disk size")
        used = 100 * (1 - free / total)
        disks.append({"node_id": node, "total_bytes": total, "available_bytes": free,
                      "used_percent": round(used, 2),
                      "advisory": "critical" if used >= critical else "warning" if used >= warning else "normal"})
    budget()
    return {"schema": 2, "cluster_uuid": cluster, "measured_at": end,
            "window": {"start": start, "end": end, "hours": hours},
            "approved": False, "automatic_deletion": False,
            "thresholds_proposal": {"warning_percent": warning, "critical_percent": critical},
            "indices": rows, "disks": disks,
            "summary": {field: sum(row[field] for row in rows) for field in (
                "documents", "received_documents", "missing_receipt_documents", "primary_bytes", "total_bytes")},
            "limitations": ["non_atomic_measurements", "search_visible_documents_only",
                            "received_count_not_wire_bytes_or_losslessness", "raw_collection_indices_only"]}


def validate_report(report):
    if (not isinstance(report, dict) or report.get("schema") != 2
            or report.get("approved") is not False or report.get("automatic_deletion") is not False):
        raise ValueError("Unsupported report")
    if not isinstance(report.get("cluster_uuid"), str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", report["cluster_uuid"]):
        raise ValueError("Invalid cluster identity")
    timestamp(report["measured_at"])
    rows = report.get("indices")
    if not isinstance(rows, list) or len(rows) > MAX_INDICES:
        raise ValueError("Invalid rows")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("index"), str) or not INDEX_NAME.fullmatch(row["index"]):
            raise ValueError("Invalid row")
        name = row["index"]
        if name in result or not isinstance(row.get("uuid"), str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,128}", row["uuid"]):
            raise ValueError("Invalid index identity")
        for field in ("documents", "received_documents", "missing_receipt_documents", "primary_bytes", "total_bytes", "index_operations"):
            integer(row[field])
        if row["total_bytes"] < row["primary_bytes"] or row["received_documents"] + row["missing_receipt_documents"] > row["documents"]:
            raise ValueError("Inconsistent row")
        result[name] = row
    return result


def compare(previous, current, *, proposed_days=30):
    if type(proposed_days) is not int or not 1 <= proposed_days <= 3650:
        raise ValueError("Invalid proposed retention")
    old, new = validate_report(previous), validate_report(current)
    seconds = (timestamp(current["measured_at"]) - timestamp(previous["measured_at"])).total_seconds()
    if seconds <= 0:
        raise ValueError("Ordered samples required")
    reason = None
    if previous["cluster_uuid"] != current["cluster_uuid"]:
        reason = "cluster_changed"
    elif set(old) - set(new) or any(old[name]["uuid"] != new[name]["uuid"] for name in old):
        reason = "indices_removed_or_recreated"
    elif any(new[name]["index_operations"] < old[name]["index_operations"] for name in old):
        reason = "index_counter_reset"
    elif any(new[name]["primary_bytes"] < old[name]["primary_bytes"] or new[name]["documents"] < old[name]["documents"] for name in old):
        reason = "index_shrink_or_document_removal"
    elif seconds < 3600:
        reason = "sample_under_one_hour"
    if reason:
        return {"status": "unknown", "reason": reason, "approved": False}
    delta = sum(row["primary_bytes"] for row in new.values()) - sum(row["primary_bytes"] for row in old.values())
    daily = round(delta * 86400 / seconds)
    return {"status": "estimate", "sample_seconds": seconds, "approved": False,
            "net_primary_bytes_per_day": daily, "proposed_days": proposed_days,
            "proposed_net_primary_bytes": daily * proposed_days,
            "representative_24_hour_sample": seconds >= 86400,
            "excludes": ["replicas", "translog", "snapshots", "merge_headroom", "other_services"],
            "limitations": ["net_growth_not_gross_ingestion", "positive_merges_or_deletions_may_be_hidden",
                            "new_index_may_contain_historical_data", "no_retention_approval"]}
