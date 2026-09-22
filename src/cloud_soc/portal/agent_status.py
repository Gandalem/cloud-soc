"""Read-only collector activity, not a heartbeat or an online/offline assertion."""

import base64
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from cloud_soc.portal.privacy import display, sensitive


INDICES = "soc-host-raw-*,soc-network-*"
PAGE_SIZE = 50
WINDOW_DAYS = 30
RECENT_SECONDS = 300
DELAYED_SECONDS = 900
SOURCE_FIELDS = ["host.name", "host.ip", "host.os.name", "host.os.platform",
                 "agent.version", "event.ingested", "@timestamp"]
CURSOR_KEYS = {"organization", "agent_id", "agent_type"}


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def activity(received, now):
    if received is None:
        return "unknown", "missing_ingestion_time"
    age = (now - received).total_seconds()
    if age < -60:
        return "unknown", "future_ingestion_time"
    if age <= RECENT_SECONDS:
        return "recent", None
    if age <= DELAYED_SECONDS:
        return "delayed", None
    return "silent", None


def decode_cursor(value):
    if not value:
        return None
    try:
        if not isinstance(value, str) or len(value) > 4096:
            raise ValueError()
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        key = json.loads(raw)
        if not isinstance(key, dict) or set(key) != CURSOR_KEYS:
            raise ValueError()
        for name, item in key.items():
            if item is None and name != "agent_id":
                continue
            if not isinstance(item, str) or not item or len(item) > 512:
                raise ValueError()
        return key
    except (ValueError, UnicodeError, TypeError):
        raise ValueError("페이지 정보가 올바르지 않습니다. 첫 페이지부터 다시 조회하세요.") from None


def encode_cursor(key):
    if isinstance(key, dict) and any(sensitive(value) for value in key.values()):
        raise ValueError("Unsafe pagination identity")
    return base64.urlsafe_b64encode(json.dumps(key, ensure_ascii=True).encode()).decode().rstrip("=")


def text(value):
    return display(value)


def object_field(value, name):
    item = value.get(name, {}) if isinstance(value, dict) else {}
    return item if isinstance(item, dict) else {}


def row_from_bucket(bucket, now):
    key = bucket["key"]
    hits = bucket["latest"]["hits"]["hits"]
    source = hits[0].get("_source", {}) if hits else {}
    host = object_field(source, "host")
    event = object_field(source, "event")
    received = parse_time(event.get("ingested"))
    status, reason = activity(received, now)
    addresses = host.get("ip", [])
    addresses = [addresses] if isinstance(addresses, str) else addresses
    valid_ips = []
    for address in addresses[:16] if isinstance(addresses, list) else []:
        try:
            if isinstance(address, str):
                valid_ips.append(str(ipaddress.ip_address(address)))
        except ValueError:
            continue
    return {
        "agent_id": text(key["agent_id"]), "agent_type": text(key.get("agent_type")),
        "organization": text(key.get("organization")), "host_name": text(host.get("name")),
        "host_ips": valid_ips, "os": text(object_field(host, "os").get("name")),
        "version": text(object_field(source, "agent").get("version")),
        "last_received": iso(received) if received else None,
        "last_event": iso(value) if (value := parse_time(source.get("@timestamp"))) else None,
        "documents": bucket["doc_count"], "status": status, "reason": reason,
    }


def snapshot(client, *, after=None, now=None):
    now = now or datetime.now(timezone.utc)
    cutoff = iso(now - timedelta(days=WINDOW_DAYS))
    composite = {"size": PAGE_SIZE, "sources": [
        {"organization": {"terms": {"field": "organization.id", "missing_bucket": True}}},
        {"agent_id": {"terms": {"field": "agent.id"}}},
        {"agent_type": {"terms": {"field": "agent.type", "missing_bucket": True}}},
    ]}
    if after is not None:
        composite["after"] = after
    # Legacy documents may be visible, but their event time never implies activity.
    body = {"size": 0, "track_total_hits": False, "timeout": "4s", "query": {"bool": {
        "minimum_should_match": 1, "should": [
            {"range": {"event.ingested": {"gte": cutoff}}},
            {"bool": {"must_not": [{"exists": {"field": "event.ingested"}}],
                      "filter": [{"range": {"@timestamp": {"gte": cutoff}}}]}},
        ],
    }}, "aggs": {
        "unidentified": {"filter": {"bool": {"must_not": [{"exists": {"field": "agent.id"}}]}}},
        "agents": {"composite": composite, "aggs": {
            "latest": {"top_hits": {"size": 1, "_source": {"includes": SOURCE_FIELDS}, "sort": [
                {"event.ingested": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
                {"@timestamp": {"order": "desc", "missing": "_last", "unmapped_type": "date"}},
            ]}},
        }},
    }}
    response = client.search(index=INDICES, body=body, allow_no_indices=True,
                             ignore_unavailable=True, expand_wildcards="open", allow_partial_search_results=False)
    if response.get("timed_out") or response.get("_shards", {}).get("failed", 0):
        raise RuntimeError("Incomplete search results")
    # A cluster with no matching indices may return no aggregation objects.
    if not response.get("aggregations") and response.get("_shards", {}).get("total") == 0:
        groups, unidentified = {}, 0
    else:
        groups = response["aggregations"]["agents"]
        unidentified = response["aggregations"]["unidentified"]["doc_count"]
    rows = [row_from_bucket(bucket, now) for bucket in groups.get("buckets", [])]
    next_key = groups.get("after_key") if len(rows) == PAGE_SIZE else None
    return {"agents": rows, "checked_at": iso(now), "window_days": WINDOW_DAYS,
            "page_size": PAGE_SIZE, "next_cursor": encode_cursor(next_key) if next_key else None,
            "unidentified_documents": unidentified, "basis": "server_ingestion",
            "thresholds": {"recent_seconds": RECENT_SECONDS, "delayed_seconds": DELAYED_SECONDS}}
