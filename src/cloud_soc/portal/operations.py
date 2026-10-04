"""Read-only operational totals and exact evidence, never synthetic incidents."""

from datetime import datetime, timezone
import re
from time import monotonic
from urllib.parse import quote
from elasticsearch import NotFoundError
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import INDICES, SOURCE_FIELDS, field, parse_filters, document_reference, project_hit
from cloud_soc.portal.log_query import LogQueryError, bounded_json
from cloud_soc.portal.security_detail import DETAIL_FIELDS, security_detail, text
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from cloud_soc.processing.worker import checked
from cloud_soc.detection.engine import event_fingerprint

ALERT = "security-alerts"
INDEX_PATH_BUDGET = 3000
MAX_INDEX_BATCHES = 32
SERIES_TIMEOUT = 12
ALERT_FIELDS = ["@timestamp", "rule.id", "rule.name", "organization.id", "source.ip", "cloud_soc.severity",
                "cloud_soc.alert_title", "cloud_soc.event_count", "cloud_soc.threshold", "cloud_soc.time_window_seconds",
                "cloud_soc.window_start", "cloud_soc.window_end", "cloud_soc.provenance"]


def exact_indices(client, patterns):
    try:
        response = client.indices.resolve_index(name=",".join(patterns), expand_wildcards="open")
    except NotFoundError:
        return []
    if response.get("aliases") or response.get("data_streams"):
        raise ValueError("Aliases are not accepted")
    names = [row["name"] for row in response.get("indices", [])]
    for name in names:
        if not any(re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), name) for pattern in patterns):
            raise ValueError("Unexpected index")
    return list(dict.fromkeys(names))


def index_batches(names):
    """Keep exact index scope while leaving room for API paths and query options."""
    batches, batch, length = [], [], 0
    for name in names:
        if not name or len(name.encode("utf-8")) > 255 or re.search(r"[,*/?\\#]", name):
            raise ValueError("Invalid concrete index")
        size = len(quote(name, safe="")) + (3 if batch else 0)
        if length + size > INDEX_PATH_BUDGET:
            batches.append(batch)
            batch, length, size = [], 0, len(quote(name, safe=""))
        batch.append(name)
        length += size
    if batch:
        batches.append(batch)
    if len(batches) > MAX_INDEX_BATCHES:
        raise ValueError("Index scope too large")
    return batches


def exact_count(value):
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise ValueError("Invalid count")
    return value


def identifier(value):
    if not isinstance(value, str) or not value or len(value) > 512 or text(value) != value:
        raise ValueError("Invalid document ID")
    return value


def alert_row(hit):
    source = hit["_source"]
    get = lambda path: text(field(source, path))
    return {"id": identifier(hit["_id"]), "timestamp": get("@timestamp"), "rule": get("rule.id"),
            "title": get("cloud_soc.alert_title") or get("rule.name"), "severity": get("cloud_soc.severity"),
            "organization": get("organization.id"), "source_ip": get("source.ip")}


class Operations:
    def __init__(self, client):
        self.client = client.options(request_timeout=5, max_retries=0) if client is not None else None

    def get(self, index, doc_id, fields):
        if not self.client:
            raise RuntimeError("Monitor not configured")
        if not exact_indices(self.client, [index]):
            return None
        try:
            options = {"source_includes": fields} if fields is not None else {}
            return self.client.get(index=index, id=identifier(doc_id), **options)["_source"]
        except NotFoundError:
            return None

    def series(self, patterns, time_field, start, end, interval, *, records=False, alerts=False):
        if not self.client:
            raise RuntimeError()
        deadline = monotonic() + SERIES_TIMEOUT
        names = exact_indices(self.client, patterns)
        if not names:
            return {"state": "no_index", "count": 0, "buckets": [], "rows": [], "statuses": []}
        batches = index_batches(names)
        # Alerts are a single concrete index; do not approximate cross-index top-N sorting.
        if alerts and names != [ALERT]:
            raise ValueError("Unexpected alert scope")
        aggs = {"trend": {"date_histogram": {"field": time_field, "fixed_interval": interval,
                    "min_doc_count": 0, "extended_bounds": {"min": start, "max": iso(parse_time(end))}}}}
        if records:
            aggs["status"] = {"terms": {"field": "status", "size": 10}}
        count, buckets, statuses, rows = 0, {}, {}, []
        for batch in batches:
            if monotonic() >= deadline:
                raise RuntimeError("Query budget exhausted")
            caps = self.client.field_caps(index=batch, fields=[time_field], include_unmapped=True)["fields"].get(time_field, {})
            if not caps or set(caps) - {"date", "date_nanos"} or any(
                    value.get("aggregatable") is False or value.get("searchable") is False for value in caps.values()):
                raise ValueError("Time mapping missing")
            if monotonic() >= deadline:
                raise RuntimeError("Query budget exhausted")
            result = checked(self.client.search(index=batch, size=50 if alerts else 0,
                source=ALERT_FIELDS if alerts else False, sort=[{"@timestamp": "desc"}] if alerts else None,
                track_total_hits=True, timeout="4s", allow_partial_search_results=False,
                query={"range": {time_field: {"gte": start, "lt": end}}}, aggs=aggs))
            if monotonic() >= deadline:
                raise RuntimeError("Query budget exhausted")
            if result["hits"]["total"]["relation"] != "eq":
                raise ValueError("Inexact total")
            batch_count = exact_count(result["hits"]["total"]["value"])
            trend = result["aggregations"]["trend"]["buckets"]
            if sum(exact_count(b["doc_count"]) for b in trend) != batch_count:
                raise ValueError("Incomplete trend")
            for bucket in trend:
                stamp = parse_time(bucket["key_as_string"])
                if stamp is None:
                    raise ValueError("Invalid bucket time")
                buckets[stamp] = exact_count(buckets.get(stamp, 0) + bucket["doc_count"])
            if len(buckets) > 1000:
                raise ValueError("Too many buckets")
            count = exact_count(count + batch_count)
            status = result["aggregations"].get("status", {})
            if records and (status.get("sum_other_doc_count", 0) or status.get("doc_count_error_upper_bound", 0)
                    or sum(exact_count(b["doc_count"]) for b in status.get("buckets", [])) != batch_count):
                raise ValueError("Incomplete statuses")
            for bucket in status.get("buckets", []):
                key = bucket["key"] if bucket["key"] in ("normalized", "unsupported", "invalid") else "unknown"
                statuses[key] = exact_count(statuses.get(key, 0) + exact_count(bucket["doc_count"]))
            if alerts:
                rows = [alert_row(hit) for hit in result["hits"]["hits"]]
        return {"state": "ok", "count": count,
                "buckets": [{"time": iso(stamp), "count": buckets[stamp]} for stamp in sorted(buckets)],
                "rows": rows, "statuses": [{"key": key, "doc_count": statuses[key]} for key in sorted(statuses)]}

    def worker_status(self, worker):
        value = self.get(STATUS, worker, ["@timestamp", "state", "last_success", "checkpoint", "error", "detection", "health", "lag_seconds", "late_total", "legacy_excluded", "excluded_total", "history_pending"])
        if value is None:
            return {"state": "not_started"}
        stamp = parse_time(value.get("@timestamp"))
        age = (datetime.now(timezone.utc) - stamp).total_seconds() if stamp else None
        state = value.get("state")
        state = state if age is not None and 0 <= age <= 300 and state in ("success", "running", "failed", "waiting") else "stale"
        checkpoint = parse_time(value.get('checkpoint'))
        lag = max(0, int((datetime.now(timezone.utc) - checkpoint).total_seconds())) if checkpoint else None
        late = value.get('late_total')
        late = late if type(late) is int and late >= 0 else 0
        legacy = value.get('legacy_excluded')
        legacy = legacy if type(legacy) is int and legacy >= 0 else 0
        excluded = value.get('excluded_total')
        excluded = excluded if type(excluded) is int and excluded >= 0 else 0
        pending = value.get('history_pending')
        pending = pending if type(pending) is int and pending >= 0 else 0
        health = 'failed' if state == 'failed' else 'stale' if state == 'stale' else 'delayed' if lag is not None and lag > 1200 else 'warning' if late or legacy or excluded or pending else 'healthy'
        return {"state": state, "health": health, "lag_seconds": lag, "late_total": late, "legacy_excluded": legacy, "excluded_total": excluded, "history_pending": pending,
                "detection": text(value.get('detection')),
                "last_success": text(value.get("last_success")), "checkpoint": text(value.get("checkpoint")),
                "error": text(value.get('error'))}

    def pipeline(self):
        try:
            result = self.worker_status("normalizer")
        except Exception:
            result = {"state": "unavailable"}
        try:
            result["detector"] = self.worker_status("detector")
        except Exception:
            result["detector"] = {"state": "unavailable"}
        result["detection"] = result["detector"]["state"]
        return result

    def summary(self, pairs):
        pairs = list(pairs)
        try:
            if any(key not in ("start", "end") for key, _ in pairs):
                raise ValueError()
            filters = parse_filters(pairs)
        except ValueError:
            raise LogQueryError("invalid_operations_query", 400, "조회 기간을 확인하세요.") from None
        interval = "5m" if (parse_time(filters.end) - parse_time(filters.start)).total_seconds() <= 86400 else "1h"
        result = {"start": filters.start, "end": filters.end, "incident_work": "separate_case_api", "sections": {}}
        for key, operation in {
            "intake": lambda: self.series(INDICES, "event.ingested", filters.start, filters.end, interval),
            "processing": lambda: self.series([RECORDS], "event.ingested", filters.start, filters.end, interval, records=True),
            "alerts": lambda: self.series([ALERT], "@timestamp", filters.start, filters.end, interval, alerts=True),
            "quality": lambda: self.series(["soc-agent-health-*"], "event.ingested", filters.start, filters.end, interval),
            "pipeline": self.pipeline,
        }.items():
            try:
                result["sections"][key] = operation()
            except Exception:
                result["sections"][key] = {"state": "unavailable"}
        return bounded_json(result)

    def detail(self, pairs):
        try:
            pairs = list(pairs)
            values = dict(pairs)
            if len(pairs) != len(values) or 'id' not in values or set(values) - {'id', 'evidence', 'offset', 'limit'} or ('evidence' in values and set(values) != {'id', 'evidence'}):
                raise ValueError()
            doc_id = identifier(values["id"])
            position = values.get("evidence")
            if position is not None and not re.fullmatch(r"[0-9]{1,9}", position):
                raise ValueError()
            if any(not re.fullmatch(r'[0-9]{1,9}', values[k]) for k in ('offset', 'limit') if k in values):
                raise ValueError()
            offset, limit = int(values.get('offset', '0')), int(values.get('limit', '25'))
            if not 1 <= limit <= 100:
                raise ValueError()
        except ValueError:
            raise LogQueryError("invalid_alert_query", 400, "경보 참조를 확인하세요.") from None
        try:
            source = self.get(ALERT, doc_id, ALERT_FIELDS)
            if source is None:
                raise LogQueryError("alert_missing", 404, "경보가 없거나 보존 기간이 지났습니다.")
            evidence = field(source, "cloud_soc.provenance.evidence")
            evidence = evidence if isinstance(evidence, list) else []
            result = {"alert": alert_row({"_source": source, "_id": doc_id}), "evidence_count": len(evidence),
                      "evidence_limit": min(len(evidence), 100), "evidence_state": "referenced" if evidence else "legacy_missing_provenance",
                      "rule_version": text(field(source, "cloud_soc.provenance.rule_version")),
                      "engine_version": text(field(source, "cloud_soc.provenance.engine_version")),
                      "condition": {k: field(source, "cloud_soc." + k) for k in ("event_count", "threshold", "time_window_seconds")
                                    if type(field(source, "cloud_soc." + k)) is int}}
            if offset > len(evidence):
                raise LogQueryError('invalid_evidence_offset', 400, '근거 페이지 범위를 확인하세요.')
            last = min(offset + limit, len(evidence))
            result['evidence_page'] = {'offset': offset, 'limit': limit, 'total': len(evidence),
                                       'positions': list(range(offset, last)), 'next_offset': last if last < len(evidence) else None}
            if position is not None:
                number = int(position)
                if number >= len(evidence):
                    raise LogQueryError("evidence_missing", 404, "요청한 근거 참조가 없습니다.")
                result["evidence"] = self.evidence(evidence[number])
            return bounded_json(result)
        except LogQueryError:
            raise
        except Exception:
            raise LogQueryError("alerts_unavailable", 503, "경보·근거를 조회하지 못했습니다. 권한과 참조를 확인하세요.") from None

    def evidence(self, reference):
        if not isinstance(reference, dict):
            return {"state": "invalid_reference"}
        normalized, raw = reference.get("normalized"), reference.get("raw")
        try:
            if not isinstance(normalized, dict) or normalized.get("index") not in (NORMALIZED, "normalized-events"):
                raise ValueError()
            normalized = {"index": normalized["index"], "id": identifier(normalized.get("id"))}
            if isinstance(raw, dict) and re.fullmatch(r"raw-logs-[a-z0-9][a-z0-9_.-]{0,220}", str(raw.get("index", ""))):
                raw = {"index": raw["index"], "id": identifier(raw.get("id"))}
            else:
                raw = document_reference(raw.get("index"), raw.get("id"))
        except (ValueError, AttributeError):
            return {"state": "unsupported_or_invalid_reference"}
        norm = self.get(normalized["index"], normalized["id"], None)
        if norm is None:
            return {"state": "normalized_missing_or_expired", "normalized": normalized, "raw": raw}
        if field(norm, "cloud_soc.provenance.raw") != raw:
            return {"state": "provenance_mismatch"}
        expected_hash = reference.get('event_hash')
        if expected_hash is None:
            integrity = 'unverified_legacy'
        elif not isinstance(expected_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_hash):
            return {'state': 'invalid_evidence_hash'}
        else:
            # Reproduce the detector's exact _source plus its injected document locator.
            # Hash before any privacy projection, but never return this complete source.
            from copy import deepcopy
            hashed = deepcopy(norm)
            hashed['_cloud_soc_meta'] = {'index': normalized['index'], 'document_id': normalized['id']}
            if event_fingerprint(hashed) != expected_hash:
                return {'state': 'normalized_hash_mismatch', 'normalized': normalized, 'raw': raw}
            integrity = 'normalized_hash_verified'
        source = self.get(raw["index"], raw["id"], list(SOURCE_FIELDS + DETAIL_FIELDS))
        if source is None:
            return {"state": "raw_missing_or_expired", "normalized": normalized, "raw": raw}
        metadata = ({path: text(field(source, path)) for path in ("@timestamp", "host.name", "user.name", "event.action")}
                    if raw["index"].startswith("raw-logs-") else project_hit({"_index": raw["index"], "_id": raw["id"], "_source": source}))
        return {"state": "exact_reference", "normalized": normalized, "raw": raw,
                "integrity": integrity, "raw_integrity": 'not_hashed_at_detection',
                "normalized_event": {"timestamp": text(norm.get("@timestamp")), "action": text(field(norm, "event.action")),
                                     "outcome": text(field(norm, "event.outcome"))},
                "metadata": metadata,
                "security": security_detail(source)}
