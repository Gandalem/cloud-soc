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
from cloud_soc.privacy import redact_metadata

ALERT = "security-alerts"
INDEX_PATH_BUDGET = 3000
MAX_INDEX_BATCHES = 32
SERIES_TIMEOUT = 12
ALERT_FIELDS = ["@timestamp", "rule.id", "rule.name", "organization.id", "source.ip", "cloud_soc.severity",
                "cloud_soc.alert_title", "cloud_soc.event_count", "cloud_soc.threshold", "cloud_soc.time_window_seconds",
                "cloud_soc.window_start", "cloud_soc.window_end", "cloud_soc.provenance",
                "cloud_soc.risk_score", "cloud_soc.risk_level", "cloud_soc.risk_version", "cloud_soc.risk_factors", "mitre"]


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


def display_summary(value):
    """Preserve bounded numeric charts while filtering every other metadata field."""
    prepared = dict(value)
    prepared['sections'] = {name: dict(section) for name, section in value['sections'].items()}
    charts = {}
    for name in ('intake', 'processing', 'alerts', 'quality'):
        section = prepared['sections'].get(name)
        if not section or section.get('state') != 'ok':
            continue
        buckets = section.pop('buckets', None)
        if not isinstance(buckets, list) or len(buckets) > 1000:
            raise ValueError('Invalid chart series')
        projected = []
        for bucket in buckets:
            if not isinstance(bucket, dict) or parse_time(bucket.get('time')) is None:
                raise ValueError('Invalid chart series')
            projected.append({'time': iso(parse_time(bucket['time'])), 'count': exact_count(bucket.get('count'))})
        charts[name] = projected
    result = redact_metadata(prepared)
    for name, buckets in charts.items():
        result['sections'][name]['buckets'] = buckets
    return result


def identifier(value):
    if not isinstance(value, str) or not value or len(value) > 512 or text(value) != value:
        raise ValueError("Invalid document ID")
    return value


def analysis_coverage(normalizer, detector):
    """A detector poll is not proof that newly received logs were analyzed."""
    for name, status in (("normalizer", normalizer), ("detector", detector)):
        state, health = status.get("state"), status.get("health")
        if state == "failed" or health == "failed":
            return {"state": "blocked", "reason": name + "_failed"}
        if state in ("unavailable", "stale", None) or health == "stale":
            return {"state": "unknown", "reason": name + "_unconfirmed"}
        if state == "not_started":
            return {"state": "not_started", "reason": name + "_not_started"}
        if health == "delayed":
            return {"state": "delayed", "reason": name + "_delayed"}
    if normalizer.get("progress", {}).get("state") == "catching_up":
        return {"state": "catching_up", "reason": "receipt_backlog"}
    early_reason = {"failed": "initial_notice_failed", "reconcile_required": "initial_notice_reconciliation_required",
                    "pending": "initial_notice_pending", "unknown": "initial_notice_unconfirmed"}.get(detector.get("early", {}).get("state"))
    if early_reason:
        return {"state": "warning", "reason": early_reason}
    if detector.get("health") == "warning":
        return {"state": "warning", "reason": "evaluation_exclusions"}
    return {"state": "observed", "reason": "recent_worker_reports"}


def early_status(counts):
    """Only observed, typed provisional counters; absent legacy metadata stays absent."""
    fields = ("early_failed", "early_final_reconcile_required", "early_final_link_pending",
              "early_delivery_pending", "early_scan_pending")
    if not isinstance(counts, dict) or not any(key in counts for key in fields):
        return None
    values = {key: counts[key] if type(counts[key]) is int and 0 <= counts[key] <= 2**53 - 1 else None
              for key in fields if key in counts}
    state = ("unknown" if any(value is None for value in values.values()) else
             "failed" if values.get("early_failed") else
             "reconcile_required" if values.get("early_final_reconcile_required") else
             "pending" if any(values.values()) else "observed")
    return {"state": state, "counts": values}


def alert_row(hit):
    source = hit["_source"]
    get = lambda path: text(field(source, path))
    return {"id": identifier(hit["_id"]), "timestamp": get("@timestamp"), "rule": get("rule.id"),
            "historical_review": field(source, "cloud_soc.provenance.review.mode") == "retrospective",
            "title": get("cloud_soc.alert_title") or get("rule.name"), "severity": get("cloud_soc.severity"),
            "organization": get("organization.id"), "source_ip": get("source.ip"),
            "risk_score": field(source, "cloud_soc.risk_score") if type(field(source, "cloud_soc.risk_score")) is int and 0 <= field(source, "cloud_soc.risk_score") <= 100 else None,
            "risk_level": get("cloud_soc.risk_level")}


class Operations:
    def __init__(self, client, *, organizations=None):
        self.client = client.options(request_timeout=5, max_retries=0) if client is not None else None
        self.organizations = tuple(organizations) if organizations is not None else None

    def visible(self, source):
        organization = field(source, "organization.id")
        return self.organizations is None or (isinstance(organization, str) and organization in self.organizations)

    def get(self, index, doc_id, fields):
        if not self.client:
            raise RuntimeError("Monitor not configured")
        if not exact_indices(self.client, [index]):
            return None
        try:
            options = {"source_includes": fields} if fields is not None else {}
            source = self.client.get(index=index, id=identifier(doc_id), **options)["_source"]
            return source if self.visible(source) else None
        except NotFoundError:
            return None

    def series(self, patterns, time_field, start, end, interval, *, records=False, alerts=False):
        # Processing records have no tenant field; never disclose global totals to scoped users.
        if records and self.organizations is not None:
            return {"state": "unavailable"}
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
            query = {"range": {time_field: {"gte": start, "lt": end}}}
            if self.organizations is not None:
                query = {"bool": {"filter": [query, {"terms": {"organization.id": list(self.organizations)}}]}}
            result = checked(self.client.search(index=batch, size=50 if alerts else 0,
                source=ALERT_FIELDS if alerts else False, sort=[{"@timestamp": "desc"}] if alerts else None,
                track_total_hits=True, timeout="4s", allow_partial_search_results=False,
                query=query, aggs=aggs))
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
                if any(not self.visible(hit["_source"]) for hit in result["hits"]["hits"]):
                    raise ValueError("Organization scope mismatch")
                rows = [alert_row(hit) for hit in result["hits"]["hits"]]
        return {"state": "ok", "count": count,
                "buckets": [{"time": iso(stamp), "count": buckets[stamp]} for stamp in sorted(buckets)],
                "rows": rows, "statuses": [{"key": key, "doc_count": statuses[key]} for key in sorted(statuses)]}

    def worker_status(self, worker):
        if self.organizations is not None:
            return {"state": "unavailable"}
        value = self.get(STATUS, worker, ["@timestamp", "state", "last_success", "checkpoint", "initial_start", "error", "detection", "health", "lag_seconds", "late_total", "legacy_excluded", "excluded_total", "history_pending", "pending_contexts", "progress", "counts"])
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
        early = early_status(value.get("counts")) if worker == "detector" else None
        health = 'failed' if state == 'failed' else 'stale' if state == 'stale' else 'delayed' if lag is not None and lag > 1200 else 'warning' if late or legacy or excluded or pending or (early and early["state"] != "observed") else 'healthy'
        result = {"state": state, "health": health, "lag_seconds": lag, "late_total": late, "legacy_excluded": legacy, "excluded_total": excluded, "history_pending": pending,
                "detection": text(value.get('detection')),
                "last_success": text(value.get("last_success")), "checkpoint": text(value.get("checkpoint")),
                "error": text(value.get('error'))}
        if early is not None:
            result["early"] = early
        if parse_time(value.get("initial_start")) is not None:
            result["initial_start"] = iso(parse_time(value["initial_start"]))
        if "pending_contexts" in value:
            queued = value["pending_contexts"]
            result["pending_contexts"] = queued if type(queued) is int and queued >= 0 else None
            if result["pending_contexts"] and result["health"] == "healthy":
                result["health"] = "warning"
        progress = value.get("progress")
        if isinstance(progress, dict) and progress.get("state") == "catching_up":
            processed = progress.get("processed")
            if type(processed) is int and processed >= 0:
                result["progress"] = {"state": "catching_up", "processed": processed, "range_complete": False}
        counts = value.get("counts")
        if worker == "detector" and isinstance(counts, dict) and type(counts.get("events")) is int:
            result["latest_input_count"] = counts["events"] if counts["events"] >= 0 else None
        return result

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
        result["coverage"] = analysis_coverage(result, result["detector"])
        if self.organizations is None:
            try:
                historical = self.worker_status("detector-retrospective")
            except Exception:
                historical = {"state": "unavailable"}
            if historical.get("state") != "not_started":
                result["late_review"] = historical
                if historical.get("state") == "failed":
                    result["coverage"] = {"state": "blocked", "reason": "retrospective_failed"}
            try:
                priority_worker = self.worker_status("normalizer-priority")
            except Exception:
                priority_worker = {"state": "unavailable"}
            if priority_worker.get("state") != "not_started":
                result["priority_normalizer"] = priority_worker
                result["realtime_coverage"] = analysis_coverage(priority_worker, result["detector"])
                try:
                    result["historical_backlog"] = self.backlog(result.get("checkpoint"), priority_worker.get("initial_start"))
                except Exception:
                    result["historical_backlog"] = {"state": "unavailable"}
            try:
                additional = self.worker_status("detector-additional")
            except Exception:
                additional = {"state": "unavailable"}
            if additional.get("state") != "not_started":
                result["additional_detector"] = additional
                coverage = analysis_coverage(result, additional)
                priority = {"blocked": 6, "unknown": 5, "not_started": 4, "delayed": 3,
                            "catching_up": 2, "warning": 1, "observed": 0}
                if priority[coverage["state"]] > priority[result["coverage"]["state"]]:
                    result["coverage"] = {**coverage, "reason": "additional_" + coverage["reason"]}
                if "priority_normalizer" in result:
                    current = result["realtime_coverage"]
                    extra = analysis_coverage(result["priority_normalizer"], additional)
                    if priority[extra["state"]] > priority[current["state"]]:
                        result["realtime_coverage"] = {**extra, "reason": "additional_" + extra["reason"]}
        return result

    def backlog(self, checkpoint, priority_floor):
        """Unconfirmed raw receipt range before the live floor, not event-time age."""
        if self.organizations is not None or not self.client:
            return {"state": "unavailable"}
        lower, upper = parse_time(checkpoint), parse_time(priority_floor)
        if lower is None or upper is None:
            return {"state": "unavailable"}
        if lower >= upper:
            return {"state": "ok", "count": 0, "start": iso(upper), "end": iso(upper),
                    "basis": "unconfirmed_receipt_range"}
        count = 0
        deadline = monotonic() + SERIES_TIMEOUT
        for scope in index_batches(exact_indices(self.client, INDICES)):
            if monotonic() >= deadline:
                raise RuntimeError("Query budget exhausted")
            caps = self.client.field_caps(index=scope, fields=["event.ingested"], include_unmapped=True)["fields"].get("event.ingested", {})
            if not caps or set(caps) - {"date", "date_nanos"}:
                raise ValueError("Receipt mapping missing")
            response = checked(self.client.options(request_timeout=4, max_retries=0).count(
                index=scope, query={"range": {"event.ingested": {"gte": iso(lower), "lt": iso(upper)}}}))
            count = exact_count(count + exact_count(response["count"]))
            if monotonic() >= deadline:
                raise RuntimeError("Query budget exhausted")
        return {"state": "ok", "count": count, "start": iso(lower), "end": iso(upper),
                "basis": "unconfirmed_receipt_range"}

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
            result["risk"] = {"score": result["alert"]["risk_score"], "level": result["alert"]["risk_level"],
                              "version": text(field(source, "cloud_soc.risk_version")),
                              "factors": redact_metadata(field(source, "cloud_soc.risk_factors"))}
            result["rule_snapshot"] = redact_metadata(field(source, "cloud_soc.provenance.rule_snapshot"))
            assessment = field(source, 'cloud_soc.provenance.assessment')
            if isinstance(assessment, dict):
                result['assessment'] = redact_metadata(assessment)
            result["mitre"] = redact_metadata(field(source, "mitre"))
            if offset > len(evidence):
                raise LogQueryError('invalid_evidence_offset', 400, '근거 페이지 범위를 확인하세요.')
            last = min(offset + limit, len(evidence))
            result['evidence_page'] = {'offset': offset, 'limit': limit, 'total': len(evidence),
                                       'positions': list(range(offset, last)), 'next_offset': last if last < len(evidence) else None}
            if position is not None:
                number = int(position)
                if number >= len(evidence):
                    raise LogQueryError("evidence_missing", 404, "요청한 근거 참조가 없습니다.")
                result["evidence"] = self.evidence(evidence[number], organization=field(source, "organization.id"))
            return bounded_json(result)
        except LogQueryError:
            raise
        except Exception:
            raise LogQueryError("alerts_unavailable", 503, "경보·근거를 조회하지 못했습니다. 권한과 참조를 확인하세요.") from None

    def evidence(self, reference, *, organization=None):
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
            if self.organizations is not None:
                return {"state": "normalized_missing_or_expired"}
            return {"state": "normalized_missing_or_expired", "normalized": normalized, "raw": raw}
        if organization is not None and field(norm, "organization.id") != organization:
            return {"state": "provenance_mismatch"}
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
            if self.organizations is not None:
                return {"state": "raw_missing_or_expired"}
            return {"state": "raw_missing_or_expired", "normalized": normalized, "raw": raw}
        if organization is not None and field(source, "organization.id") != organization:
            return {"state": "provenance_mismatch"}
        metadata = ({path: text(field(source, path)) for path in ("@timestamp", "host.name", "user.name", "event.action")}
                    if raw["index"].startswith("raw-logs-") else project_hit({"_index": raw["index"], "_id": raw["id"], "_source": source}))
        return {"state": "exact_reference", "normalized": normalized, "raw": raw,
                "integrity": integrity, "raw_integrity": 'not_hashed_at_detection',
                "normalized_event": {"timestamp": text(norm.get("@timestamp")), "action": text(field(norm, "event.action")),
                                     "outcome": text(field(norm, "event.outcome"))},
                "metadata": metadata,
                "security": security_detail(source)}
