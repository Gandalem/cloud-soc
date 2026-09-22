"""Read-only operational totals and exact evidence, never synthetic incidents."""

from datetime import datetime, timezone
import re
from elasticsearch import NotFoundError
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import INDICES, SOURCE_FIELDS, field, parse_filters, document_reference, project_hit
from cloud_soc.portal.log_query import LogQueryError, bounded_json
from cloud_soc.portal.security_detail import DETAIL_FIELDS, security_detail, text
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from cloud_soc.processing.worker import checked

ALERT = "security-alerts"
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
    return names


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
            return self.client.get(index=index, id=identifier(doc_id), source_includes=fields)["_source"]
        except NotFoundError:
            return None

    def series(self, patterns, time_field, start, end, interval, *, records=False, alerts=False):
        if not self.client:
            raise RuntimeError()
        names = exact_indices(self.client, patterns)
        if not names:
            return {"state": "no_index", "count": 0, "buckets": [], "rows": [], "statuses": []}
        caps = self.client.field_caps(index=names, fields=[time_field], include_unmapped=True)["fields"].get(time_field, {})
        if not caps or set(caps) - {"date", "date_nanos"}:
            raise ValueError("Time mapping missing")
        aggs = {"trend": {"date_histogram": {"field": time_field, "fixed_interval": interval,
                    "min_doc_count": 0, "extended_bounds": {"min": start, "max": iso(parse_time(end))}}}}
        if records:
            aggs["status"] = {"terms": {"field": "status", "size": 10}}
        result = checked(self.client.search(index=names, size=50 if alerts else 0,
            source=ALERT_FIELDS if alerts else False, sort=[{"@timestamp": "desc"}] if alerts else None,
            track_total_hits=True, timeout="4s", allow_partial_search_results=False,
            query={"range": {time_field: {"gte": start, "lt": end}}}, aggs=aggs))
        if result["hits"]["total"]["relation"] != "eq":
            raise ValueError("Inexact total")
        return {"state": "ok", "count": result["hits"]["total"]["value"],
                "buckets": [{"time": b["key_as_string"], "count": b["doc_count"]} for b in result["aggregations"]["trend"]["buckets"]],
                "rows": [alert_row(hit) for hit in result["hits"]["hits"]] if alerts else [],
                "statuses": [{"key": b["key"] if b["key"] in ("normalized", "unsupported", "invalid") else "unknown",
                              "doc_count": b["doc_count"]} for b in result["aggregations"].get("status", {}).get("buckets", [])]}

    def pipeline(self):
        value = self.get(STATUS, "normalizer", ["@timestamp", "state", "last_success", "checkpoint", "error", "detection"])
        if value is None:
            return {"state": "not_started", "detection": "disabled_pending_approval"}
        stamp = parse_time(value.get("@timestamp"))
        age = (datetime.now(timezone.utc) - stamp).total_seconds() if stamp else None
        state = value.get("state")
        return {"state": state if age is not None and 0 <= age <= 300 and state in ("success", "running", "failed", "waiting") else "stale",
                "last_success": text(value.get("last_success")), "checkpoint": text(value.get("checkpoint")),
                "detection": "disabled_pending_approval"}

    def summary(self, pairs):
        pairs = list(pairs)
        try:
            if any(key not in ("start", "end") for key, _ in pairs):
                raise ValueError()
            filters = parse_filters(pairs)
        except ValueError:
            raise LogQueryError("invalid_operations_query", 400, "조회 기간을 확인하세요.") from None
        interval = "5m" if (parse_time(filters.end) - parse_time(filters.start)).total_seconds() <= 86400 else "1h"
        result = {"start": filters.start, "end": filters.end, "incident_work": "not_implemented", "sections": {}}
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
            if len(pairs) != len(values) or set(values) not in ({"id"}, {"id", "evidence"}):
                raise ValueError()
            doc_id = identifier(values["id"])
            position = values.get("evidence")
            if position is not None and not re.fullmatch(r"[0-9]{1,3}", position):
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
            if position is not None:
                number = int(position)
                if number >= min(len(evidence), 100):
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
        norm = self.get(normalized["index"], normalized["id"], ["@timestamp", "event.category", "event.action", "event.outcome", "cloud_soc.provenance.raw"])
        if norm is None:
            return {"state": "normalized_missing_or_expired", "normalized": normalized, "raw": raw}
        if field(norm, "cloud_soc.provenance.raw") != raw:
            return {"state": "provenance_mismatch"}
        source = self.get(raw["index"], raw["id"], list(SOURCE_FIELDS + DETAIL_FIELDS))
        if source is None:
            return {"state": "raw_missing_or_expired", "normalized": normalized, "raw": raw}
        metadata = ({path: text(field(source, path)) for path in ("@timestamp", "host.name", "user.name", "event.action")}
                    if raw["index"].startswith("raw-logs-") else project_hit({"_index": raw["index"], "_id": raw["id"], "_source": source}))
        return {"state": "exact_reference", "normalized": normalized, "raw": raw,
                "metadata": metadata,
                "security": security_detail(source)}
