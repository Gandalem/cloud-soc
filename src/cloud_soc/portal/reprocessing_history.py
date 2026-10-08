"""Bounded metadata-only view of immutable historical replay results."""
import json
from collections import Counter
import re

from cloud_soc.portal.log_contract import field, document_reference
from cloud_soc.portal.log_query import LogQueryError
from cloud_soc.privacy import display, sensitive

INDEX = "soc-normalized-history-v1"
LIMIT = 2000
FIELDS = ["@timestamp", "event.action", "event.category", "event.outcome", "event.ingested",
          "host.name", "cloud_soc.parse_status", "cloud_soc.detail.adapter", "cloud_soc.detail.limitations",
          "cloud_soc.provenance", "cloud_soc.historical_replay"]


def history(client, pairs):
    pairs = list(pairs)
    args = dict(pairs)
    try:
        if len(args) != len(pairs) or set(args) - {"q", "status", "page", "limit"}:
            raise ValueError()
        query = args.get("q", "").strip().casefold()
        status_filter = args.get("status", "")
        page_text, limit_text = args.get("page", "1"), args.get("limit", "50")
        if (len(query) > 128 or sensitive(query) or any(ord(char) < 32 for char in query)
                or status_filter not in {"", "recognized", "partial"}
                or not re.fullmatch(r"[0-9]{1,4}", page_text)
                or not re.fullmatch(r"[0-9]{1,3}", limit_text)):
            raise ValueError()
        page, limit = int(page_text), int(limit_text)
        if not 1 <= page <= LIMIT or not 1 <= limit <= 100:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise LogQueryError("invalid_filters", 400, "재처리 이력의 검색·상태·페이지 조건을 확인하세요.") from None
    if client is None:
        raise LogQueryError("monitor_not_configured", 503, "이력 조회 계정이 준비되지 않았습니다.")
    try:
        mapping = client.indices.get_mapping(index=INDEX)
        if (set(mapping) != {INDEX} or mapping[INDEX]["mappings"].get("_meta", {}).get("contract")
                != "ubuntu-linux-parser-757-v3"):
            raise ValueError("history_contract_mismatch")
        result = client.search(index=INDEX, size=LIMIT, source=FIELDS, track_total_hits=True,
                               sort=[{"@timestamp": "desc"}], query={"match_all": {}},
                               allow_partial_search_results=False, timeout="10s")
        total = result["hits"]["total"]
        hits = result["hits"]["hits"]
        if (result.get("timed_out") or result.get("terminated_early") or result.get("_shards", {}).get("failed", 0)
                or total["relation"] != "eq" or total["value"] != len(hits) or len(hits) > LIMIT):
            raise ValueError("incomplete_history")
        rows, statuses = [], Counter()
        corrections = 0
        for hit in hits:
            source = hit["_source"]
            audit = field(source, "cloud_soc.historical_replay") or {}
            if audit.get("job") != "ubuntu-linux-parser-757-v3" or audit.get("history_only") is not True:
                raise ValueError("unexpected_history_document")
            status = field(source, "cloud_soc.parse_status")
            if status not in {"recognized", "partial"}:
                raise ValueError("unexpected_parse_status")
            correction = audit.get("timezone_correction")
            corrected = bool(correction and correction.get("applied") == "+09:00" and correction.get("raw_modified") is False)
            corrections += corrected
            statuses[status] += 1
            raw = field(source, "cloud_soc.provenance.raw") or {}
            reference = document_reference(raw.get("index"), raw.get("id"))
            if reference is None:
                raise ValueError("invalid_raw_reference")
            rows.append({"id": hit["_id"], "timestamp": field(source, "@timestamp"),
                "ingested": field(source, "event.ingested"), "host": display(field(source, "host.name")),
                "action": display(field(source, "event.action")), "outcome": display(field(source, "event.outcome")),
                "parse_status": status, "adapter": display(field(source, "cloud_soc.detail.adapter")),
                "timezone_corrected": corrected, "raw": reference,
                "time_basis": display(field(source, "cloud_soc.provenance.time.basis"))})
        rows.sort(key=lambda row: (row["timestamp"] or "", row["id"]), reverse=True)
        response = {"total": len(rows), "recognized": statuses["recognized"], "partial": statuses["partial"],
                    "timezone_corrected": corrections, "rows": rows}
        if args:
            selected = [row for row in rows if (not status_filter or row["parse_status"] == status_filter)
                        and query in f'{row["host"] or ""} {row["action"] or ""}'.casefold()]
            response.update(filtered_total=len(selected), page=page, limit=limit,
                            pages=max(1, (len(selected) + limit - 1) // limit),
                            rows=selected[(page - 1) * limit:page * limit])
        return json.dumps(response, ensure_ascii=False)
    except Exception as error:
        raise LogQueryError("history_unavailable", 503,
            "재처리 이력을 조회하지 못했습니다. 이력 인덱스·읽기 권한·조회 한도를 확인하세요.") from error
