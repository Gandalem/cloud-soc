"""Bounded metadata-only view of immutable historical replay results."""
import json
from collections import Counter

from cloud_soc.portal.log_contract import field, document_reference
from cloud_soc.portal.log_query import LogQueryError
from cloud_soc.privacy import display

INDEX = "soc-normalized-history-v1"
LIMIT = 2000
FIELDS = ["@timestamp", "event.action", "event.category", "event.outcome", "event.ingested",
          "host.name", "cloud_soc.parse_status", "cloud_soc.detail.adapter", "cloud_soc.detail.limitations",
          "cloud_soc.provenance", "cloud_soc.historical_replay"]


def history(client, pairs):
    if list(pairs):
        raise LogQueryError("invalid_filters", 400, "이력 조회는 추가 요청 조건을 지원하지 않습니다.")
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
        return json.dumps({"total": len(rows), "recognized": statuses["recognized"], "partial": statuses["partial"],
                           "timezone_corrected": corrections, "rows": rows}, ensure_ascii=False)
    except Exception as error:
        raise LogQueryError("history_unavailable", 503,
            "재처리 이력을 조회하지 못했습니다. 이력 인덱스·읽기 권한·조회 한도를 확인하세요.") from error
