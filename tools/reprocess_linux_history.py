"""Replay the verified 757-document scope into isolated immutable history indices."""
import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import Elasticsearch, ConflictError
from cloud_soc.portal.log_contract import field
from cloud_soc.processing.contract import normalize, RECORDS, NORMALIZED
from cloud_soc.processing.worker import READ_FIELDS, checked

EVENTS = "soc-normalized-history-v1"
HISTORY = "soc-processing-history-v1"
SCOPE = {"gte": "2026-10-05T04:00:00Z", "lt": "2026-10-05T04:15:00Z"}
JOB = "ubuntu-linux-parser-757-v3"
MANIFEST = Path("/backup/linux-history-757-manifest.json")


def connect(**auth):
    return Elasticsearch("https://elasticsearch:9200", ca_certs="/run/ca.crt",
                         request_timeout=60, max_retries=2, retry_on_timeout=True, **auth)


def replay(client, operations):
    counts = Counter()
    for index, identifier, document in operations:
        try:
            client.create(index=index, id=identifier, document=document)
            counts["created"] += 1
        except ConflictError:
            existing = client.get(index=index, id=identifier)["_source"]
            if existing != document:
                raise RuntimeError("Existing history document differs; stopped without overwriting")
            counts["existing"] += 1
    for index in (EVENTS, HISTORY):
        client.indices.refresh(index=index)
    for index, identifier, document in operations:
        if client.get(index=index, id=identifier)["_source"] != document:
            raise RuntimeError("Stored history verification failed")
    return counts


def main():
    now = datetime.now(timezone.utc).isoformat()
    if MANIFEST.exists():
        saved = json.loads(MANIFEST.read_text())
        assert saved["job"] == JOB and saved["scope"] == SCOPE
        now = saved["processed_at"]
    operations, refs, statuses, adapters = [], [], Counter(), Counter()
    corrected = 0
    with connect(basic_auth=("cloud_soc_agent_monitor", Path("/run/monitor").read_text().strip())) as client:
        result = checked(client.search(index=RECORDS, size=1000, track_total_hits=True,
            query={"bool": {"filter": [{"term": {"status": "unsupported"}},
                                     {"range": {"event.ingested": SCOPE}}]}}))
        hits = result["hits"]["hits"]
        assert result["hits"]["total"] == {"value": len(hits), "relation": "eq"}
        refs = sorted({(h["_source"]["raw"]["index"], h["_source"]["raw"]["id"]) for h in hits})
        assert len(refs) == 757, "Target scope changed"
        for start in range(0, len(refs), 100):
            batch = refs[start:start + 100]
            docs = client.mget(docs=[{"_index": i, "_id": d} for i, d in batch], source=READ_FIELDS)["docs"]
            assert len(docs) == len(batch)
            for doc in docs:
                assert doc.get("found") and not doc.get("error"), "Raw document unavailable"
                sample = deepcopy(doc)
                source = sample["_source"]
                correction = None
                if not field(source, "event.timezone") and field(source, "log.file.path") in {
                        "/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"}:
                    source.setdefault("event", {})["timezone"] = "+09:00"
                    correction = {"field": "event.timezone", "original": None, "applied": "+09:00",
                                  "basis": "operator_verified_vm_timezone", "raw_modified": False}
                    corrected += 1
                identifier, record, event = normalize(sample, now)
                assert event is not None and record["status"] == "normalized", "Normalization incomplete"
                assert record["adapter"] in {"linux_operational_v1", "linux_unclassified_v1"}
                audit = {"job": JOB, "scope": SCOPE, "history_only": True,
                         "timezone_correction": correction}
                event["cloud_soc"]["historical_replay"] = audit
                record["historical_replay"] = audit
                record["normalized"]["index"] = EVENTS
                operations.extend([(EVENTS, identifier, event), (HISTORY, identifier, record)])
                statuses[event["cloud_soc"]["parse_status"]] += 1
                adapters[record["adapter"]] += 1
    assert corrected == 385 and statuses == {"recognized": 744, "partial": 13}
    assert len({(i, d) for i, d, _ in operations}) == 1514
    manifest = {"job": JOB, "scope": SCOPE, "processed_at": now, "operations": operations}
    if MANIFEST.exists():
        assert saved == json.loads(json.dumps(manifest)), "Replay manifest differs; stopped"
    else:
        with MANIFEST.open("x", encoding="utf-8") as output:
            json.dump(manifest, output, ensure_ascii=False, sort_keys=True)
        MANIFEST.chmod(0o600)
    print("저장 전 검사: 757건 / 시간대 보완 385건 / recognized 744 / partial 13", flush=True)
    key_id = None
    with connect(basic_auth=("elastic", Path("/run/admin").read_text().strip())) as admin:
        try:
            for target, original in ((EVENTS, NORMALIZED), (HISTORY, RECORDS)):
                if admin.indices.exists(index=target):
                    mapping = admin.indices.get_mapping(index=target)
                    assert set(mapping) == {target} and mapping[target]["mappings"].get("_meta", {}).get("contract") == JOB
                else:
                    mappings = deepcopy(admin.indices.get_mapping(index=original)[original]["mappings"])
                    mappings["dynamic"] = False
                    mappings["_meta"] = {"contract": JOB, "source_contract": original, "history_only": True}
                    admin.indices.create(index=target, settings={"number_of_shards": 1, "number_of_replicas": 0}, mappings=mappings)
            key = admin.security.create_api_key(name=JOB, expiration="1h", role_descriptors={JOB: {
                "cluster": [], "indices": [{"names": [EVENTS, HISTORY],
                    "privileges": ["create_doc", "read", "maintenance"]}]}})
            key_id = key["id"]
            with connect(api_key=key["encoded"]) as writer:
                counts = replay(writer, operations)
            print("이력 정규화 저장·검증: 757건", flush=True)
            print("이력 처리 기록 저장·검증: 757건", flush=True)
            print("저장 결과:", dict(counts), flush=True)
            print("파서별:", dict(adapters), flush=True)
            print("인덱스:", EVENTS, HISTORY, flush=True)
            print("원본·기존 기록·현재 탐지 checkpoint 변경 없음", flush=True)
        finally:
            if key_id:
                response = admin.security.invalidate_api_key(ids=[key_id])
                if response.get("error_count", 0):
                    raise RuntimeError("Temporary key revocation failed")
                print("임시 저장 키 폐기 완료", flush=True)


if __name__ == "__main__":
    main()
