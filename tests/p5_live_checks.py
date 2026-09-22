"""Opt-in disposable ES tests; synthetic existing alerts, not approved rules."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from elasticsearch import Elasticsearch, AuthorizationException
from cloud_soc.portal.agent_status import iso
from cloud_soc.processing.setup import prepare, ROLE
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from cloud_soc.processing.worker import run_once
from cloud_soc.portal.operations import Operations
from cloud_soc.elastic.repository import ensure_security_alerts_index
from test_processing import fixture


def check_p5(test, admin, monitor, url):
    prepare(admin)
    hit = fixture()
    admin.index(index=hit["_index"], id=hit["_id"], document=hit["_source"], refresh=True)
    key = admin.security.create_api_key(name="synthetic-normalizer", expiration="1h", role_descriptors={"normalizer": ROLE})
    now = datetime.now(timezone.utc)
    start = iso(now - timedelta(minutes=4))
    with tempfile.TemporaryDirectory() as directory, Elasticsearch(url, api_key=key["encoded"], request_timeout=10) as worker:
        state = Path(directory) / "checkpoint.sqlite"
        result = run_once(worker, state, start, now=now + timedelta(seconds=40))
        test.assertGreaterEqual(result["counts"]["normalized"], 7)
        admin.indices.refresh(index=[NORMALIZED, RECORDS, STATUS])
        before = admin.count(index=NORMALIZED)["count"]
        run_once(worker, state, start, now=now + timedelta(seconds=45))
        admin.indices.refresh(index=[NORMALIZED, RECORDS])
        test.assertEqual(admin.count(index=NORMALIZED)["count"], before)
        for operation in (lambda: worker.index(index=NORMALIZED, id="x", document={}),
                          lambda: worker.create(index="security-alerts", id="x", document={}),
                          lambda: worker.create(index="soc-host-raw-denied", id="x", document={})):
            with test.assertRaises(AuthorizationException): operation()
    normalized = admin.search(index=NORMALIZED, query={"term": {"event.outcome": "failure"}}, size=1)["hits"]["hits"][0]
    raw = normalized["_source"]["cloud_soc"]["provenance"]["raw"]
    ensure_security_alerts_index(admin)
    admin.index(index="security-alerts", id="synthetic-p5-alert", refresh=True, document={
        "@timestamp": iso(now), "rule": {"id": "SYNTHETIC-ONLY", "name": "Synthetic fixture, not enabled rule"},
        "cloud_soc": {"severity": "high", "provenance": {"rule_version": "test", "evidence": [
            {"normalized": {"index": NORMALIZED, "id": normalized["_id"]}, "raw": raw}]}}})
    reader = Operations(monitor)
    result = json.loads(reader.summary([("start", start), ("end", iso(now + timedelta(seconds=60)))]))
    for kind in ("intake", "processing", "alerts", "quality"):
        test.assertEqual(result["sections"][kind]["state"], "ok", (kind, result))
    test.assertGreaterEqual(result["sections"]["alerts"]["count"], 1)
    detail = json.loads(reader.detail([("id", "synthetic-p5-alert"), ("evidence", "0")]))
    test.assertEqual(detail["evidence"]["state"], "exact_reference", detail)
    test.assertNotIn("PRIVATE_CANARY", json.dumps(detail))
    with test.assertRaises(AuthorizationException):
        monitor.index(index=STATUS, id="denied", document={})
