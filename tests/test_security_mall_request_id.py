"""6-D-2 local-only contracts: synthetic events, real collector JS, modeled ES.

No Filebeat process, Painless compilation, VM deployment or Elasticsearch I/O.
"""
from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml

from cloud_soc.detection.engine import detect_events
from cloud_soc.parsers.security_mall import AuditError, parse, SOURCE_FIELDS
from cloud_soc.parsers.security_mall_edge import envelope, parse_access, parse_native
from cloud_soc.portal.log_contract import field
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.processing.worker import READ_FIELDS
from test_security_mall import payload, hit, PROCESSED
from test_security_mall_collection import collector, line, receive  # noqa: F401 (pytest fixture)
from test_security_mall_detection import rules, sequence
from test_security_mall_edge import TSV, native, MANIFEST, RID as EDGE_RID

ROOT = Path(__file__).resolve().parents[1]
RID = "atI3YyuokZgOiD33Gh3LxwAAAAI"


@pytest.mark.parametrize("audit", [payload(outcome="failure"), payload(),
    payload("order_view", "failure", reason="not_owner"),
    payload("admin_view", "success", reason="admin"),
    payload("admin_view", "failure", reason="unauthenticated", anonymous=True)])
def test_app_collection_normalization_preserves_optional_id_privacy_and_provenance(collector, audit):
    audit["request_id"] = RID
    queued = collector([line(audit)])[0]
    assert not queued["cancelled"]
    assert queued["source"]["security_mall"]["audit"] == audit
    received = receive(queued)
    raw = {"_index": "soc-host-raw-mall-isolated-unit", "_id": queued["id"], "_source": received}
    identifier, record, event = normalize(raw, PROCESSED)
    assert record["status"] == "normalized"
    assert field(event, "http.request.id") == RID
    assert field(event, "event.id") == audit["event_id"]
    assert field(event, "cloud_soc.security_mall.account_id") == audit["account_id"]
    assert field(event, "cloud_soc.security_mall.account_key_id") == audit["account_key_id"]
    assert field(event, "cloud_soc.provenance.raw") == {"index": raw["_index"], "id": raw["_id"]}
    assert "request_id_is_unverified_correlation_hint" in field(event, "cloud_soc.detail.limitations")
    serialized = json.dumps([received, event])
    assert all(term not in serialized for term in ("MUST_NOT_LEAVE", "message", "event.original", "Cookie", "Authorization"))
    # New metadata must not change the raw or normalized replay identity.
    old = deepcopy(audit)
    del old["request_id"]
    assert collector([line(old)])[0]["id"] == queued["id"]
    raw["_source"]["security_mall"]["audit"] = old
    assert normalize(raw, PROCESSED)[0] == identifier


@pytest.mark.parametrize("candidate", [None, "absent"])
def test_legacy_and_explicit_null_are_compatible(collector, candidate):
    audit = payload()
    if candidate is None:
        audit["request_id"] = None
    queued = collector([line(audit)])[0]
    assert not queued["cancelled"]
    _, record, event = normalize(hit(audit), PROCESSED)
    assert record["status"] == "normalized" and field(event, "http.request.id") is None
    assert "request_id_is_unverified_correlation_hint" not in field(event, "cloud_soc.detail.limitations")


@pytest.mark.parametrize("candidate", ["", "short", RID + "\n", " " + RID, RID + ",", "a" * 28,
    "a" * 26 + "/", [RID], {"raw": "PRIVATE_CANARY"}, 27, True])
def test_invalid_request_ids_rejected_without_echoing_input(collector, candidate):
    audit = dict(payload(), request_id=candidate)
    with pytest.raises(AuditError, match="^security_mall_request_id_invalid$"):
        parse(audit)
    assert collector([line(audit)]) == [{"cancelled": True}]
    _, record, event = normalize(hit(audit), PROCESSED)
    assert event is None and record["reason"] == "security_mall_request_id_invalid"
    assert "PRIVATE_CANARY" not in json.dumps(record)


def test_request_id_cannot_smuggle_raw_fields_or_duplicate_keys(collector):
    audit = dict(payload(), request_id=RID)
    private = dict(audit, message="PRIVATE_CANARY", password="PRIVATE_CANARY")
    duplicate = line(audit)[:-1] + ',"request_id":"' + RID + '"}'
    assert collector([line(private), duplicate]) == [{"cancelled": True}, {"cancelled": True}]
    # Defense in depth: the pure normalizer copies allowlisted metadata only.
    _, record, event = normalize(hit(private), PROCESSED)
    assert record["status"] == "normalized"
    assert "PRIVATE_CANARY" not in json.dumps(event)


def test_existing_apache_header_boundary_and_field_projection_contract():
    proxy = (ROOT / "deploy/security-mall/waf-lab/conf/proxy.conf").read_text()
    assert proxy.index("RequestHeader unset X-Request-ID") < proxy.index('RequestHeader set X-Request-ID "%{UNIQUE_ID}e"')
    for name in ("X-Forwarded-For", "Forwarded", "X-Correlation-ID"):
        assert "RequestHeader unset " + name in proxy
    assert "%{UNIQUE_ID}e" in proxy and "%{c}a" in proxy
    assert "security_mall.audit.request_id" in SOURCE_FIELDS
    assert "security_mall.audit.request_id" in READ_FIELDS
    config = yaml.safe_load((ROOT / "filebeat/security-mall/filebeat.example.yml").read_text())
    includes = next(p["include_fields"]["fields"] for p in config["processors"] if "include_fields" in p)
    assert "security_mall.audit.request_id" in includes
    template = json.loads((ROOT / "deploy/security-mall/index-template.json").read_text())
    audit_mapping = template["template"]["mappings"]["properties"]["security_mall"]["properties"]["audit"]["properties"]
    assert audit_mapping["request_id"] == {"type": "keyword"}
    # Inspect the authored configuration only; native Painless is NOT run here.
    pipeline = yaml.safe_load((ROOT / "deploy/security-mall/ingest-pipeline.yml").read_text())
    guard = pipeline["processors"][0]["script"]["source"]
    assert "allowed.add('request_id')" in guard and "/[A-Za-z0-9_-]{27}/" in guard


def test_same_request_common_field_requires_organization_host_and_service_scope():
    app = hit(dict(payload(), request_id=RID))
    rows = [app]
    for body in (parse_access(TSV.replace(EDGE_RID, RID)), parse_native(native(request_id=RID), MANIFEST)):
        source = envelope(body, "collector-org", "collector-host")
        source["event"]["ingested"] = "2026-10-16T14:00:00Z"
        rows.append({"_index": "soc-host-raw-mall-edge-unit", "_id": source["event"]["id"], "_source": source})
    events = []
    for raw in rows:
        _, record, event = normalize(raw, PROCESSED)
        assert record["status"] == "normalized"
        events.append(event)
    paths = ("organization.id", "host.id", "service.name", "http.request.id")
    # Candidate matching contract, NOT a new join engine or proof of proxy origin.
    scope = tuple(field(events[0], p) for p in paths)
    assert all(tuple(field(event, p) for p in paths) == scope for event in events)
    for group in ("organization", "host"):
        other = deepcopy(app)
        other["_source"][group]["id"] = "different-scope"
        _, _, normalized = normalize(other, PROCESSED)
        assert tuple(field(normalized, p) for p in paths) != scope
    assert len({field(event, "event.id") for event in events}) == 3


def test_existing_access_and_auth_detection_ignore_unverified_request_id():
    # Feed the optional ID through the normalizer used by the real rule engine.
    access = hit(dict(payload("order_view", "failure", reason="not_owner"), request_id=RID))
    identifier, record, row = normalize(access, PROCESSED)
    assert record["status"] == "normalized"
    row["_cloud_soc_meta"] = {"index": NORMALIZED, "document_id": identifier}
    found = detect_events([row], rules())
    assert len(found) == 1 and found[0]["rule_id"] == "WEB-ACCESS-01"
    assert detect_events([row, deepcopy(row)], rules()) == found
    login_rows = sequence()
    for number, event in enumerate(login_rows):
        event["http"] = {"request": {"id": RID if number % 2 else "B" * 27}}
    found = detect_events(login_rows, rules())
    assert len(found) == 1 and found[0]["rule_id"] == "WEB-AUTH-01"
    assert detect_events(login_rows + deepcopy(login_rows), rules()) == found
