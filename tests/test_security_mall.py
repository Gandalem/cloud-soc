"""Synthetic schema/parser/normalizer contracts only; no files, secrets or servers."""

from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from cloud_soc.parsers.security_mall import (
    ADAPTER, ADMIN_RESOURCES, COMMON_FIELDS, SOURCE_FIELDS, VERSION, AuditError, parse,
)
from cloud_soc.portal.log_contract import SOURCE_FIELDS as ENVELOPE_FIELDS, field
from cloud_soc.portal.security_detail import DETAIL_FIELDS, security_detail
from cloud_soc.processing.contract import NORMALIZED, RECORDS, normalize
from cloud_soc.processing.worker import READ_FIELDS, create_batch, scan

STAMP = "2026-10-16T05:00:00.123456789Z"
RECEIVED = "2026-10-16T05:01:00Z"
PROCESSED = "2026-10-16T05:02:00Z"
EVENT_ID = "784a9b30-4a77-43a8-b698-cb67f95269f1"
CANARY = "PRIVATE_CANARY"


def payload(action="login", outcome="success", *, reason=None, anonymous=False):
    result = {
        "schema_version": 1, "@timestamp": STAMP, "event_id": EVENT_ID,
        "service_name": "security-mall", "event_action": action, "event_outcome": outcome,
        "source_ip": "192.0.2.25", "account_id": None if anonymous else "a" * 64, "account_key_id": "v1",
    }
    if action != "login":
        result.update(resource_type="order" if action == "order_view" else ADMIN_RESOURCES[action],
                      authorization_reason=reason)
    return result


def hit(audit=None):
    audit = payload() if audit is None else deepcopy(audit)
    return {
        "_index": "soc-host-raw-mall-synthetic", "_id": "synthetic-raw-1",
        "_source": {"@timestamp": STAMP, "event": {"ingested": RECEIVED},
                    "organization": {"id": "collector-org"}, "host": {"id": "collector-host"},
                    "labels": {"log_source": "security_mall_audit"}, "security_mall": {"audit": audit}},
    }


def normalized(audit):
    identifier, record, event = normalize(hit(audit), PROCESSED)
    assert record["status"] == "normalized"
    assert record["adapter"] == ADAPTER
    assert record["version"] == VERSION
    assert record["normalized"] == {"index": NORMALIZED, "id": identifier}
    return event


@pytest.mark.parametrize("outcome", ["success", "failure"])
def test_login(outcome):
    original = payload(outcome=outcome)
    assert parse(json.dumps(original)) == parse(original)
    event = normalized(original)
    assert event["event"] == {"kind": "event", "category": ["authentication"], "action": "login",
                              "outcome": outcome, "ingested": RECEIVED, "id": EVENT_ID}
    assert event["@timestamp"] == "2026-10-16T05:00:00.123456Z"
    assert event["cloud_soc"]["detail"]["fields"]["timestamp"] == STAMP
    assert event["cloud_soc"]["security_mall"] == {"schema_version": 1, "account_id": "a" * 64,
                                                 "account_key_id": "v1"}
    assert "user" not in event


@pytest.mark.parametrize("action", ADMIN_RESOURCES)
@pytest.mark.parametrize("outcome,reason", [("success", "admin"), ("failure", "admin_required")])
def test_all_documented_admin_actions(action, outcome, reason):
    event = normalized(payload(action, outcome, reason=reason))
    assert event["event"]["category"] == ["iam"]
    assert event["event"]["action"] == action
    assert event["event"]["outcome"] == outcome
    assert event["cloud_soc"]["security_mall"]["resource_type"] == ADMIN_RESOURCES[action]
    assert event["cloud_soc"]["security_mall"]["authorization_reason"] == reason


@pytest.mark.parametrize("outcome,reason", [("success", "owner"), ("failure", "not_owner"), ("failure", "not_found")])
def test_order_access(outcome, reason):
    event = normalized(payload("order_view", outcome, reason=reason))
    assert event["event"]["action"] == "order_view"
    assert event["event"]["category"] == ["iam"]
    assert event["event"]["outcome"] == outcome
    assert event["cloud_soc"]["security_mall"]["resource_type"] == "order"
    assert event["cloud_soc"]["security_mall"]["authorization_reason"] == reason


@pytest.mark.parametrize("action", ["admin_view", "order_view"])
def test_anonymous_denial_has_explicit_null_account_and_no_user(action):
    event = normalized(payload(action, "failure", reason="unauthenticated", anonymous=True))
    assert event["cloud_soc"]["security_mall"]["account_id"] is None
    assert event["cloud_soc"]["security_mall"]["account_key_id"] == "v1"
    assert "user" not in event


@pytest.mark.parametrize("line", [
    "", "{", "null", "[]", "42", '{"schema_version":NaN}', '{"schema_version":Infinity}',
    '{"schema_version":1,"schema_version":2}', '{}\n{}', " " * 8193,
    '"\\ud800"', "[" * 1500 + "]" * 1500,
])
def test_bad_json_never_returns_a_partial_or_leaks_input(line):
    with pytest.raises(AuditError) as error:
        parse(line)
    assert str(error.value).startswith("security_mall_")
    assert CANARY not in str(error.value)


@pytest.mark.parametrize("name,value", [
    ("schema_version", True), ("schema_version", "1"), ("schema_version", 2),
    ("@timestamp", "not-a-time"), ("@timestamp", "2026-02-30T05:00:00Z"),
    ("@timestamp", "2026-10-16T05:00:00"), ("@timestamp", "2026-10-16T05:00:00+09:00"),
    ("@timestamp", "2026-10-16T05:00:00.1234567890Z"), ("@timestamp", []),
    ("event_id", "not-a-uuid"), ("event_id", "00000000-0000-0000-0000-000000000000"),
    ("event_id", EVENT_ID.upper()), ("event_id", {}),
    ("service_name", "user@example.invalid"), ("service_name", "password=PRIVATE_CANARY"),
    ("account_key_id", ""), ("account_key_id", ["v1"]),
    ("account_id", "username"), ("account_id", "A" * 64), ("account_id", None),
    ("source_ip", "unknown"), ("source_ip", "192.0.2.25, 192.0.2.26"), ("source_ip", "fe80::1%eth0"),
    ("event_action", "admin_login"), ("event_action", []), ("event_outcome", "allowed"), ("event_outcome", {}),
])
def test_invalid_schema_fields_are_rejected_in_parser_and_normalizer(name, value):
    audit = payload()
    audit[name] = value
    with pytest.raises(AuditError) as error:
        parse(audit)
    _identifier, record, event = normalize(hit(audit), PROCESSED)
    assert event is None
    assert record["status"] == error.value.status
    assert record["reason"] == error.value.reason
    assert CANARY not in json.dumps(record)


@pytest.mark.parametrize("name", COMMON_FIELDS)
def test_every_common_field_is_required(name):
    audit = payload()
    del audit[name]
    with pytest.raises(AuditError, match="fields_missing"):
        parse(audit)


@pytest.mark.parametrize("action,outcome,reason,anonymous", [
    ("admin_view", "success", "admin_required", False), ("admin_view", "failure", "admin", False),
    ("admin_view", "success", "owner", False), ("order_view", "success", "not_owner", False),
    ("order_view", "failure", "owner", False), ("order_view", "success", "admin", False),
    ("order_view", "failure", "unauthenticated", False), ("order_view", "success", "unauthenticated", True),
    ("order_view", "failure", "not_owner", True), ("order_view", "failure", "unknown", False),
])
def test_inconsistent_authorization_claims_are_rejected(action, outcome, reason, anonymous):
    audit = payload(action, outcome, reason=reason, anonymous=anonymous)
    _identifier, record, event = normalize(hit(audit), PROCESSED)
    assert event is None
    assert record["reason"] == "security_mall_authorization_invalid"


def test_authorization_requires_resource_and_reason_and_login_does_not_claim_them():
    for name in ("resource_type", "authorization_reason"):
        audit = payload("order_view", "failure", reason="not_owner")
        del audit[name]
        with pytest.raises(AuditError, match="fields_missing"):
            parse(audit)
    audit = payload("order_view", "failure", reason="not_owner")
    audit["resource_type"] = "user"
    with pytest.raises(AuditError, match="authorization_invalid"):
        parse(audit)
    audit = payload()
    audit["authorization_reason"] = "owner"
    with pytest.raises(AuditError, match="login_invalid"):
        parse(audit)


def test_allowlisted_output_cannot_copy_sensitive_payload_or_override_collector_identity():
    audit = payload("order_view", "failure", reason="not_owner")
    audit.update({name: CANARY for name in ("password", "cookie", "token", "username", "buyerName",
                                          "buyerAddr", "buyerPhone", "Authorization", "message", "hmac_key")})
    audit.update(organization={"id": CANARY}, host={"id": CANARY}, event={"id": CANARY})
    sample = hit(audit)
    sample["_source"].update(message=CANARY, user={"id": CANARY, "name": CANARY},
                              cloud={"provider": CANARY}, destination={"ip": "198.51.100.99"})
    sample["_source"]["event"].update(id=CANARY, code=CANARY, dataset=CANARY, provider=CANARY)
    sample["_source"]["source"] = {"ip": "198.51.100.99"}
    before = deepcopy(sample)
    _identifier, record, event = normalize(sample, PROCESSED)
    assert event["organization"] == {"id": "collector-org"}
    assert event["host"] == {"id": "collector-host"}
    assert event["source"] == {"ip": "192.0.2.25"}
    assert event["event"]["id"] == EVENT_ID
    assert set(event) == {"@timestamp", "organization", "event", "cloud_soc", "service", "host", "source"}
    assert CANARY not in json.dumps([record, event, parse(json.dumps(audit)), security_detail(sample["_source"])])
    assert "198.51.100.99" not in json.dumps(event)
    assert sample == before


@pytest.mark.parametrize("problem", ["organization", "host", "timestamp", "scope", "object", "label"])
def test_collector_envelope_is_required_and_not_filled_from_payload(problem):
    sample = hit()
    if problem == "organization":
        del sample["_source"]["organization"]
        sample["_source"]["security_mall"]["audit"]["organization"] = {"id": "forged"}
    elif problem == "host":
        del sample["_source"]["host"]
        sample["_source"]["security_mall"]["audit"]["host"] = {"id": "forged"}
    elif problem == "timestamp":
        sample["_source"]["@timestamp"] = RECEIVED
    elif problem == "scope":
        sample["_index"] = "soc-network-synthetic"
    elif problem == "object":
        sample["_source"]["security_mall"]["audit"] = json.dumps(payload())
    else:
        sample["_source"]["labels"]["log_source"] = "unknown"
    _identifier, record, event = normalize(sample, PROCESSED)
    assert event is None
    assert record["status"] in ("invalid", "unsupported")


def test_ipv6_is_canonicalized_without_claiming_end_user_or_forwarded_address():
    audit = payload()
    audit.update(source_ip="2001:db8:0:0:0:0:0:25", forwarded_for="198.51.100.99")
    event = normalized(audit)
    assert event["source"]["ip"] == "2001:db8::25"
    assert "ip_is_observed_socket_peer" in event["cloud_soc"]["detail"]["limitations"]
    assert "198.51.100.99" not in json.dumps(event)


def test_key_rotation_is_preserved_and_not_flattened_into_a_username_or_unscoped_user_id():
    audit = payload()
    before = normalized(audit)
    audit["account_key_id"] = "v2"
    after = normalized(audit)
    assert before["cloud_soc"]["security_mall"] != after["cloud_soc"]["security_mall"]
    assert "user" not in before and "user" not in after


def test_exact_reference_event_id_and_immutable_replay_ids():
    sample = hit()
    identifier, record, event = normalize(sample, PROCESSED)
    assert normalize(sample, "2026-10-17T05:02:00Z")[0] == identifier
    assert event["cloud_soc"]["provenance"]["raw"] == {"index": sample["_index"], "id": sample["_id"]}
    assert record["raw"] == event["cloud_soc"]["provenance"]["raw"]
    assert event["event"]["id"] == EVENT_ID
    sample["_id"] = "synthetic-raw-2"
    other_id, _record, other_event = normalize(sample, PROCESSED)
    assert other_id != identifier
    assert other_event["event"]["id"] == EVENT_ID
    assert other_event["cloud_soc"]["provenance"]["raw"]["id"] == "synthetic-raw-2"
    stored = set()

    def bulk(*, operations):
        results = []
        for operation in operations[::2]:
            identity = tuple(operation["create"].values())
            if identity in stored:
                results.append({"create": {"status": 409, "error": {"type": "version_conflict_engine_exception"}}})
            else:
                stored.add(identity)
                results.append({"create": {"status": 201}})
        return {"items": results}

    client = Mock()
    client.bulk.side_effect = bulk
    documents = [(NORMALIZED, identifier, event), (RECORDS, identifier, record)]
    create_batch(client, documents)
    create_batch(client, documents)
    assert len(stored) == 2


def project(source, fields):
    """Emulate ES leaf-field projection; no wildcard/parent or message fallback."""
    selected = {}
    for path in fields:
        value = field(source, path)
        if value is None and path != "security_mall.audit.account_id":
            continue
        target = selected
        parts = path.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    return selected


@pytest.mark.parametrize("anonymous", [False, True])
def test_worker_field_projection_preserves_parser_contract_without_requesting_payload_parent(anonymous):
    assert set(SOURCE_FIELDS) <= set(DETAIL_FIELDS) <= set(READ_FIELDS)
    assert all("*" not in name for name in DETAIL_FIELDS)
    assert "security_mall.audit" not in DETAIL_FIELDS
    audit = payload("order_view", "failure", reason="unauthenticated" if anonymous else "not_owner", anonymous=anonymous)
    sample = hit(audit)
    sample["_source"]["security_mall"]["audit"]["password"] = CANARY
    client = Mock()
    client.indices.resolve_index.return_value = {"indices": [{"name": sample["_index"]}]}
    client.field_caps.return_value = {"fields": {"event.ingested": {"date": {}}}}
    client.open_point_in_time.return_value = {"id": "synthetic-pit"}
    calls = 0

    def search(**kwargs):
        nonlocal calls
        calls += 1
        filtered = {**sample, "sort": [1], "_source": project(sample["_source"], kwargs["source"])}
        return {"hits": {"hits": [filtered] if calls == 1 else []}}

    client.search.side_effect = search
    scanned = list(scan(client, RECEIVED, PROCESSED))
    assert len(scanned) == 1
    assert CANARY not in json.dumps(scanned)
    assert normalize(scanned[0], PROCESSED)[2] == normalize(sample, PROCESSED)[2]
    assert security_detail(project(sample["_source"], ENVELOPE_FIELDS + DETAIL_FIELDS))["status"] == "recognized"
    client.close_point_in_time.assert_called_once_with(id="synthetic-pit")
