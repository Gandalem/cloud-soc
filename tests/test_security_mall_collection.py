"""Real collector JS + modeled Filebeat/ES boundaries, synthetic files only.

This does NOT execute Filebeat, Painless, or a live Elasticsearch service.
"""

from copy import deepcopy
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
from unittest.mock import Mock

import pytest
import yaml

from cloud_soc.parsers.security_mall import COMMON_FIELDS, AUTHORIZATION_FIELDS, OPTIONAL_FIELDS, parse, SOURCE_FIELDS
from cloud_soc.portal.log_contract import field
from cloud_soc.processing.contract import normalize, NORMALIZED, RECORDS
from cloud_soc.processing.worker import create_batch
from test_security_mall import payload, ADMIN_RESOURCES, EVENT_ID, STAMP

ROOT = Path(__file__).resolve().parents[1]
CONFIG = yaml.safe_load((ROOT / "filebeat/security-mall/filebeat.example.yml").read_text(encoding="utf-8"))
PIPELINE = yaml.safe_load((ROOT / "deploy/security-mall/ingest-pipeline.yml").read_text(encoding="utf-8"))
TEMPLATE = json.loads((ROOT / "deploy/security-mall/index-template.json").read_text(encoding="utf-8"))
INDEX = "soc-host-raw-mall-isolated-synthetic"
RECEIVED = "2026-10-16T05:10:00Z"
PROCESSED = "2026-10-16T05:11:00Z"
CANARY = "PRIVATE_CANARY_MALL_NEVER_QUEUE"
PROCESSORS = CONFIG["processors"]
PARAMS = next(p["script"]["params"] for p in PROCESSORS if "script" in p)
FINGERPRINT = next(p["fingerprint"] for p in PROCESSORS if "fingerprint" in p)
INCLUDES = next(p["include_fields"]["fields"] for p in PROCESSORS if "include_fields" in p)

# Native Filebeat processors below are deliberately a model. Only the referenced
# production processor JavaScript is executed, unchanged, in an isolated VM.
HARNESS = r"""
const fs = require('fs'), vm = require('vm'), crypto = require('crypto');
const request = JSON.parse(fs.readFileSync(0, 'utf8'));
const context = vm.createContext({});
vm.runInContext(fs.readFileSync(request.script, 'utf8'), context, {timeout: 1000});
context.register(request.params);
function get(root, path) {
  let value = root;
  for (const part of path.split('.')) {
    if (value === null || typeof value !== 'object' || !(part in value)) return undefined;
    value = value[part];
  }
  return value;
}
function put(root, path, value) {
  const parts = path.split('.'); let node = root;
  for (const part of parts.slice(0, -1)) node = node[part] || (node[part] = {});
  node[parts[parts.length - 1]] = value;
}
const results = request.lines.map(item => {
  let cancelled = false;
  const data = {'@timestamp': '2026-10-16T05:09:00Z', message: item.line,
    '@metadata': {mall_validated: false, op_type: 'create'},
    event: {original: 'MUST_NOT_LEAVE', ingested: '1900-01-01T00:00:00Z'},
    host: {id: 'UNTRUSTED_DEFAULT', name: 'MUST_NOT_LEAVE'},
    agent: {id: 'MUST_NOT_LEAVE'}, ecs: {version: 'MUST_NOT_LEAVE'}, type: 'log'};
  const event = {
    Get: path => get(data, path),
    Put: (path, value) => { if (item.fail_on === path) throw Error('PRIVATE_ERROR'); put(data, path, value); },
    Delete: path => {
      const parts = path.split('.'); let node = data;
      for (const part of parts.slice(0, -1)) { if (!(part in node)) return; node = node[part]; }
      delete node[parts[parts.length - 1]];
    },
    Cancel: () => { cancelled = true; }
  };
  context.process(event);
  if (cancelled || data['@metadata'].mall_validated !== true) return {cancelled: true};
  const names = request.fingerprint.fields.slice().sort();
  const values = names.map(name => get(data, name));
  if (values.some(v => typeof v !== 'string')) return {cancelled: true};
  const input = '|' + names.map((name, i) => name + '|' + values[i]).join('|') + '|';
  const id = crypto.createHash('sha256').update(input).digest('hex');
  const selected = {'@timestamp': data['@timestamp']};
  for (const path of request.includes) {
    const value = get(data, path);
    if (value !== undefined) put(selected, path, value);
  }
  return {cancelled: false, id, op_type: data['@metadata'].op_type, source: selected};
});
process.stdout.write(JSON.stringify(results));
"""


@pytest.fixture(scope="module")
def collector(tmp_path_factory):
    harness = tmp_path_factory.mktemp("mall-js") / "harness.cjs"
    harness.write_text(HARNESS, encoding="utf-8")
    node = os.environ.get("MALL_TEST_NODE") or shutil.which("node")
    if not node:
        pytest.fail("Existing Node runtime required to test collector JS; no native test was performed")

    def run(lines, *, params=None):
        request = {
            "script": str(ROOT / "filebeat/security-mall/security-mall-audit.js"),
            "params": params or PARAMS, "fingerprint": FINGERPRINT, "includes": INCLUDES,
            "lines": [item if isinstance(item, dict) and "line" in item else {"line": item} for item in lines],
        }
        completed = subprocess.run([node, str(harness)], input=json.dumps(request), text=True,
                                   capture_output=True, timeout=10, check=True)
        assert not completed.stderr
        return json.loads(completed.stdout)
    return run


def line(audit):
    return json.dumps(audit, separators=(",", ":"))


def complete_lines(path):
    """Model filestream's LF framing; retained partial EOF bytes are not published."""
    data = gzip.decompress(path.read_bytes()) if path.suffix == ".gz" else path.read_bytes()
    return [raw.rstrip(b"\r\n").decode("utf-8") for raw in data.splitlines(keepends=True) if raw.endswith(b"\n")]


def receive(event, *, received_at=RECEIVED):
    """ES final-pipeline reference model, not execution/compilation of Painless."""
    body = deepcopy(event["source"])
    assert not event["cancelled"] and event["op_type"] == "create"
    assert body["organization"] == {"id": PARAMS["organization_id"]}
    assert body["host"] == {"id": PARAMS["host_id"]}
    assert body["labels"] == {"log_source": "security_mall_audit"}
    assert set(body) <= {"@timestamp", "organization", "host", "labels", "security_mall", "event"}
    assert set(body["security_mall"]) == {"audit"}
    audit = body["security_mall"]["audit"]
    assert set(audit) <= set(COMMON_FIELDS + AUTHORIZATION_FIELDS + OPTIONAL_FIELDS)
    parse(audit)
    body["@timestamp"] = audit["@timestamp"]
    assert body["@timestamp"] == audit["@timestamp"]
    body["event"] = {"ingested": received_at}
    return body


def stores():
    documents = {}
    client = Mock()

    def bulk(*, operations):
        results = []
        for metadata, document in zip(operations[::2], operations[1::2], strict=True):
            assert set(metadata) == {"create"}
            key = (metadata["create"]["_index"], metadata["create"]["_id"])
            if key in documents:
                results.append({"create": {"status": 409, "error": {"type": "version_conflict_engine_exception"}}})
            else:
                documents[key] = deepcopy(document)
                results.append({"create": {"status": 201}})
        return {"items": results}

    client.bulk.side_effect = bulk
    return client, documents


def publish(events, client, *, received_at=RECEIVED):
    for event in events:
        if not event["cancelled"]:
            create_batch(client, [(INDEX, event["id"], receive(event, received_at=received_at))])


def normalize_stored(client, documents):
    for (index, identifier), source in list(documents.items()):
        if index == INDEX:
            ident, record, result = normalize({"_index": index, "_id": identifier, "_source": source}, PROCESSED)
            assert record["status"] == "normalized"
            assert result["cloud_soc"]["provenance"]["raw"] == {"index": INDEX, "id": identifier}
            create_batch(client, [(NORMALIZED, ident, result), (RECORDS, ident, record)])


def test_synthetic_jsonl_login_success_failure_and_order_denial_end_to_end(collector, tmp_path):
    audits = [payload(), payload(outcome="failure"), payload("order_view", "failure", reason="not_owner")]
    for number, audit in enumerate(audits, 1):
        audit["event_id"] = f"784a9b30-4a77-43a8-b698-cb67f95269f{number}"
    source = tmp_path / "security-audit.jsonl"
    source.write_text("\n".join(map(line, audits)) + "\n", encoding="utf-8")
    events = collector(complete_lines(source))
    client, documents = stores()
    publish(events, client)
    normalize_stored(client, documents)
    raw = {key: body for key, body in documents.items() if key[0] == INDEX}
    normalized = [body for (index, _identifier), body in documents.items() if index == NORMALIZED]
    assert len(raw) == len(normalized) == 3
    assert {body["event"]["id"] for body in normalized} == {a["event_id"] for a in audits}
    assert [body["event"]["category"] for body in normalized] == [["authentication"], ["authentication"], ["iam"]]
    assert [body["event"]["outcome"] for body in normalized] == ["success", "failure", "failure"]
    assert normalized[-1]["cloud_soc"]["security_mall"]["authorization_reason"] == "not_owner"
    assert all(body["event"]["ingested"] == RECEIVED for body in raw.values())
    assert all(body["@timestamp"] == STAMP for body in raw.values())


def test_documented_access_variants_reuse_unchanged_3a_parser(collector):
    audits = [payload(action, outcome, reason=reason) for action in ADMIN_RESOURCES
              for outcome, reason in [("success", "admin"), ("failure", "admin_required")]]
    audits += [payload("order_view", "success", reason="owner"),
               payload("order_view", "failure", reason="unauthenticated", anonymous=True)]
    events = collector(list(map(line, audits)))
    assert all(not event["cancelled"] for event in events)
    for event, audit in zip(events, audits, strict=True):
        assert event["source"]["security_mall"]["audit"] == audit
        result = normalize({"_index": INDEX, "_id": event["id"], "_source": receive(event)}, PROCESSED)[2]
        assert result["cloud_soc"]["security_mall"]["account_key_id"] == "v1"
    assert receive(events[-1])["security_mall"]["audit"]["account_id"] is None


def test_replay_and_conflicting_same_id_never_rewrite_raw_or_normalized(collector):
    first = payload()
    conflicting = payload(outcome="failure")
    events = collector([line(first), line(first), line(conflicting)])
    assert len({event["id"] for event in events}) == 1
    client, documents = stores()
    publish(events[:1], client)
    normalize_stored(client, documents)
    before = deepcopy(documents)
    publish(events[1:], client, received_at="2026-10-17T05:10:00Z")
    normalize_stored(client, documents)
    assert documents == before
    assert len(documents) == 3


def test_identity_scopes_org_host_service_and_uuid_but_not_read_time_path_or_key_version(collector):
    original = payload()
    first = collector([line(original)])[0]
    names = sorted(FINGERPRINT["fields"])
    native_input = "|" + "|".join(name + "|" + field(first["source"], name) for name in names) + "|"
    assert first["id"] == hashlib.sha256(native_input.encode()).hexdigest()
    scoped = []
    for field_name in ("organization_id", "host_id"):
        params = {**PARAMS, field_name: "other-scope"}
        scoped.append(collector([line(original)], params=params)[0]["id"])
    for key, value in (("service_name", "other-service"), ("event_id", "784a9b30-4a77-43a8-b698-cb67f95269f2")):
        scoped.append(collector([line({**original, key: value})])[0]["id"])
    assert len({first["id"], *scoped}) == 5
    assert collector([line({**original, "account_key_id": "v2"})])[0]["id"] == first["id"]


def test_newline_framing_never_publishes_unfinished_json_or_complete_json_without_lf(collector, tmp_path):
    source = tmp_path / "security-audit.jsonl"
    complete = line(payload()).encode()
    source.write_bytes(complete[:30])
    assert complete_lines(source) == []
    source.write_bytes(complete)
    assert complete_lines(source) == []
    source.write_bytes(complete + b"\n")
    assert not collector(complete_lines(source))[0]["cancelled"]
    source.write_bytes(complete[:30] + b"\n")
    assert collector(complete_lines(source)) == [{"cancelled": True}]


def test_restart_and_gzip_rotation_reread_is_idempotent_and_new_event_survives(collector, tmp_path):
    active = tmp_path / "security-audit.jsonl"
    initial = line(payload()).encode() + b"\n"
    active.write_bytes(initial)
    client, documents = stores()
    publish(collector(complete_lines(active)), client)
    archive = tmp_path / "security-audit.jsonl.2026-10-16.0.gz"
    archive.write_bytes(gzip.compress(initial))
    new = {**payload(), "event_id": "784a9b30-4a77-43a8-b698-cb67f95269f2"}
    active.write_text(line(new) + "\n", encoding="utf-8")
    publish(collector(complete_lines(archive) + complete_lines(active)), client)
    normalize_stored(client, documents)
    assert sum(index == INDEX for index, _identifier in documents) == 2
    assert sum(index == NORMALIZED for index, _identifier in documents) == 2


@pytest.mark.parametrize("extra", ["password", "cookie", "session_id", "Authorization", "hmac_key",
                                    "buyerName", "event.original", "organization", "host", "event.ingested"])
def test_unsupported_or_sensitive_fields_are_rejected_before_queue_or_transmission(collector, extra):
    value = {**payload(), extra: CANARY}
    result = collector([line(value)])
    assert result == [{"cancelled": True}]
    assert CANARY not in json.dumps(result)


def test_malformed_duplicate_escaped_duplicate_and_unsupported_schema_are_rejected(collector):
    valid = line(payload())
    bad = ["", "{", "[]", "null", "NaN", valid + valid, " " * 8193,
           valid[:-1] + ',"schema_version":1}',
           valid[:-1] + ',"schema_versi\\u006fn":1}',
           valid.replace('"schema_version":1', '"schema_version":true'),
           valid.replace('"schema_version":1', '"schema_version":1.0'),
           valid.replace('"schema_version":1', '"schema_version":1e0'),
           valid.replace('"schema_version":1', '"schema_version":2'),
           valid.replace('"schema_version":1', '"schema_version":NaN'),
           line({**payload(), "@timestamp": "2026-02-30T05:00:00Z"}),
           line({**payload(), "@timestamp": "2026-10-16T05:00:00"}),
           line({**payload(), "event_id": "not-a-uuid"}), line({**payload(), "event_action": "admin_login"}),
           line({**payload(), "account_id": CANARY}), line({**payload(), "account_id": None}),
           line(payload("order_view", "success", reason="not_owner")),
           line({**payload(), "service_name": "AKIA" + "A" * 16}),
           line({**payload(), "source_ip": "192.0.2.25%forwarded"}),
           line({**payload(), "source_ip": "1:2:3:4:5:6:7:8::"})]
    assert collector(bad) == [{"cancelled": True}] * len(bad)


@pytest.mark.parametrize("ip", ["127.0.0.1", "192.0.2.25", "2001:db8::25", "::1", "::", "::ffff:192.0.2.25"])
def test_valid_peer_ip_parity(collector, ip):
    event = collector([line({**payload(), "source_ip": ip})])[0]
    assert not event["cancelled"]
    assert parse(event["source"]["security_mall"]["audit"])["source_ip"]


def test_escaped_scalar_json_is_accepted_without_duplicate_bypass(collector):
    escaped = line(payload()).replace('"service_name"', '"service_\\u006eame"')
    assert not collector([escaped])[0]["cancelled"]


def test_processor_failure_is_fail_closed_without_leaking_raw_errors(collector):
    result = collector([{"line": line(payload()), "fail_on": name}
                        for name in ("security_mall", "organization", "host", "labels", "@metadata.mall_validated")])
    assert result == [{"cancelled": True}] * 5
    assert "PRIVATE_ERROR" not in json.dumps(result)


def test_final_receipt_is_central_and_not_the_app_or_filebeat_clock(collector):
    event = collector([line(payload())])[0]
    assert event["source"]["@timestamp"] != STAMP
    assert "event" not in event["source"]
    event["source"]["event"] = {"ingested": "1900-01-01T00:00:00Z"}
    stored = receive(event)
    assert stored["@timestamp"] == stored["security_mall"]["audit"]["@timestamp"] == STAMP
    assert stored["event"]["ingested"] == RECEIVED
    stamp = PIPELINE["processors"][-1]["set"]
    assert stamp == {"field": "event.ingested", "value": "{{{_ingest.timestamp}}}", "override": True}
    assert "ctx.event = new HashMap()" in PIPELINE["processors"][0]["script"]["source"]


def test_isolated_config_has_exact_allowlists_fail_closed_guards_final_pipeline_and_create_only_role():
    stream = CONFIG["filebeat.inputs"][0]
    assert stream["type"] == "filestream" and "parsers" not in stream
    assert stream["compression"] == "auto" and stream["message_max_bytes"] > 8192
    assert stream["prospector.scanner.fingerprint.length"] == 64
    assert len(stream["paths"]) == 2 and stream["paths"][1].endswith("}.*")
    assert "MALL_TEST_DATA_PATH" in CONFIG["path.data"]
    assert {"method": FINGERPRINT["method"], "target": FINGERPRINT["target_field"],
            "ignore": FINGERPRINT["ignore_missing"]} == {"method": "sha256", "target": "@metadata._id", "ignore": False}
    assert set(INCLUDES) == {"organization.id", "host.id", "labels.log_source", *SOURCE_FIELDS}
    assert PROCESSORS[0]["add_fields"]["fields"] == {"mall_validated": False, "op_type": "create"}
    assert PROCESSORS[2]["drop_event"]["when"]["not"]["equals"] == {"@metadata.mall_validated": True}
    assert PROCESSORS[4]["drop_event"]["when"]["not"]["has_fields"] == ["@metadata._id"]
    assert CONFIG["setup.template.enabled"] is False and CONFIG["setup.ilm.enabled"] is False
    assert CONFIG["output.elasticsearch"]["ssl.verification_mode"] == "full"
    assert TEMPLATE["index_patterns"] == ["soc-host-raw-mall-isolated-*"]
    assert TEMPLATE["template"]["settings"]["index.final_pipeline"] == "security-mall-isolated-final-v1"
    mappings = TEMPLATE["template"]["mappings"]
    assert mappings["dynamic"] == "strict"
    assert set(mappings["properties"]) == {"@timestamp", "organization", "host", "labels", "event", "security_mall"}
    audit = mappings["properties"]["security_mall"]["properties"]["audit"]["properties"]
    assert set(audit) == set(COMMON_FIELDS + AUTHORIZATION_FIELDS)
    assert "null_value" not in audit["account_id"]
    assert PIPELINE["processors"][0]["script"]["params"] == PARAMS
    assert PIPELINE["on_failure"] == [{"fail": {"message": "security_mall_intake_invalid"}}]
    json.dumps(PIPELINE)  # YAML asset can be converted to an ES API JSON body.
    role = json.loads((ROOT / "deploy/security-mall/writer-role.example.json").read_text(encoding="utf-8"))
    assert role["cluster"] == ["monitor"]
    assert role["indices"][0]["names"] == ["soc-host-raw-mall-isolated-example"]
    assert not any("*" in name for name in role["indices"][0]["names"])
    assert role["indices"][0]["privileges"] == ["create_doc"]
