import pytest

from cloud_soc.detection.profiles import catalog
from cloud_soc.detection.telemetry import evaluate
from cloud_soc.processing.contract import normalize
from test_site_agents import web_hit


RULES = {rule["id"]: rule for rule in catalog()}


def test_legacy_web_service_name_reaches_rule_evaluation():
    hit = web_hit()
    stamp = "2026-10-14T00:00:03Z"
    identifier, _, event = normalize(hit, stamp)
    rule = RULES["UNIFIED-APP-MIN3-001"]
    assert evaluate(event, rule) == ("matched", [])

    hit["_source"]["service"].pop("name")
    _, record, _ = normalize(hit, stamp)
    assert record["status"] == "unsupported"

    hit["_source"]["service"]["name"] = "[REDACTED]"
    redacted_id, _, redacted = normalize(hit, stamp)
    assert redacted_id == identifier
    assert evaluate(redacted, rule) == ("unknown", ["service.name"])


@pytest.mark.parametrize(
    ("rule_id", "adapter", "metadata"),
    [
        ("ATTACK-02", "linux_journal_audit_v1", {}),
        ("ATTACK-03", "windows_security_v1", {}),
        ("AUTH-SEQ-001", "windows_security_v1", {"category": ["authentication"], "outcome": "failure"}),
        ("WEB-404-001", "linux_operational_v1", {"action": "service_started"}),
        ("UNIFIED-APP-MIN3-001", "linux_operational_v1", {"action": "service_started"}),
        ("UNIFIED-WEB-HOST-001", "linux_operational_v1", {"action": "service_started"}),
        ("UNIFIED-NET-MIN3-001", "packetbeat_metadata_v1", {"category": ["network"], "dataset": "dns"}),
        ("UNIFIED-HOST-NET-001", "packetbeat_metadata_v1", {"category": ["network"], "dataset": "tls"}),
        ("UNIFIED-THREE-SOURCE-001", "packetbeat_metadata_v1", {"category": ["network"], "dataset": "tls"}),
    ],
)
def test_known_out_of_scope_source_is_not_an_evaluation_gap(rule_id, adapter, metadata):
    event = {"event": metadata, "cloud_soc": {"detail": {"adapter": adapter}}}
    assert evaluate(event, RULES[rule_id]) == ("not_matched", [])


@pytest.mark.parametrize(
    ("rule_id", "adapter", "metadata", "missing"),
    [
        ("ATTACK-02", "aws_cloudtrail_metadata_v1", {}, "event.dataset"),
        ("ATTACK-02", ["linux_journal_audit_v1"], {}, "event.dataset"),
        ("WEB-404-001", "linux_operational_v1", {"action": "http_access"}, "cloud_soc.detail.fields.http_status"),
        ("WEB-404-001", "linux_operational_v1", {}, "cloud_soc.detail.fields.http_status"),
        ("UNIFIED-NET-MIN3-001", "packetbeat_metadata_v1", {"category": ["network"], "dataset": "flow"},
         "cloud_soc.detail.fields.flow_final"),
        ("AUTH-SEQ-001", "linux_ssh_v2", {"category": ["authentication"], "outcome": "failure"}, "network.protocol"),
    ],
)
def test_missing_selector_for_potential_match_remains_an_evaluation_gap(rule_id, adapter, metadata, missing):
    event = {"event": metadata, "cloud_soc": {"detail": {"adapter": adapter}}}
    outcome, fields = evaluate(event, RULES[rule_id])
    assert outcome == "unknown"
    assert missing in fields
