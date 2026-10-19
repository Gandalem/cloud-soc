"""All fourteen real engines, immutable evidence and safe profile selection."""
from copy import deepcopy
from datetime import timedelta
import io
import json
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from cloud_soc.detection.__main__ import main
from cloud_soc.detection.engine import detect_events, detect_rule, event_fingerprint, rule_revision
from cloud_soc.detection.profiles import RULE_IDS as CATALOG_IDS, catalog, assessment, source_observed
from cloud_soc.detection.telemetry import evaluate, stats_for, run_records
from cloud_soc.detection.worker import approved_rules
from cloud_soc.detection.rule_loader import validate_rule
from cloud_soc.main import make_alert_id, build_security_alert
from ruleset_fixtures import positive, delete, assign, second_burst, BASE

# These legacy fixtures mutate threshold timestamps/outcomes in isolation.
# Edge-v1 requires matching envelope/identity fields; WEB-WAF-01's real-adapter
# cases are covered by test_security_mall_waf_detection.py instead.
RULE_IDS = tuple(key for key in CATALOG_IDS if key != 'WEB-WAF-01')
RULES = {rule['id']: rule for rule in approved_rules(isolated_all=True)}


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_threshold_positive_before_boundary_exact_evidence_and_privacy(identifier):
    rule = RULES[identifier]
    rows = positive(identifier)
    before = event_fingerprint(rows)
    assert detect_rule(rows[:-1], rule) == []
    matches = detect_rule(rows, rule)
    assert len(matches) == 1
    match = matches[0]
    assert match['rule_id'] == identifier and match['evidence_status'] == 'complete'
    assert match['severity'] in ('low', 'medium', 'high', 'critical')
    assert len(match['evidence']) == len(rows)
    assert {event_fingerprint(e['raw']) for e in match['evidence']} == {
        event_fingerprint(row['cloud_soc']['provenance']['raw']) for row in rows}
    alert = build_security_alert(match)
    assert alert['@timestamp'] == match['window_end']
    assert 0 <= alert['cloud_soc']['risk_score'] <= 100
    assert alert['cloud_soc']['provenance']['rule_snapshot']['id'] == identifier
    assert alert['message'] and alert['rule']['name']
    assert 'CANARY_WEB_NEVER_TRANSMIT' not in json.dumps(alert)
    assert event_fingerprint(rows) == before
    assert make_alert_id(detect_rule(list(reversed(rows)), rule)[0]) == make_alert_id(match)


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_normal_outcome_wrong_source_and_organization_do_not_become_attacks(identifier):
    rule = RULES[identifier]
    rows = positive(identifier)
    for row in rows:
        assign(row, rule['conditions'][0]['field'], 'unrelated-source')
    assert detect_rule(rows, rule) == []
    rows = positive(identifier)
    if rule.get('type') == 'single':
        rows[0]['event']['outcome'] = 'success' if identifier == 'WEB-ACCESS-01' else 'failure'
    elif identifier == 'NET-PORT-001':
        assign(rows[-1], 'cloud_soc.detail.fields.flow_final', False)
    elif identifier == 'WEB-404-001':
        assign(rows[-1], 'cloud_soc.detail.fields.http_status', 200)
    elif identifier == 'WEB-SITE-404-001':
        assign(rows[-1], 'http.response.status_code', 200)
    elif identifier == 'WEB-SITE-WAF-001':
        assign(rows[-1], 'cloud_soc.detail.fields.sqli', False)
    elif identifier in ('ATTACK-02',):
        rows[-1]['event']['action'] = 'DescribeMadeUp'
    elif identifier == 'ATTACK-03':
        rows[-1]['event']['outcome'] = 'failure'
    elif identifier == 'ATTACK-01':
        assign(rows[-1], 'cloud_soc.detail.fields.target_user', 'ordinary-user')
    else:
        rows[-1]['event']['outcome'] = 'success' if identifier not in ('AUTH-SEQ-001', 'WEB-AUTH-01', 'ATTACK-01') else 'failure'
    assert detect_rule(rows, rule) == []
    rows = positive(identifier)
    rows[-1]['organization']['id'] = 'other-organization'
    if rule.get('type') != 'single':
        assert detect_rule(rows, rule) == []
    else:
        assert detect_rule(rows, rule)[0]['organization_id'] == 'other-organization'


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_missing_fields_are_unknown_not_negative_safety_claim(identifier):
    rule = RULES[identifier]
    fields = set(rule['group_by']) | set(rule.get('required_fields', []))
    fields |= {condition['field'] for condition in rule['conditions'] if condition['operator'] != 'exists'}
    for field in fields:
        rows = positive(identifier)
        delete(rows[-1], field)
        outcome, missing = evaluate(rows[-1], rule)
        assert outcome == 'unknown' and field in missing, (identifier, field, outcome, missing)
        assert detect_events(rows, [rule]) == []
    metrics = stats_for([rule])
    assert assessment(metrics[identifier], 'committed')['state'] == 'unverified'
    metrics[identifier].update(source_events=1, unknown=1, excluded=1)
    record = list(run_records([rule], metrics, run_id='isolated', stamp=BASE.isoformat(),
                             start=BASE.isoformat(), end=BASE.isoformat(), state='committed'))[0][1]
    assert record['assessment']['state'] == 'not_evaluable'
    assert 'attack_absent' not in json.dumps(record)


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_time_window_closed_boundary_and_just_outside(identifier):
    rule = RULES[identifier]
    if rule.get('type') == 'single':
        # Single events have no aggregation interval or suppression of later events.
        assert len(detect_rule(positive(identifier) + second_burst(positive(identifier), 86400), rule)) == 2
        return
    for delta, expected in ((0, 1), (.001, 0)):
        rows = positive(identifier)
        for row in rows[:-1]:
            row['@timestamp'] = BASE.isoformat()
        if identifier == 'ATTACK-01':
            rows[-2]['@timestamp'] = (BASE + timedelta(seconds=300)).isoformat()
        boundary = rule['success_window']['seconds'] if identifier == 'WEB-AUTH-01' else rule['time_window']['seconds']
        rows[-1]['@timestamp'] = (BASE + timedelta(seconds=boundary + delta)).isoformat()
        assert len(detect_rule(rows, rule)) == expected, (identifier, delta)


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_duplicates_raw_revision_and_cooldown_across_runtime_serialization(identifier):
    rule = RULES[identifier]
    rows = positive(identifier)
    duplicate = deepcopy(rows[0])
    duplicate['_cloud_soc_meta']['document_id'] += '-revision'
    if rule.get('type') == 'single':
        assert len(detect_rule(rows + [duplicate] * 30, rule)) == 1
        return
    incomplete = rows[1:] + [deepcopy(rows[1])] * 30 if len(rows) > 2 else rows[:-1] * 30
    assert detect_rule(incomplete, rule) == []
    assert len(detect_rule(rows + [duplicate] * 30, rule)) == 1
    runtime = {}
    assert len(detect_rule(rows, rule, runtime=runtime)) == 1
    restored = json.loads(json.dumps(runtime))
    next_rows = second_burst(rows, 30)
    assert len(detect_rule(next_rows, rule, runtime=restored)) == (0 if rule['cooldown']['seconds'] else 1)
    restored = json.loads(json.dumps(restored))
    later = second_burst(rows, 2000)
    for row in later:
        row['cloud_soc']['provenance']['raw']['id'] += '-later'
        for field in ('event_id', 'flow_id'):
            if field in row['cloud_soc']['detail']['fields']:
                row['cloud_soc']['detail']['fields'][field] += '-later'
    assert len(detect_rule(later, rule, runtime=restored)) == 1


def test_complete_inventory_explicit_selection_cli_and_live_write_gate():
    assert tuple(RULES) == CATALOG_IDS
    assert len(catalog()) == 19
    assert [r['id'] for r in approved_rules()] == ['AUTH-001']
    assert [r['id'] for r in approved_rules(rule_ids=['AUTH-SEQ-001'])] == ['AUTH-001', 'AUTH-SEQ-001']
    assert rule_revision(approved_rules()[0]) == rule_revision(RULES['AUTH-001'])
    for options in ({'rule_ids': ['AWS-CONSOLE-001']}, {'rule_ids': ['invented']}, {'rule_ids': []},
                    {'rule_ids': ['AUTH-001', 'AUTH-001']}, {'isolated_all': True, 'include_cloud': True}):
        with pytest.raises(ValueError):
            approved_rules(**options)
    stream = io.StringIO()
    with redirect_stdout(stream):
        assert main(['--isolated-all']) == 0
    assert all(identifier in stream.getvalue() for identifier in RULE_IDS)
    with patch('cloud_soc.detection.__main__.Elasticsearch') as connection:
        for url in ('https://192.168.32.60:9200', 'https://example.test', 'http://127.0.0.1:9200'):
            with redirect_stdout(io.StringIO()):
                assert main(['--isolated-all', '--run', '--state', 'isolated.sqlite', '--start', BASE.isoformat(), '--es-url', url]) == 1
        with redirect_stdout(io.StringIO()):
            assert main(['--isolated-all', '--run', '--state', './state/detection/runtime.sqlite',
                         '--start', BASE.isoformat(), '--es-url', 'https://127.0.0.1:9200']) == 1
        connection.assert_not_called()
    from cloud_soc.runtime_audit import command_options
    assert command_options(['--isolated-all']) == {'--isolated-all': True}


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_source_presence_is_independent_of_attack_outcome_and_invalid_bounds(identifier):
    rule = RULES[identifier]
    assert source_observed(positive(identifier)[0], identifier)
    for name in ('threshold', 'time_window', 'cooldown'):
        malformed = deepcopy(rule)
        malformed[name][next(iter(malformed[name]))] = True
        with pytest.raises(ValueError):
            validate_rule(malformed)


@pytest.mark.parametrize('identifier', ['AUTH-SEQ-001', 'ATTACK-01'])
def test_current_ubuntu_journal_and_iso_mirrors_do_not_inflate_sequence(identifier):
    from test_linux_ssh_live_formats import raw, event, BASE as ssh_base
    from test_attack_detection import sudo
    rule = RULES[identifier]
    for count, expected in ((4, 0), (5, 1)):
        rows = [event(raw(i, origin)) for i in range(count) for origin in ('journald', 'rfc3339')]
        rows.append(event(raw(10, outcome='success')))
        if identifier == 'ATTACK-01':
            terminal = sudo()
            terminal['host']['id'] = 'fixture-host'
            terminal['@timestamp'] = (ssh_base + timedelta(seconds=20)).isoformat()
            rows.append(terminal)
        matches = detect_rule(rows, rule)
        assert len(matches) == expected
        if matches:
            assert matches[0]['event_count'] == (6 if identifier == 'AUTH-SEQ-001' else 7)


def test_generic_site_web_404_uses_real_adapter_and_preserves_privacy():
    from test_site_agents import web_hit
    from cloud_soc.processing.contract import normalize, NORMALIZED
    rows = []
    for i in range(20):
        hit = web_hit()
        hit['_id'] = f'site-{i}'
        hit['_source']['http']['response']['status_code'] = 404
        key, record, row = normalize(hit, BASE.isoformat())
        assert record['status'] == 'normalized'
        row['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
        rows.append(row)
    assert len(detect_rule(rows, RULES['WEB-404-001'])) == 1
    assert source_observed(rows[0], 'WEB-404-001')


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_normal_activity_that_has_same_metadata_is_disclosed_not_proven_compromise(identifier):
    match = detect_rule(positive(identifier), RULES[identifier])[0]
    alert = build_security_alert(match)
    # Approved administration, password retries, crawlers and discovery may
    # satisfy these conditions. A triage score is never a probability/verdict.
    assert 'verdict' not in alert and 'attack_success' not in alert['cloud_soc']
    if 'assessment' in match:
        assert match['assessment']['attack_success'] == 'not_established'
        assert match['assessment']['limitations']
