"""9-B isolated synthetic metadata only; no ES, VM or attack HTTP requests."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from elasticsearch import ConflictError

from cloud_soc.detection.engine import detect_events, detect_rule, event_fingerprint
from cloud_soc.detection.profiles import source_observed
from cloud_soc.detection.rule_loader import validate_rule
from cloud_soc.detection.telemetry import evaluate
from cloud_soc.detection.waf import SQLI_IDS
from cloud_soc.detection.worker import approved_rules
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.elastic.repository import save_security_alert
from cloud_soc.parsers.security_mall_edge import envelope
from cloud_soc.processing.contract import normalize
from cloud_soc.portal.app import create_app
from test_integration_security import login
from test_security_mall_portal import fake_es
from test_source_access import HASH

BASE = datetime(2026, 10, 17, tzinfo=timezone.utc)
SCOPE = {'alerts': 'soc-mall-alerts-lab-live-waf-fixture',
         'normalized': 'soc-normalized-mall-waf-fixture', 'raw': 'soc-host-raw-mall-edge-waf-fixture'}
ROOT = Path(__file__).resolve().parents[1]


def rule():
    return approved_rules(additional_rule_ids=['WEB-WAF-01'])[0]


def waf(n=1, *, seconds=0, org='waf-org', host='waf-host', ip='127.0.0.1', ids=('942100',)):
    body = {'schema_version': 1, 'stream': 'waf', 'timestamp': (BASE + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z'),
            'request_id': f'{n:027d}', 'service_name': 'security-mall', 'source_ip': ip,
            'rules': [{'id': i, 'action': 'block', 'diagnostic': i == '10002'} for i in ids],
            'engine_mode': 'DetectionOnly', 'blocked': False}
    source = envelope(body, org, host)
    source['event']['ingested'] = (BASE + timedelta(seconds=seconds + 1)).isoformat().replace('+00:00', 'Z')
    hit = {'_index': SCOPE['raw'], '_id': source['event']['id'], '_source': source}
    nid, record, event = normalize(hit, (BASE + timedelta(seconds=seconds + 2)).isoformat())
    assert record['status'] == 'normalized'
    event['_cloud_soc_meta'] = {'index': SCOPE['normalized'], 'document_id': nid}
    return source, event


@pytest.mark.parametrize('crs_id', sorted(SQLI_IDS))
def test_allowed_sqli_ids_and_existing_evidence_and_risk(crs_id):
    _, event = waf(ids=(crs_id,))
    original = deepcopy(event)
    detection, = detect_events([event], [rule()])
    alert = build_security_alert(detection)
    assert detection['assessment']['matched_rule_ids'] == [crs_id]
    assert detection['assessment']['pattern'] == 'single_suspected_request'
    assert detection['assessment']['blocked'] is False
    assert detection['assessment']['declared_actions'] == ['block']
    assert detection['assessment']['event_ids'] == [event['event']['id']]
    evidence, = alert['cloud_soc']['provenance']['evidence']
    assert evidence['event_hash'] == event_fingerprint(event)
    assert evidence['raw'] == event['cloud_soc']['provenance']['raw']
    assert evidence['normalized']['id'] == event['_cloud_soc_meta']['document_id']
    assert alert['cloud_soc']['risk_score'] == 45 and alert['cloud_soc']['severity'] == 'medium'
    assert event == original


@pytest.mark.parametrize('crs_id', ['10002', '901001', '920350', '942011', '942999'])
def test_diagnostic_unrelated_control_and_unlisted_rules_excluded(crs_id):
    event = waf(ids=(crs_id,))[1]
    assert not detect_events([event], [rule()])
    assert evaluate(event, rule())[0] == 'not_matched'


def test_request_dedup_and_repetition_and_reorder_and_stable_ids():
    events = [waf(n, seconds=n * 10, ids=('942100', '942140'))[1] for n in range(1, 4)]
    duplicate = deepcopy(events[0])
    duplicate['_cloud_soc_meta']['document_id'] = 'another-normalization'
    found = detect_events([*reversed(events), duplicate, *events], [rule()])
    assert [d['event_count'] for d in found] == [1, 2, 3]
    assert [d['assessment']['pattern'] for d in found] == [
        'single_suspected_request', 'multiple_suspected_requests', 'repeated_suspected_requests']
    assert found[-1]['assessment']['request_count'] == 3
    assert len(found[-1]['evidence']) == 3
    assert len(set(found[-1]['assessment']['request_ids'])) == 3
    assert build_security_alert(found[-1])['cloud_soc']['risk_score'] == 55  # Existing formula; no custom boost.
    assert [make_alert_id(d) for d in found] == [make_alert_id(d) for d in detect_events(events, [rule()])]


def test_runtime_checkpoint_replay_and_window_expiry():
    events = [waf(n, seconds=n * 10)[1] for n in range(1, 4)]
    state = {}
    first = detect_rule(events[:2], rule(), runtime=state)
    restored = json.loads(json.dumps(state))
    last, = detect_rule(events, rule(), runtime=restored)
    assert len(first) == 2 and last['event_count'] == 3
    assert not detect_rule(events, rule(), runtime=restored)
    old_id = waf(1, seconds=400)[1]
    new, = detect_rule([old_id], rule(), runtime=restored)
    assert new['event_count'] == 1 and make_alert_id(new) != make_alert_id(first[0])


def test_closed_window_and_unrelated_matches_do_not_inflate_requests():
    rows = [waf(1)[1], waf(2, seconds=150)[1], waf(3, seconds=300, ids=('942100', '10002', '920350'))[1]]
    last = detect_events(rows, [rule()])[-1]
    assert last['assessment']['request_count'] == 3
    assert last['assessment']['matched_rule_ids'] == ['942100']
    rows[-1] = waf(3, seconds=301)[1]
    last = detect_events(rows, [rule()])[-1]
    assert last['assessment']['request_count'] == 2
    assert last['assessment']['pattern'] == 'multiple_suspected_requests'


def test_reprocessing_uses_existing_immutable_alert_store():
    event = waf()[1]
    first = detect_events([event], [rule()])[0]
    revised = deepcopy(event); revised['_cloud_soc_meta']['document_id'] += '-revision'
    second = detect_events([revised], [rule()])[0]
    assert make_alert_id(first) == make_alert_id(second)
    client = Mock()
    client.create.side_effect = [{'result': 'created'}, ConflictError('duplicate', None, {})]
    before = build_security_alert(first)
    opts = {'index_name': SCOPE['alerts'], 'document_id': make_alert_id(first), 'index_prepared': True}
    assert save_security_alert(client, before, **opts)['result'] == 'created'
    assert save_security_alert(client, build_security_alert(second), **opts)['result'] == 'existing'
    client.index.assert_not_called()
    client.update.assert_not_called()
    assert before['cloud_soc']['provenance']['evidence'][0]['event_hash'] == event_fingerprint(event)


def test_existing_incremental_worker_checkpoint_and_replay(tmp_path):
    from cloud_soc.detection.incremental import run_incremental
    from cloud_soc.processing.contract import NORMALIZED
    from test_early_notices import Fixture
    hits = []
    for n in range(1, 4):
        event = waf(n, seconds=n * 10)[1]
        meta = event.pop('_cloud_soc_meta')
        hits.append({'_index': NORMALIZED, '_id': meta['document_id'], '_source': event})
    fixture = Fixture(hits)
    path = tmp_path / 'waf-runtime.sqlite'
    options = dict(state_path=path, start=BASE, lateness_seconds=60,
                   scanner=fixture.scan, additional_rule_ids=['WEB-WAF-01'])
    assert run_incremental(fixture.client, now=BASE + timedelta(seconds=140), **options)['created'] == 3
    before = deepcopy(fixture.docs)
    assert run_incremental(fixture.client, now=BASE + timedelta(seconds=200), **options)['created'] == 0
    alerts = [value for (index, _), value in fixture.docs.items() if index == 'security-alerts']
    assert len(alerts) == 3
    assert sorted(a['cloud_soc']['provenance']['assessment']['request_count'] for a in alerts) == [1, 2, 3]
    assert all(fixture.docs[key] == value for key, value in before.items() if key[0] == 'security-alerts')
    assert path.exists()


@pytest.mark.parametrize('dimension', ['org', 'host', 'ip'])
def test_no_cross_scope_repetition(dimension):
    rows = [waf(n, seconds=n, **{dimension: value})[1] for n, value in enumerate(
        (['org-a', 'org-b', 'org-c'] if dimension == 'org' else ['host-a', 'host-b', 'host-c']
         if dimension == 'host' else ['192.0.2.1', '192.0.2.2', '192.0.2.3']), 1)]
    assert [d['event_count'] for d in detect_events(rows, [rule()])] == [1, 1, 1]
    changed = deepcopy(rows[0]); changed['service']['name'] = 'other-site'
    assert not detect_events([changed], [rule()])


@pytest.mark.parametrize('change', ['blocked', 'mode', 'request', 'raw_field', 'missing_provenance'])
def test_unsupported_mode_invalid_metadata_and_missing_evidence_fail_closed(change):
    event = waf()[1]
    body = event['cloud_soc']['security_mall_edge']
    if change == 'blocked':
        body['blocked'] = True
    elif change == 'mode':
        body['engine_mode'] = 'On'
    elif change == 'request':
        event['http']['request']['id'] = 'bad-client-value'
    elif change == 'raw_field':
        body['message'] = 'PRIVATE_CANARY'
    else:
        event.pop('_cloud_soc_meta')
        with pytest.raises(ValueError, match='complete evidence'):
            detect_events([event], [rule()])
        return
    assert not detect_events([event], [rule()])


def test_policy_validation_profile_and_no_secret_output():
    assert [r['id'] for r in approved_rules()] == ['AUTH-001']
    event = waf()[1]
    assert source_observed(event, 'WEB-WAF-01')
    assert not source_observed(event, 'WEB-ACCESS-01')
    event['message'] = 'PRIVATE_CANARY'
    alert = build_security_alert(detect_events([event], [rule()])[0])
    assert 'PRIVATE_CANARY' not in json.dumps(alert)
    for key, value in [('rule_ids', ['942011']), ('repeat_requests', True), ('crs_version', 'unknown')]:
        bad = rule(); bad['waf_sqli'][key] = value
        with pytest.raises(ValueError):
            validate_rule(bad)


@pytest.fixture
def portal(tmp_path):
    source, event = waf()
    detection, = detect_events([event], [rule()])
    aid = make_alert_id(detection)
    norm = deepcopy(event); norm.pop('_cloud_soc_meta')
    store = {(SCOPE['raw'], source['event']['id']): source,
             (SCOPE['normalized'], event['_cloud_soc_meta']['document_id']): norm,
             (SCOPE['alerts'], aid): build_security_alert(detection)}
    users = {'admin': {'role': 'admin', 'password_hash': HASH},
             'view': {'role': 'viewer', 'password_hash': HASH}, 'other': {'role': 'viewer', 'password_hash': HASH}}
    policy = {'version': 1, 'protected_source_enabled': True, 'admin_source_organizations': ['waf-org'],
              'users': [{'username': n, 'password_hash': HASH, 'role': 'viewer', 'organizations': [org]}
                        for n, org in [('view', 'waf-org'), ('other', 'foreign')]]}
    filename = tmp_path / 'users.json'; filename.write_text(json.dumps(users)); filename.chmod(0o600)
    es = fake_es(store)
    app = create_app({'STATE_DIR': tmp_path, 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': b'SYNTHETIC CA',
                      'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://example.test:9200',
                      'ADMIN_USER': 'admin', 'ADMIN_HASH': HASH, 'USERS_FILE': str(filename),
                      'LOG_ACCESS_POLICY': policy, 'MALL_LAB_SCOPE': SCOPE}, issuer=Mock(), monitor=es)
    app.config['TESTING'] = True
    return app, es, store, aid, event


def test_portal_list_detail_assessment_evidence_and_source_policy(portal):
    app, es, store, aid, event = portal
    before = deepcopy(store)
    http, headers = login(app, 'view')
    result = http.get('/api/alerts/detail?id=' + aid + '&evidence=0')
    assert result.status_code == 200
    data = result.json
    assert data['alert']['rule'] == 'WEB-WAF-01' and data['alert']['service'] == 'security-mall'
    assert data['risk']['score'] == 45 and data['assessment']['blocked'] is False
    assert data['assessment']['request_count'] == 1
    assert data['evidence']['integrity'] == 'normalized_hash_verified'
    assert data['evidence']['security']['fields']['rules'][0]['id'] == '942100'
    assert data['evidence']['normalized_event']['id'] == event['event']['id']
    raw_id = event['cloud_soc']['provenance']['raw']['id']
    assert http.get('/api/logs/detail?index=' + SCOPE['raw'] + '&id=' + raw_id).status_code == 200
    assert http.post('/api/logs/source', json={'index': SCOPE['raw'], 'id': raw_id,
                     'purpose': 'investigation'}, headers=headers).status_code == 403
    section = http.get('/api/operations?start=2026-10-16T00:00:00Z&end=2026-10-18T00:00:00Z').json['sections']
    assert section['security_mall']['count'] == 1
    assert section['alerts']['rows'][0]['rule'] == 'WEB-WAF-01'
    assert store == before
    es.create.assert_not_called()


def test_portal_foreign_org_and_index_override_blocked(portal):
    app, _, _, aid, event = portal
    http, _ = login(app, 'other')
    assert http.get('/api/alerts/detail?id=' + aid).status_code == 404
    assert http.get('/api/alerts/detail?id=' + aid).json == http.get('/api/alerts/detail?id=missing').json
    raw_id = event['cloud_soc']['provenance']['raw']['id']
    assert http.get('/api/logs/detail?index=' + SCOPE['raw'] + '&id=' + raw_id).status_code == 404
    http, _ = login(app, 'view')
    for query in ('&organization=foreign', '&index=security-alerts'):
        assert http.get('/api/alerts/detail?id=' + aid + query).status_code == 400


@pytest.mark.parametrize('target', ['normalized', 'raw'])
def test_portal_tampered_evidence_blocked(portal, target):
    app, _, store, aid, _ = portal
    reference = store[SCOPE['alerts'], aid]['cloud_soc']['provenance']['evidence'][0][target]
    source = store[reference['index'], reference['id']]
    if target == 'normalized':
        source['event']['outcome'] = 'success'
    else:
        source['security_mall_edge']['rules'][0]['id'] = '920350'
    http, _ = login(app, 'view')
    evidence = http.get('/api/alerts/detail?id=' + aid + '&evidence=0').json['evidence']
    assert evidence['state'] in ('normalized_hash_mismatch', 'provenance_mismatch')
    assert 'security' not in evidence
