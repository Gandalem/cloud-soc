"""Portal contract tests: isolated stores, server scope, and exact Mall evidence."""
from copy import deepcopy
from fnmatch import fnmatchcase
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from elasticsearch import NotFoundError

from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.worker import approved_rules
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.portal.app import create_app
from cloud_soc.portal.dashboard_widgets import REGISTRY, instance, valid_layout
from cloud_soc.portal.log_contract import field
from cloud_soc.portal.mall_scope import validate_scope
from cloud_soc.portal.operations import Operations
from security_mall_fixtures import mall
from test_integration_security import login
from test_source_access import HASH

SCOPE = {'alerts': 'soc-mall-alerts-lab-live-fixture', 'normalized': 'soc-normalized-mall-isolated-fixture',
         'raw': 'soc-host-raw-mall-isolated-fixture'}
SYNTHETIC = 'soc-mall-alerts-lab-synthetic-fixture'
RANGE = '?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z'
ROOT = Path(__file__).resolve().parents[1]


def dataset():
    store = {}
    rules = approved_rules(additional_rule_ids=['WEB-ACCESS-01', 'WEB-AUTH-01'])
    def save_events(events, rule, index):
        for e in events:
            f = e['cloud_soc']['detail']['fields']
            audit = {'schema_version': 1, '@timestamp': f['timestamp'], 'event_id': f['event_id'],
                     'service_name': f['service_name'], 'event_action': f['action'], 'event_outcome': f['outcome'],
                     'source_ip': f['source_ip'], 'account_id': f['account_id'], 'account_key_id': f['account_key_id']}
            for k in ('resource_type', 'authorization_reason'):
                if k in f:
                    audit[k] = f[k]
            e['cloud_soc']['provenance']['raw']['index'] = SCOPE['raw']
            e['_cloud_soc_meta']['index'] = SCOPE['normalized']
            rid = e['cloud_soc']['provenance']['raw']['id']
            store[(SCOPE['raw'], rid)] = {'@timestamp': f['timestamp'], 'event': {'ingested': e['event']['ingested']},
                'organization': deepcopy(e['organization']), 'host': deepcopy(e['host']),
                'labels': {'log_source': 'security_mall_audit'}, 'security_mall': {'audit': audit},
                'message': 'PRIVATE_CANARY', 'cookie': 'PRIVATE_CANARY', 'event.original': 'PRIVATE_CANARY'}
            norm = deepcopy(e)
            nid = norm.pop('_cloud_soc_meta')['document_id']
            store[(SCOPE['normalized'], nid)] = norm
        d = detect_events(events, [rule])[0]
        doc = build_security_alert(d)
        identifier = make_alert_id(d)
        store[(index, identifier)] = doc
        return identifier
    access = save_events([mall(1, action='order_view', organization='synthetic')], rules[0], SCOPE['alerts'])
    auth = save_events([mall(10 + i, seconds=i * 10, organization='synthetic') for i in range(5)] +
                       [mall(100, seconds=60, outcome='success', organization='synthetic')], rules[1], SYNTHETIC)
    return store, access, auth


def fake_es(store):
    es = Mock()
    es.options.return_value = es
    def names(index):
        return index.split(',') if isinstance(index, str) else list(index)
    def resolve(name, **_):
        values = sorted({i for i, _ in store if any(fnmatchcase(i, p) for p in names(name))})
        return {'indices': [{'name': i} for i in values]}
    def get(index, id, **_):
        if (index, id) not in store:
            raise NotFoundError('missing', None, {})
        return {'_index': index, '_id': id, '_source': deepcopy(store[index, id])}
    def selected(index, query):
        rows = []
        clauses = query.get('bool', {}).get('filter', [query])
        for (idx, identifier), source in store.items():
            if idx not in names(index):
                continue
            valid = True
            for clause in clauses:
                for path, values in clause.get('terms', {}).items():
                    valid &= field(source, path) in values
                for path, limits in clause.get('range', {}).items():
                    value = field(source, path)
                    valid &= isinstance(value, str) and limits['gte'] <= value < limits['lt']
            if valid:
                rows.append({'_index': idx, '_id': identifier, '_source': deepcopy(source)})
        return sorted(rows, key=lambda h: h['_source']['@timestamp'], reverse=True)
    def search(index, query, size=0, **_):
        rows = selected(index, query)
        return {'timed_out': False, '_shards': {'failed': 0},
                'hits': {'total': {'value': len(rows), 'relation': 'eq'}, 'hits': rows[:size]},
                'aggregations': {'trend': {'buckets': [{'key_as_string': '2026-10-01T00:00:00Z', 'doc_count': len(rows)}]}}}
    es.indices.resolve_index.side_effect = resolve
    es.get.side_effect = get
    es.search.side_effect = search
    es.count.side_effect = lambda index, query, **_: {'count': len(selected(index, query)), '_shards': {'failed': 0}}
    es.field_caps.return_value = {'fields': {'@timestamp': {'date': {}}, 'event.ingested': {'date': {}}}}
    return es


@pytest.fixture
def portal(tmp_path):
    store, access, auth = dataset()
    es = fake_es(store)
    policy = {'version': 1, 'protected_source_enabled': True, 'admin_source_organizations': ['synthetic'],
              'users': [{'username': n, 'password_hash': HASH, 'role': role, 'organizations': [org]}
                        for n, role, org in [('view', 'viewer', 'synthetic'), ('investigate', 'investigator', 'synthetic'),
                                             ('other', 'investigator', 'foreign')]]}
    users = {'admin': {'role': 'admin', 'password_hash': HASH},
             **{r['username']: {'role': 'viewer' if r['role'] == 'viewer' else 'analyst', 'password_hash': HASH}
                for r in policy['users']}}
    filename = tmp_path / 'users.json'
    filename.write_text(json.dumps(users))
    filename.chmod(0o600)
    settings = {'STATE_DIR': tmp_path, 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': b'SYNTHETIC CA',
                'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://example.test:9200', 'ADMIN_USER': 'admin',
                'ADMIN_HASH': HASH, 'USERS_FILE': str(filename), 'LOG_ACCESS_POLICY': policy, 'MALL_LAB_SCOPE': SCOPE}
    app = create_app(settings, issuer=Mock(), monitor=es)
    app.config['TESTING'] = True
    return app, es, store, access, auth


def test_live_list_count_service_risk_and_synthetic_exclusion(portal):
    app, es, store, access, auth = portal
    http, _ = login(app, 'view')
    before = deepcopy(store)
    for _ in range(2):
        data = http.get('/api/operations' + RANGE).json['sections']
        assert data['alerts']['count'] == data['security_mall']['count'] == 1
        row, = data['alerts']['rows']
        assert (row['id'], row['rule'], row['service'], row['status'], row['event_count']) == (access, 'WEB-ACCESS-01', 'security-mall', 'stored', 1)
        assert (row['severity'], row['risk_score'], row['risk_level']) == ('low', 20, 'low')
    assert store == before
    assert http.get('/api/alerts/detail?id=' + auth).status_code == 404
    assert all(call.kwargs['index'] in ([SCOPE['raw']], [SCOPE['alerts']]) for call in es.search.call_args_list)
    es.create.assert_not_called()


def test_detail_exact_evidence_and_no_secret_copy(portal):
    app, _, store, access, _ = portal
    http, _ = login(app, 'view')
    data = http.get('/api/alerts/detail?id=' + access + '&evidence=0').json
    assert data['alert']['reason']
    assert data['rule_snapshot']['id'] == 'WEB-ACCESS-01'
    e = data['evidence']
    assert e['integrity'] == 'normalized_hash_verified'
    assert e['normalized']['index'] == SCOPE['normalized'] and e['raw']['index'] == SCOPE['raw']
    assert e['security']['fields']['authorization_reason'] == 'not_owner'
    assert e['security']['fields']['account_id'] == 'a' * 64
    assert e['security']['fields']['account_key_id'] == 'lab-v1'
    assert e['http_status'] is None
    assert 'PRIVATE_CANARY' not in json.dumps(data)


def test_other_org_indistinguishable_missing_and_no_parameter_override(portal):
    app, es, _, access, _ = portal
    http, _ = login(app, 'other')
    assert http.get('/api/alerts/detail?id=' + access).json == http.get('/api/alerts/detail?id=missing').json
    assert http.get('/api/alerts/detail?id=' + access).status_code == 404
    assert http.get('/api/operations' + RANGE).json['sections']['alerts']['count'] == 0
    for suffix in ('&organization=synthetic', '&index=' + SCOPE['alerts'], '&include_synthetic=true'):
        assert http.get('/api/alerts/detail?id=' + access + suffix).status_code == 400
        assert http.get('/api/operations' + RANGE + suffix).status_code == 400


@pytest.mark.parametrize('target', ['normalized', 'raw'])
def test_cross_org_evidence_hidden(portal, target):
    app, _, store, access, _ = portal
    ref = store[SCOPE['alerts'], access]['cloud_soc']['provenance']['evidence'][0][target]
    store[ref['index'], ref['id']]['organization']['id'] = 'foreign'
    http, _ = login(app, 'view')
    e = http.get('/api/alerts/detail?id=' + access + '&evidence=0').json['evidence']
    assert 'raw' not in e and 'normalized' not in e and 'metadata' not in e and 'security' not in e


def test_changed_evidence_hash_and_raw_identity_rejected(portal):
    app, _, store, access, _ = portal
    ref = store[SCOPE['alerts'], access]['cloud_soc']['provenance']['evidence'][0]
    http, _ = login(app, 'view')
    norm = store[ref['normalized']['index'], ref['normalized']['id']]
    original = deepcopy(norm)
    norm['event']['outcome'] = 'success'
    assert http.get('/api/alerts/detail?id=' + access + '&evidence=0').json['evidence']['state'] == 'normalized_hash_mismatch'
    store[ref['normalized']['index'], ref['normalized']['id']] = original
    raw = store[ref['raw']['index'], ref['raw']['id']]
    raw['security_mall']['audit']['account_key_id'] = 'another-key'
    assert http.get('/api/alerts/detail?id=' + access + '&evidence=0').json['evidence']['state'] == 'provenance_mismatch'


def test_source_endpoints_enforce_scope_and_existing_role_policy(portal):
    app, es, _, access, _ = portal
    http, headers = login(app, 'investigate')
    rid = next(key[1] for key in portal[2] if key[0] == SCOPE['raw'])
    assert http.get('/api/logs/detail?index=' + SCOPE['raw'] + '&id=' + rid).status_code == 200
    assert http.post('/api/logs/source', json={'index': SCOPE['raw'], 'id': rid, 'purpose': 'investigation'}, headers=headers).status_code == 200
    es.get.reset_mock()
    assert http.get('/api/logs/detail?index=soc-host-raw-mall-synthetic-fixture&id=' + rid).status_code == 404
    assert http.post('/api/logs/source', json={'index': 'soc-host-raw-other', 'id': rid, 'purpose': 'investigation'}, headers=headers).status_code == 404
    es.get.assert_not_called()
    http, headers = login(app, 'other')
    assert http.post('/api/logs/source', json={'index': SCOPE['raw'], 'id': rid, 'purpose': 'investigation'}, headers=headers).status_code == 404
    http, headers = login(app, 'view')
    assert http.post('/api/logs/source', json={'index': SCOPE['raw'], 'id': rid, 'purpose': 'investigation'}, headers=headers).status_code == 403


@pytest.mark.parametrize('key,value', [('alerts', 'security-alerts'), ('alerts', SYNTHETIC),
                                     ('raw', 'soc-host-raw-*'), ('normalized', 'soc-normalized-mall-one,two')])
def test_invalid_server_scope_fails_closed(key, value):
    with pytest.raises(ValueError):
        validate_scope({**SCOPE, key: value})


def test_existing_auth001_contract_retained():
    store, access, _ = dataset()
    doc = deepcopy(store[SCOPE['alerts'], access])
    doc['rule']['id'] = 'AUTH-001'
    store['security-alerts', 'legacy'] = doc
    es = fake_es(store)
    ops = Operations(es, organizations=['synthetic'])
    row = json.loads(ops.summary([('start', '2026-10-01T00:00:00Z'), ('end', '2026-10-02T00:00:00Z')]))['sections']['alerts']['rows'][0]
    assert row['rule'] == 'AUTH-001' and row['risk_score'] == 20
    assert json.loads(ops.detail([('id', 'legacy')]))['alert']['rule'] == 'AUTH-001'


def test_widget_and_shared_assets_available_without_layout_rewrite(portal):
    app, _, _, _, _ = portal
    http, _ = login(app, 'view')
    assert REGISTRY['security-mall-count']['source'] == 'operations'
    assert valid_layout({'name': 'Mall', 'period': 1440, 'theme': 'light', 'widgets': [instance('security-mall-count')]}, 'viewer')
    assert http.get('/mall-alerts.js').status_code == 200
    for page in ('operations.html', 'workbench.html'):
        html = (ROOT / 'prototype' / page).read_text(encoding='utf-8')
        assert 'mall-alerts.js' in html
