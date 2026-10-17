"""9-C: real Portal/engines/CLI with synthetic ES IO; never contacts a VM/ES."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import Mock, patch

import pytest
from elastic_transport import ApiResponseMeta, NodeConfig
from elasticsearch import ApiError, ConflictError

from cloud_soc.detection.engine import detect_events
from cloud_soc.detection import mall_lab
from cloud_soc.detection.worker import approved_rules
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.portal.app import create_app
from cloud_soc.portal.mall_scope import read_scope, scope_indices, validate_scope
import test_mall_investigation_portal as investigation_fixtures
from test_security_mall_portal import SCOPE, ROOT, fake_es
from test_security_mall_waf_detection import SCOPE as EDGE, waf, rule as waf_rule
from test_integration_security import login
from test_source_access import HASH

snapshot = investigation_fixtures.snapshot
START, END = '2026-10-17T00:00:00Z', '2026-10-18T00:00:00Z'
MULTI = {'alerts': SCOPE['alerts'], 'normalized': [SCOPE['normalized'], EDGE['normalized']],
         'raw': [SCOPE['raw'], EDGE['raw']]}


@pytest.fixture
def combined(snapshot, tmp_path):
    config, store, access = snapshot
    source, event = waf(org='synthetic', host=config['scope']['host'])
    detection, = detect_events([event], [waf_rule()])
    wid = make_alert_id(detection)
    norm = deepcopy(event); norm.pop('_cloud_soc_meta')
    store[EDGE['raw'], source['event']['id']] = source
    store[EDGE['normalized'], event['_cloud_soc_meta']['document_id']] = norm
    store[SCOPE['alerts'], wid] = build_security_alert(detection)
    users = {'admin': {'role': 'admin', 'password_hash': HASH},
             'view': {'role': 'viewer', 'password_hash': HASH}, 'other': {'role': 'viewer', 'password_hash': HASH}}
    policy = {'version': 1, 'protected_source_enabled': True, 'admin_source_organizations': ['synthetic'],
              'users': [{'username': n, 'role': 'viewer', 'password_hash': HASH, 'organizations': [org]}
                        for n, org in [('view', 'synthetic'), ('other', 'foreign')]]}
    user_file = tmp_path / 'users.json'; user_file.write_text(json.dumps(users)); user_file.chmod(0o600)
    snapshot_file = tmp_path / 'snapshot.json'
    snapshot_file.write_text(json.dumps(config)); snapshot_file.chmod(0o600)
    es = fake_es(store)
    app = create_app({'STATE_DIR': tmp_path, 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': b'SYNTHETIC CA',
        'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://example.test:9200', 'ADMIN_USER': 'admin',
        'ADMIN_HASH': HASH, 'USERS_FILE': str(user_file), 'LOG_ACCESS_POLICY': policy,
        'MALL_LAB_SCOPE': MULTI, 'MALL_TRIAGE_SNAPSHOT_FILE': str(snapshot_file)}, issuer=Mock(), monitor=es)
    app.config['TESTING'] = True
    return app, es, store, access, wid


def test_single_scope_roundtrip_and_bounded_multi_file(tmp_path):
    assert validate_scope(SCOPE) == SCOPE
    assert scope_indices(validate_scope(SCOPE), 'raw') == (SCOPE['raw'],)
    path = tmp_path / 'scope.json'; path.write_text(json.dumps(MULTI))
    scope = read_scope(path)
    assert scope['alerts'] == SCOPE['alerts']
    assert scope_indices(scope, 'normalized') == tuple(MULTI['normalized'])
    assert validate_scope(scope) == scope


@pytest.mark.parametrize('key,value', [
    ('alerts', [SCOPE['alerts']]), ('raw', []), ('raw', [SCOPE['raw']] * 2),
    ('raw', ['soc-host-raw-*']), ('raw', ['security-alerts']), ('raw', [1]),
    ('normalized', ['soc-normalized-mall-one,two']), ('normalized', {'index': SCOPE['normalized']}),
    ('normalized', ['soc-normalized-mall-synthetic-one']), ('raw', ['soc-host-raw-mall-x'] * 9),
])
def test_invalid_scope_rejected(key, value):
    with pytest.raises(ValueError):
        validate_scope({**MULTI, key: value})


def test_access_and_waf_detail_metadata_and_existing_snapshot(combined):
    app, _, store, access, wid = combined
    before = deepcopy(store)
    http, headers = login(app, 'view')
    access_data = http.get('/api/alerts/detail?id=' + access + '&evidence=0').json
    assert access_data['risk']['score'] == access_data['investigation']['triage_score'] == 20
    assert access_data['alert']['severity'] == 'low'
    assert access_data['investigation']['evidence_confidence'] == 'limited'
    waf_data = http.get('/api/alerts/detail?id=' + wid + '&evidence=0').json
    assert waf_data['risk']['score'] == 45 and waf_data['assessment']['blocked'] is False
    assert waf_data['investigation']['state'] != 'available'
    for data in (access_data, waf_data):
        evidence = data['evidence']
        assert evidence['state'] == 'exact_reference' and evidence['integrity'] == 'normalized_hash_verified'
        ref = evidence['raw']
        assert http.get('/api/logs/detail?index=' + ref['index'] + '&id=' + ref['id']).status_code == 200
        assert http.post('/api/logs/source', json={**ref, 'purpose': 'investigation'}, headers=headers).status_code == 403
        assert 'PRIVATE_CANARY' not in json.dumps(data)
    assert store == before


def test_multi_scope_foreign_org_and_browser_override_denied(combined):
    app, _, store, access, wid = combined
    http, _ = login(app, 'other')
    for aid in (access, wid):
        assert http.get('/api/alerts/detail?id=' + aid).status_code == 404
        ref = store[SCOPE['alerts'], aid]['cloud_soc']['provenance']['evidence'][0]['raw']
        assert http.get('/api/logs/detail?index=' + ref['index'] + '&id=' + ref['id']).status_code == 404
    http, _ = login(app, 'view')
    for arg in ('index=security-alerts', 'organization=foreign', 'raw=soc-host-raw-mall-other'):
        assert http.get('/api/alerts/detail?id=' + access + '&' + arg).status_code == 400
    assert http.get('/api/logs/detail?index=soc-host-raw-mall-outside&id=hidden').status_code == 404


@pytest.mark.parametrize('variant', ['alias', 'data_stream', 'unexpected'])
def test_runtime_resolution_fails_closed(combined, variant):
    app, es, _, _, wid = combined
    original = es.indices.resolve_index.side_effect
    def resolve(name, **options):
        if name == EDGE['raw']:
            return {'indices': [{'name': EDGE['raw'] if variant != 'unexpected' else 'soc-host-raw-mall-outside'}],
                    'aliases': [{'name': name}] if variant == 'alias' else [],
                    'data_streams': [{'name': name}] if variant == 'data_stream' else []}
        return original(name, **options)
    es.indices.resolve_index.side_effect = resolve
    http, _ = login(app, 'view')
    assert http.get('/api/alerts/detail?id=' + wid + '&evidence=0').status_code == 503
    assert http.get('/api/logs/detail?index=' + EDGE['raw'] + '&id=unknown').status_code == 503


@pytest.mark.parametrize('rule_id', ['access', 'waf'])
@pytest.mark.parametrize('change', ['hash', 'raw_reference', 'raw_event_id'])
def test_multi_scope_integrity_failures(combined, rule_id, change):
    app, _, store, access, wid = combined
    aid = access if rule_id == 'access' else wid
    ref = store[SCOPE['alerts'], aid]['cloud_soc']['provenance']['evidence'][0]
    if change == 'hash':
        store[ref['normalized']['index'], ref['normalized']['id']]['event']['outcome'] = 'tampered'
    elif change == 'raw_reference':
        ref['raw']['index'] = 'soc-host-raw-mall-outside'
    else:
        raw = store[ref['raw']['index'], ref['raw']['id']]
        if rule_id == 'access': raw['security_mall']['audit']['event_id'] = '11111111-1111-4111-8111-111111111111'
        else: raw['event']['id'] = 'a' * 64
    http, _ = login(app, 'view')
    evidence = http.get('/api/alerts/detail?id=' + aid + '&evidence=0').json['evidence']
    assert evidence['state'] != 'exact_reference' and 'security' not in evidence


def lab_config():
    return {'es_url': 'https://127.0.0.1:19200', 'ca_file': str(Path.cwd() / 'state/ca.crt'),
            'reader_key_file': str(Path.cwd() / 'state/reader.json'),
            'writer_key_file': str(Path.cwd() / 'state/writer.json'), 'organization': 'waf-org', 'host': 'waf-host',
            'scope': EDGE, 'rule_ids': ['WEB-WAF-01'], 'max_documents': 100}


def clients(events):
    config = lab_config(); store = {}
    for source, event in events:
        meta = event['_cloud_soc_meta']; norm = deepcopy(event); norm.pop('_cloud_soc_meta')
        store[EDGE['raw'], source['event']['id']] = deepcopy(source)
        store[meta['index'], meta['document_id']] = norm
    reader, writer = fake_es(store), Mock()
    reader.indices.resolve_index.side_effect = lambda name, **_: {'indices': [{'name': n} for n in name.split(',')]}
    reader.indices.get_mapping.return_value = {EDGE['alerts']: {'mappings': {'properties': {
        'cloud_soc': {'properties': {'provenance': {'type': 'object', 'enabled': False}}}}}}}
    def grants(role):
        return {'cluster': {p: False for p in ['all', 'manage', 'manage_security', 'manage_api_key']},
                'index': {n: {p: p in ({'read', 'view_index_metadata'} if role == 'reader' else
                    {'create_doc', 'view_index_metadata'} if n == EDGE['alerts'] else set())
                    for p in mall_lab.PRIVILEGES} for n in scope_indices(validate_scope(EDGE))}}
    reader.security.has_privileges.return_value = grants('reader')
    writer.security.has_privileges.return_value = grants('writer')
    reader.open_point_in_time.side_effect = lambda index, **_: {'id': index}
    def search(**options):
        if options.get('search_after') is not None: return {'hits': {'hits': []}}
        rows = [{'_index': index, '_id': key, '_source': deepcopy(value), 'sort': [i]}
                for i, ((index, key), value) in enumerate(store.items()) if index == options['pit']['id']]
        return {'hits': {'hits': rows}}
    reader.search.side_effect = search
    def create(index, id, document, **_):
        if (index, id) in store: raise ConflictError('duplicate', None, {})
        store[index, id] = deepcopy(document)
        return {'result': 'created'}
    writer.create.side_effect = create
    return config, reader, writer, store


def test_runner_dry_run_repeat_count_provenance_and_immutable_replay():
    values = [waf(n, seconds=n * 10, ids=('942100', '942140')) for n in range(1, 4)]
    config, reader, writer, store = clients(values)
    original = deepcopy(store)
    plan = mall_lab.run(reader, config, START, END)
    assert plan['mode'] == 'dry_run' and plan['detections'] == 3 and plan['created'] == 0
    assert store == original
    result = mall_lab.run(reader, config, START, END, writer=writer, write_alerts=True)
    assert result['created'] == 3
    saved = deepcopy(store)
    result = mall_lab.run(reader, config, START, END, writer=writer, write_alerts=True)
    assert result['created'] == 0 and result['existing'] == 3 and store == saved
    alerts = [d for (index, _), d in store.items() if index == EDGE['alerts']]
    assert sorted(d['cloud_soc']['provenance']['assessment']['request_count'] for d in alerts) == [1, 2, 3]
    assert sorted(d['cloud_soc']['risk_score'] for d in alerts) == [45, 55, 55]
    assert all(d['cloud_soc']['provenance']['evidence'] for d in alerts)
    assert all(not d['cloud_soc']['provenance']['assessment']['blocked'] for d in alerts)
    for es in (reader, writer):
        es.index.assert_not_called(); es.update.assert_not_called(); es.delete.assert_not_called()
        es.indices.put_mapping.assert_not_called()


def test_runner_request_duplicates_diagnostics_and_ip_isolation():
    repeated = waf(1)
    repeated[1]['_cloud_soc_meta']['document_id'] += '-revision'
    values = [waf(1), repeated, waf(2, seconds=10, ids=('10002', '920350')),
              waf(3, seconds=20, ip='192.0.2.3'), waf(4, seconds=30, ip='192.0.2.4')]
    config, reader, writer, store = clients(values)
    result = mall_lab.run(reader, config, START, END, writer=writer, write_alerts=True)
    assert result['created'] == 3
    alerts = [d for (index, _), d in store.items() if index == EDGE['alerts']]
    assert all(d['cloud_soc']['provenance']['assessment']['request_count'] == 1 for d in alerts)
    assert [r['id'] for r in approved_rules()] == ['AUTH-001']


@pytest.mark.parametrize('change', ['raw_scope', 'provenance', 'organization', 'host', 'service', 'reader_write', 'writer_index', 'alias'])
def test_runner_rejects_before_first_write(change):
    config, reader, writer, store = clients([waf()])
    norm_key = next(k for k in store if k[0] == EDGE['normalized'])
    if change == 'raw_scope': store[norm_key]['cloud_soc']['provenance']['raw']['index'] = 'soc-host-raw-mall-outside'
    elif change == 'provenance': store[norm_key]['cloud_soc'].pop('provenance')
    elif change in ('organization', 'host', 'service'):
        store[norm_key][change]['name' if change == 'service' else 'id'] = 'other'
    elif change == 'reader_write': reader.security.has_privileges.return_value['index'][EDGE['raw']]['write'] = True
    elif change == 'writer_index': writer.security.has_privileges.return_value['index'][EDGE['alerts']]['index'] = True
    else: reader.indices.resolve_index.return_value = {'aliases': [{'name': EDGE['raw']}], 'indices': []}; reader.indices.resolve_index.side_effect = None
    with pytest.raises((mall_lab.LabError, ValueError)):
        mall_lab.run(reader, config, START, END, writer=writer, write_alerts=True)
    writer.create.assert_not_called()


def test_cli_default_does_not_load_writer_and_does_not_disclose(tmp_path, capsys):
    config, reader, writer, _ = clients([waf()])
    tmp_path.chmod(0o700)
    path = tmp_path / 'config.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
    factory = Mock(return_value=reader)
    assert mall_lab.main(['--config', str(path), '--start', START, '--end', END], client_factory=factory) == 0
    assert factory.call_count == 1 and factory.call_args.args[1] == 'reader'
    assert json.loads(capsys.readouterr().out)['mode'] == 'dry_run'
    writer.create.assert_not_called()
    command = [sys.executable, '-m', 'cloud_soc.detection.mall_lab']
    child_env = os.environ.copy()
    source_dir = str(Path(__file__).resolve().parents[1] / 'src')
    child_env['PYTHONPATH'] = os.pathsep.join(filter(None, (source_dir, child_env.get('PYTHONPATH'))))
    help_result = subprocess.run([*command, '--help'], capture_output=True, text=True,
                                 check=False, env=child_env)
    assert help_result.returncode == 0 and '--write-alerts' in help_result.stdout
    failure = subprocess.run([*command, '--config', str(tmp_path / 'missing'), '--start', START,
                              '--end', END], capture_output=True, text=True, check=False, env=child_env)
    assert failure.returncode == 1 and json.loads(failure.stdout)['state'] == 'failed'
    assert not failure.stderr


def test_client_private_key_expiry_and_full_tls(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / 'reader.json'
    payload = {'encoded': base64.b64encode(b'fake-id:FAKE_SECRET').decode(), 'expiration': int(time.time()*1000)+100000}
    path.write_text(json.dumps(payload)); path.chmod(0o600)
    config = lab_config(); config['reader_key_file'] = str(path)
    with patch.object(mall_lab.ssl, 'create_default_context') as tls, patch.object(mall_lab, 'Elasticsearch') as es:
        mall_lab.client(config, 'reader')
        tls.assert_called_once_with(cafile=config['ca_file'])
        assert es.call_args.kwargs['ssl_context'] == tls.return_value
        assert es.call_args.args == ('https://127.0.0.1:19200',)
        payload['expiration'] = 0; path.write_text(json.dumps(payload))
        with pytest.raises(mall_lab.LabError, match='expired'):
            mall_lab.client(config, 'reader')


@pytest.mark.parametrize('status,reason', [(401, 'authentication_failed'), (403, 'permission_denied')])
def test_cli_auth_errors_are_sanitized_and_never_write(tmp_path, capsys, status, reason):
    config, reader, writer, _ = clients([waf()])
    tmp_path.chmod(0o700)
    path = tmp_path / 'config.json'; path.write_text(json.dumps(config)); path.chmod(0o600)
    meta = ApiResponseMeta(status, '1.1', {}, 0, NodeConfig('https', '127.0.0.1', 19200))
    reader.security.has_privileges.side_effect = ApiError('PRIVATE_CANARY', meta, {'secret': 'PRIVATE_CANARY'})
    assert mall_lab.main(['--config', str(path), '--start', START, '--end', END],
                         client_factory=Mock(return_value=reader)) == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {'state': 'failed', 'reason': reason, 'http_status': status}
    assert 'PRIVATE_CANARY' not in output.out and not output.err
    writer.create.assert_not_called()


@pytest.mark.parametrize('change', ['endpoint', 'index', 'time', 'capacity'])
def test_runner_boundaries_fail_without_writes(change):
    config, reader, writer, _ = clients([waf()])
    if change == 'endpoint': config['es_url'] = 'https://external.invalid:19200'
    elif change == 'index': config['scope'] = {**EDGE, 'normalized': 'soc-normalized-v1'}
    elif change == 'capacity': config['max_documents'] = 10001
    with pytest.raises((mall_lab.LabError, ValueError)):
        mall_lab.run(reader, config, START, '2026-10-19T00:00:00Z' if change == 'time' else END,
                     writer=writer, write_alerts=True)
    reader.search.assert_not_called(); writer.create.assert_not_called()
