"""All profiles enabled in disposable state; real engines/Flask, simulated ES IO."""
from contextlib import closing
from copy import deepcopy
from datetime import timedelta
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import uuid
from unittest.mock import patch

import pytest
from elasticsearch import NotFoundError

from cloud_soc.detection import early
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.profiles import RULE_IDS as CATALOG_IDS
from cloud_soc.detection.telemetry import RUNS, EXCLUSIONS
from cloud_soc.portal.app import create_app
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.detection_history import project
from cloud_soc.portal.log_query import LogQueryError
from ruleset_fixtures import positive, BASE, delete
from test_early_notices import Fixture
from test_integration_security import make_session_portal, login

# Legacy fixtures rewrite timestamps without edge-v1's corresponding envelope.
# WAF adapter/Portal/runtime/create-only cases have dedicated tests in 9-B.
RULE_IDS = tuple(key for key in CATALOG_IDS if key != 'WEB-WAF-01')


def fixture_for(identifier):
    rows = positive(identifier)
    hits = []
    for i, row in enumerate(rows):
        if i == len(rows) - 1:
            row['@timestamp'] = (BASE + timedelta(seconds=65)).isoformat()
            row['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=130)).isoformat()
        meta = row.pop('_cloud_soc_meta')
        hits.append({'_index': meta['index'], '_id': meta['document_id'], '_source': row})
    return Fixture(hits)


def run_at(fixture, path, seconds, **extra):
    return run_incremental(fixture.client, state_path=path, start=BASE,
        now=BASE + timedelta(seconds=seconds), lateness_seconds=60, scanner=fixture.scan,
        isolated_all=True, early_auth=True, **extra)


def saved(path):
    with closing(sqlite3.connect(path)) as db:
        return json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])


def reopen_in_fresh_process(fixture, path, seconds):
    # The source data and fake ES create-only store are synthetic and supplied
    # via stdin. SQLite window/cooldown/checkpoint state survives a new interpreter.
    code = '''import json,sys
from pathlib import Path
from test_ruleset_integration import Fixture,run_at
request=json.loads(sys.stdin.read())
fixture=Fixture(request['hits'])
fixture.docs={(index,key):body for index,key,body in request['docs']}
result=run_at(fixture,Path(request['path']),request['seconds'])
print(json.dumps({'result':result,'docs':[[index,key,body] for (index,key),body in fixture.docs.items()]}))
'''
    root = Path(__file__).resolve().parents[1]
    environment = {**os.environ, 'PYTHONPATH': os.pathsep.join((str(root / 'src'), str(root / 'tests')))}
    response = subprocess.run([sys.executable, '-c', code], input=json.dumps({
        'hits': fixture.hits, 'docs': [[index, key, body] for (index, key), body in fixture.docs.items()],
        'path': str(path), 'seconds': seconds}), capture_output=True, text=True,
        timeout=30, check=True, env=environment, cwd=root)
    body = json.loads(response.stdout)
    fixture.docs = {(index, key): document for index, key, document in body['docs']}
    return body['result']


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_all_enabled_split_receipts_fresh_process_replay_and_exact_portal_evidence(identifier, tmp_path):
    fixture = fixture_for(identifier)
    path = tmp_path / 'isolated.sqlite'
    run_at(fixture, path, 140)
    assert not any(index == 'security-alerts' and body['rule']['id'] == identifier
                   for (index, _), body in fixture.docs.items())
    first = saved(path)
    result = reopen_in_fresh_process(fixture, path, 230)
    assert result['created'] >= 1
    alerts = {key: body for (index, key), body in fixture.docs.items() if index == 'security-alerts'}
    chosen = [(key, body) for key, body in alerts.items() if body['rule']['id'] == identifier]
    assert len(chosen) == 1
    before = event_fingerprint(alerts)
    assert reopen_in_fresh_process(fixture, path, 300)['created'] == 0
    assert saved(path)['checkpoint'] > first['checkpoint']
    assert event_fingerprint({key: body for (index, key), body in fixture.docs.items() if index == 'security-alerts'}) == before
    completed = [body for (index, _), body in fixture.docs.items() if index == RUNS and body['state'] == 'committed']
    assert set(RULE_IDS) <= {body['rule']['id'] for body in completed}
    assert any(body['rule']['id'] == identifier and body['counts']['source_events'] for body in completed)
    assert all(project(body)['assessment']['state'] in ('evaluated', 'unverified', 'not_evaluable') for body in completed)

    # Real portal hash verification against the exact normalized document and raw
    # locator. Original source content is represented by public metadata only.
    store = deepcopy(fixture.docs)
    for hit in fixture.hits:
        row = hit['_source']
        store[(hit['_index'], hit['_id'])] = row
        raw = row['cloud_soc']['provenance']['raw']
        store[(raw['index'], raw['id'])] = {'organization': row['organization'], '@timestamp': row['@timestamp']}
    key, alert = chosen[0]
    reader = Operations(fixture.client)
    with patch.object(reader, 'get', side_effect=lambda index, identifier, fields: deepcopy(store.get((index, identifier)))):
        for i in range(len(alert['cloud_soc']['provenance']['evidence'])):
            detail = json.loads(reader.detail([('id', key), ('evidence', str(i))]))
            assert detail['evidence']['state'] == 'exact_reference'
            assert detail['evidence']['integrity'] == 'normalized_hash_verified'
            assert detail['alert']['rule'] == identifier
    if identifier in ('AUTH-001', 'AUTH-SPRAY-001'):
        notices = [body for (index, _), body in fixture.docs.items() if index == early.NOTICES]
        assert notices and any(body['notice']['state'] == 'confirmed' for body in notices)
    else:
        assert not any(index == early.NOTICES for index, _ in fixture.docs)


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_missing_required_field_is_persisted_as_exclusion_and_source_absence_is_unverified(identifier, tmp_path):
    fixture = fixture_for(identifier)
    for hit in fixture.hits:
        delete(hit['_source'], 'organization.id')
    path = tmp_path / 'incomplete.sqlite'
    assert run_at(fixture, path, 230)['created'] == 0
    records = [body for (index, _), body in fixture.docs.items() if index == EXCLUSIONS and body['rule']['id'] == identifier]
    assert records and all('organization.id' in body['missing_fields'] for body in records)
    assert not any(index == 'security-alerts' for index, _ in fixture.docs)
    histories = [body for (index, _), body in fixture.docs.items() if index == RUNS and body['state'] == 'committed' and body['rule']['id'] == identifier]
    assert histories[-1]['assessment']['state'] == 'not_evaluable'
    empty = Fixture([])
    run_at(empty, tmp_path / 'no-sources.sqlite', 230)
    assert all(body['assessment']['state'] == 'unverified' for (index, _), body in empty.docs.items() if index == RUNS)


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_write_failure_preserves_checkpoint_then_recovers_without_overwrite(identifier, tmp_path):
    fixture = fixture_for(identifier)
    path = tmp_path / 'failure.sqlite'
    run_at(fixture, path, 140)
    prior = saved(path)
    create = fixture.create
    failed = False

    def fail_once(**options):
        nonlocal failed
        if options['index'] == 'security-alerts' and not failed:
            failed = True
            raise RuntimeError('isolated simulated failure')
        return create(**options)

    fixture.client.create.side_effect = fail_once
    with pytest.raises(RuntimeError):
        run_at(fixture, path, 230)
    assert saved(path) == prior
    fixture.client.create.side_effect = create
    assert run_at(fixture, path, 230)['created'] >= 1
    snapshot = deepcopy(fixture.docs)
    assert run_at(fixture, path, 300)['created'] == 0
    assert all(fixture.docs[key] == body for key, body in snapshot.items())
    # The existing state is never reset when someone selects another profile.
    before = saved(path)
    with pytest.raises(ValueError, match='requires_new_state'):
        run_incremental(fixture.client, state_path=path, start=BASE, now=BASE + timedelta(seconds=400),
                        lateness_seconds=60, scanner=fixture.scan)
    assert saved(path) == before


@pytest.mark.parametrize('identifier', RULE_IDS)
def test_real_flask_alert_case_dashboard_and_scoped_denial(identifier, tmp_path):
    fixture = fixture_for(identifier)
    run_at(fixture, tmp_path / 'pipeline.sqlite', 230)
    key, body = next((key, body) for (index, key), body in fixture.docs.items()
                     if index == 'security-alerts' and body['rule']['id'] == identifier)
    (tmp_path / 'portal').mkdir()
    app, monitor, settings, _ = make_session_portal(tmp_path / 'portal')
    monitor.indices.resolve_index.side_effect = lambda **options: {'indices': [{'name': options['name']}]}
    def stub_get(**options):
        if options['index'] == 'security-alerts' and options['id'] == key:
            return {'_source': deepcopy(body)}
        # Elasticsearch GET returns 404 by exception, never a {'found': False} response.
        raise NotFoundError('not found', None, {'found': False})
    monitor.get.side_effect = stub_get
    admin, headers = login(app, 'admin')
    detail = admin.get('/api/alerts/detail', query_string={'id': key})
    assert detail.status_code == 200 and detail.json['alert']['rule'] == identifier
    monitor.indices.resolve_index.side_effect = lambda **options: {'indices': [{'name': 'security-alerts'}]} if options['name'] == 'security-alerts' else {'indices': []}
    monitor.field_caps.return_value = {'fields': {'@timestamp': {'date': {'aggregatable': True, 'searchable': True}}}}
    monitor.search.return_value = {'timed_out': False, '_shards': {'failed': 0},
        'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [{'_id': key, '_source': body}]},
        'aggregations': {'trend': {'buckets': [{'key_as_string': body['@timestamp'], 'doc_count': 1}]}}}
    monitor.search.side_effect = None
    summary = admin.get('/api/operations', query_string={'start': BASE.isoformat(), 'end': (BASE + timedelta(days=1)).isoformat()})
    assert summary.status_code == 200
    assert summary.json['sections']['alerts']['rows'][0]['rule'] == identifier
    assert summary.json['sections']['alerts']['count'] == 1
    monitor.indices.resolve_index.side_effect = lambda **options: {'indices': [{'name': options['name']}]}
    case = admin.post('/api/cases', json={'title': 'Approved isolated rule validation', 'alert_id': key,
        'priority': body['cloud_soc']['severity']}, headers={**headers, 'Idempotency-Key': str(uuid.uuid4())})
    assert case.status_code == 200
    edited = admin.patch('/api/cases/' + case.json['id'], json={'version': case.json['version'],
        'note': 'Synthetic isolated data; no live attack attribution', 'verdict': 'benign', 'status': 'closed'},
        headers={**headers, 'Idempotency-Key': str(uuid.uuid4())})
    assert edited.status_code == 200
    dashboard = admin.post('/api/dashboards', json={'revision': 0, 'action': 'create', 'template': 'security',
        'name': 'Isolated fourteen rule validation'}, headers=headers)
    assert dashboard.status_code == 200
    assert any(widget['type'] == 'alerts' for widget in dashboard.json['dashboards'][0]['layout']['widgets'])
    restarted = create_app(settings, issuer=app.extensions['issuer'], monitor=monitor)
    fresh, _ = login(restarted, 'admin')
    assert fresh.get('/api/cases/' + case.json['id']).json['case']['status'] == 'closed'
    assert fresh.get('/api/dashboards').json['dashboards'] == dashboard.json['dashboards']
    # A real scoped reader must deny other organizations and never grant access
    # through client-supplied role/scope headers.
    scoped = Operations(monitor, organizations=['foreign'])
    with pytest.raises(LogQueryError):
        scoped.detail([('id', key)])
    viewer, _ = login(app, 'view')
    assert viewer.get('/api/detection/history', headers={'X-Role': 'admin'}).status_code == 403
    assert viewer.get('/api/alerts/detail', query_string={'id': key}).status_code == 404
    assert body == fixture.docs[('security-alerts', key)]


def test_all_profiles_together_generate_all_rule_ids_without_rewriting_existing_state(tmp_path):
    hits = []
    for identifier in RULE_IDS:
        fixture = fixture_for(identifier)
        for hit in fixture.hits:
            hit['_id'] += '-' + identifier
            hit['_source']['organization']['id'] = 'isolated-' + identifier.lower()
            hits.append(hit)
    fixture = Fixture(hits)
    run_at(fixture, tmp_path / 'all.sqlite', 230)
    found = {body['rule']['id'] for (index, _), body in fixture.docs.items() if index == 'security-alerts'}
    assert found == set(RULE_IDS)
