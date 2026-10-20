"""Private configuration and recovery tests use disposable SQLite state only."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from cloud_soc.portal.app import create_app
from cloud_soc.portal.dashboards import DashboardStore, DashboardError, DEFAULT
from cloud_soc.portal.dashboard_widgets import catalog, template, instance, valid_layout
from cloud_soc.portal import backup
from legacy_backup_fixtures import legacy_source, legacy_artifact, legacy_layout, collection, snapshot
from test_integration_security import session_portal as session_portal, login
from unittest.mock import Mock


def create(store, actor='a', revision=0, key='empty', role='viewer'):
    return store.mutate(actor, role, {'revision': revision, 'action': 'create', 'template': key, 'name': '개인 화면'})


def test_read_does_not_migrate_or_replace_legacy_and_copy_is_explicit(tmp_path):
    store = DashboardStore(tmp_path / 'dashboards.sqlite')
    old = {**deepcopy(DEFAULT), 'name': '기존 화면', 'widgets': [
        {'id': 'overview', 'size': 'wide'}, {'id': 'alerts', 'size': 'normal'},
        {'id': 'pipeline', 'size': 'wide'}]}
    store.save('a', {'revision': 0, 'layout': old})
    before = store.get('a')
    for _ in range(2):
        value = store.collection('a', 'viewer')
        assert value['revision'] == 0 and value['dashboards'] == []
        assert valid_layout(value['legacy']['layout'], 'viewer')
    with store.connect() as db:
        assert db.execute('SELECT count(*) FROM dashboard_collections').fetchone()[0] == 0
    result = store.mutate('a', 'viewer', {'revision': 0, 'action': 'duplicate', 'id': 'legacy', 'name': '복사'})
    assert result['dashboards'][0]['layout']['widgets'][0]['w'] == 12
    assert store.get('a') == before
    assert store.collection('b', 'viewer')['dashboards'] == []


def test_crud_default_favorites_and_restart(tmp_path):
    path = tmp_path / 'dashboards.sqlite'
    store = DashboardStore(path)
    response = create(store)
    first = response['selected_id']
    assert response['dashboards'][0]['layout']['widgets'] == []
    for action, extra in [('rename', {'name': '내 화면'}), ('favorite', {'favorite': True}), ('default', {})]:
        response = store.mutate('a', 'viewer', {'revision': response['revision'], 'action': action, 'id': first, **extra})
    assert response['default_id'] == first
    assert DashboardStore(path).collection('a', 'viewer')['dashboards'][0]['favorite'] is True
    response = store.mutate('a', 'viewer', {'revision': response['revision'], 'action': 'duplicate', 'id': first, 'name': '사본'})
    assert len(response['dashboards']) == 2
    response = store.mutate('a', 'viewer', {'revision': response['revision'], 'action': 'delete', 'id': first})
    assert response['default_id'] == 'legacy' and len(response['dashboards']) == 1
    with pytest.raises(DashboardError) as error:
        store.mutate('b', 'viewer', {'revision': 0, 'action': 'rename', 'id': response['dashboards'][0]['id'], 'name': '다른 사용자'})
    assert error.value.status == 404


def test_instances_have_independent_settings_and_survive_restart(tmp_path):
    store = DashboardStore(tmp_path / 'dashboards.sqlite')
    result = create(store)
    layout = deepcopy(result['dashboards'][0]['layout'])
    layout['widgets'] = [instance('trend', 0), instance('trend', 1)]
    layout['widgets'][0]['config'].update(period=60, chart='bar', title='최근 경보')
    layout['widgets'][1]['config'].update(period=10080, chart='heatmap', color='purple')
    saved = store.mutate('a', 'viewer', {'revision': 1, 'action': 'save', 'id': result['selected_id'], 'layout': layout})
    assert DashboardStore(store.path).collection('a', 'viewer')['dashboards'] == saved['dashboards']
    assert store.get('a')['revision'] == 0


@pytest.mark.parametrize('change', [
    {'type': 'world-map'}, {'type': 'pipeline'}, {'x': 7, 'w': 6}, {'x': -1}, {'y': 241}, {'w': 13},
    {'h': True}, {'id': '<script>'}, {'url': 'https://evil.test'},
    {'config': {'query': '*'}}, {'type': ['alerts']},
])
def test_widget_tampering_rejected_without_losing_saved_data(tmp_path, change):
    store = DashboardStore(tmp_path / 'store.sqlite')
    result = create(store, key='security')
    layout = deepcopy(result['dashboards'][0]['layout'])
    layout['widgets'][0].update(change)
    with pytest.raises(DashboardError):
        store.mutate('a', 'viewer', {'revision': 1, 'action': 'save', 'id': result['selected_id'], 'layout': layout})
    assert store.collection('a', 'viewer')['revision'] == 1


@pytest.mark.parametrize('key,value', [('title','<img src=x onerror=alert(1)>'), ('title','password=private-canary'),
    ('title','a\nline'), ('period', True), ('period', 5), ('severity','foreign'), ('sort','script'),
    ('chart','external'), ('limit',100000), ('color','url(javascript:x)')])
def test_configuration_allowlist_and_xss(key, value):
    layout = template('security', 'viewer')
    layout['widgets'][0]['config'][key] = value
    assert not valid_layout(layout, 'viewer')


def test_overlapping_and_duplicate_instance_identifiers_are_rejected():
    layout = template('security', 'viewer')
    layout['widgets'][1].update(x=layout['widgets'][0]['x'], y=layout['widgets'][0]['y'])
    assert not valid_layout(layout, 'viewer')
    layout = template('security', 'viewer')
    layout['widgets'][1]['id'] = layout['widgets'][0]['id']
    assert not valid_layout(layout, 'viewer')


def test_templates_catalog_roles_and_mutation_limits(tmp_path):
    assert len(catalog('admin')) >= 20
    for role in ('admin', 'analyst', 'viewer'):
        for key in ('security', 'investigation', 'cloud', 'collection', 'empty'):
            assert valid_layout(template(key, role), role)
    assert not next(w for w in catalog('viewer') if w['type'] == 'agents')['enabled']
    store = DashboardStore(tmp_path / 'store.sqlite')
    for revision in range(20):
        create(store, revision=revision)
    with pytest.raises(DashboardError):
        create(store, revision=20)
    assert len(store.collection('a', 'viewer')['dashboards']) == 20


def test_two_independent_connections_cannot_overwrite_each_other(tmp_path):
    path = tmp_path / 'store.sqlite'
    store = DashboardStore(path)
    create(store)
    def attempt(name):
        try:
            return DashboardStore(path).mutate('a', 'viewer', {'revision': 1, 'action': 'create', 'template': 'empty', 'name': name})['revision']
        except DashboardError as error:
            return error.status
    with ThreadPoolExecutor(2) as pool:
        assert sorted(pool.map(attempt, ['창 1', '창 2'])) == [2, 409]
    assert len(store.collection('a', 'viewer')['dashboards']) == 2


def test_api_keeps_auth_csrf_organization_and_role_authority(session_portal):
    app, monitor, settings, _ = session_portal
    view, headers = login(app, 'view')
    payload = {'revision': 0, 'action': 'create', 'template': 'security', 'name': '조회 화면'}
    assert app.test_client().get('/api/dashboards').status_code == 401
    assert view.get('/api/dashboards?actor=admin').status_code == 400
    assert view.post('/api/dashboards', json=payload, headers={'X-Cloud-SOC': 'portal'}).status_code == 403
    assert view.post('/api/dashboards', json=payload, headers={**headers, 'Origin': 'https://evil.test'}).status_code == 403
    assert view.post('/api/dashboards', json={**payload, 'actor': 'admin'}, headers=headers).status_code == 400
    response = view.post('/api/dashboards', json=payload, headers=headers)
    assert response.status_code == 200
    other, _ = login(app, 'investigate')
    assert other.get('/api/dashboards').json['dashboards'] == []
    assert view.post('/api/cases', json={}, headers=headers).status_code == 403
    assert view.get('/api/agents/status').status_code == 403
    assert view.get('/api/detection/history').status_code == 403
    assert view.get('/api/logs').status_code == 200
    assert {'terms': {'organization.id': ['synthetic']}} in monitor.search.call_args.kwargs['body']['query']['bool']['filter']
    assert view.get('/dashboard-builder.js').status_code == 200
    assert view.get('/dashboard-widgets.js').status_code == 200
    restarted = create_app(settings, issuer=Mock(), monitor=monitor)
    fresh, _ = login(restarted, 'view')
    assert fresh.get('/api/dashboards').json['dashboards'] == response.json['dashboards']
    assert view.post('/api/auth/logout', json={}, headers=headers).status_code == 200
    fresh_again, _ = login(app, 'view')
    assert fresh_again.get('/api/dashboards').json['dashboards'] == response.json['dashboards']


def test_storage_errors_keep_failure_distinct_from_empty(session_portal):
    app, _, _, _ = session_portal
    view, headers = login(app, 'view')
    with app.extensions['dashboards'].connect() as db:
        db.execute('DROP TABLE dashboard_collections')
    assert view.get('/api/dashboards').status_code == 503
    assert view.post('/api/dashboards', json={'revision': 0, 'action': 'create', 'template': 'empty', 'name': '개인'}, headers=headers).status_code == 503


def test_independent_application_process_keeps_multi_dashboard_settings(session_portal):
    app, _, settings, _ = session_portal
    http, headers = login(app, 'view')
    result = http.post('/api/dashboards', headers=headers, json={
        'revision': 0, 'action': 'create', 'template': 'cloud', 'name': '프로세스 재시작 검증'}).json
    code = '''import json,sys
from unittest.mock import Mock
from cloud_soc.portal.app import create_app
settings=json.loads(sys.stdin.read())
app=create_app(settings,issuer=Mock(),monitor=Mock())
client=app.test_client()
response=client.post('/api/auth/login',json={'username':'view','password':'synthetic-password'},headers={'X-Cloud-SOC':'portal'})
assert response.status_code==200
response=client.get('/api/dashboards')
assert response.status_code==200
print(json.dumps(response.json['dashboards']))
'''
    root = Path(__file__).resolve().parents[1]
    environment = {**os.environ, 'PYTHONPATH': str(root / 'src')}
    child = subprocess.run([sys.executable, '-c', code], input=json.dumps(settings, default=str),
                           text=True, capture_output=True, timeout=20, env=environment, cwd=root, check=True)
    assert json.loads(child.stdout) == result['dashboards']


def test_current_multi_dashboard_and_insight_backup_restore(session_portal, tmp_path):
    from cloud_soc.portal.insight_state import InsightStore, InsightError
    from cloud_soc.portal.insight_metrics import validate_policy, validate_assessment, validate_evaluation
    from test_dashboard_insights_decisions import policy, assessment, evaluation_run
    from datetime import datetime, timezone

    app, _, settings, _ = session_portal
    store = app.extensions['dashboards']
    legacy = store.save('view', {'revision': 0, 'layout': DEFAULT})
    other = store.save('other', {'revision': 0, 'layout': {**deepcopy(DEFAULT), 'name': 'Other settings', 'theme': 'dark'}})
    created = create(store, actor='view', key='cloud')
    copied = store.mutate('view', 'viewer', {'revision': 1, 'action': 'default', 'id': created['selected_id']})
    source = settings['STATE_DIR']
    insights = app.extensions['insights']
    now = 1900000000
    insights.clock = lambda: now
    key = insights.register({'request_id': 'backup-device', 'organization': 'org-a', 'label': 'synthetic',
                             'interval': 30, 'days': 1}, 'admin')
    body = {'generation': key['generation'], 'sequence': 1,
            'generated_at': datetime.fromtimestamp(now, timezone.utc).isoformat(), 'collector': {'state': 'running'}}
    insights.heartbeat(key['credential'], body)
    insights.put_record('policy', policy(), 'admin', validate_policy)
    assessment_body = {**assessment(), 'observed_at': '2020-01-01T00:00:00Z', 'expires_at': '2020-01-02T00:00:00Z'}
    insights.put_record('assessment', assessment_body, 'admin', validate_assessment)
    evaluation_body = {**evaluation_run(), 'started_at': '2020-01-01T00:00:00Z', 'completed_at': '2020-01-01T00:01:00Z'}
    insights.put_record('evaluation', evaluation_body, 'admin', validate_evaluation)
    names = {'packages.sqlite3', 'cases.sqlite', 'log-access.sqlite', 'dashboards.sqlite', 'dashboard-insights.sqlite'}
    before = snapshot(source, names)
    original_auth_key = (source / 'dashboard-report-auth.key').read_bytes()
    backup_path = tmp_path.parent / (tmp_path.name + '-current-backup')
    restored_path = tmp_path.parent / (tmp_path.name + '-current-restored')
    report = backup.backup(source, backup_path)
    assert report['format'] == 5 and report['missing'] == []
    assert {f['name'] for f in report['files']} == names
    assert {p.name for p in backup_path.iterdir()} == names | {'manifest.json'}
    assert backup.verify(backup_path) == report
    assert backup.restore(backup_path, restored_path) == report
    assert {p.name for p in restored_path.iterdir()} == names | {'manifest.json'}
    assert snapshot(restored_path, names) == before
    assert snapshot(source, names) == before
    assert not (restored_path / 'dashboard-report-auth.key').exists()
    restored = DashboardStore(restored_path / 'dashboards.sqlite')
    assert restored.get('view') == legacy and restored.get('other') == other
    assert restored.collection('view', 'viewer')['dashboards'] == copied['dashboards']
    assert restored.collection('view', 'viewer')['default_id'] == created['selected_id']
    restored_insights = InsightStore(restored_path / 'dashboard-insights.sqlite', clock=lambda: now)
    assert (restored_path / 'dashboard-report-auth.key').read_bytes() != original_auth_key
    assert restored_insights.fleet()['rows'][0]['state'] == 'credential_reset_required'
    with pytest.raises(InsightError, match='authentication_failed'):
        restored_insights.heartbeat(key['credential'], body)
    assert snapshot(restored_path, names) == before
    assert (source / 'dashboard-report-auth.key').read_bytes() == original_auth_key
    assert backup.verify(backup_path) == report


@pytest.mark.parametrize('version', [3, 4])
@pytest.mark.parametrize('artifact', ['current_writer', 'frozen_manifest'])
def test_legacy_dashboard_formats_restore_before_store_initialization(tmp_path, version, artifact):
    source = legacy_source(tmp_path / 'legacy-source', version)
    names = {'packages.sqlite3', 'cases.sqlite', 'log-access.sqlite', 'dashboards.sqlite'}
    before = snapshot(source, names)
    backup_path, restored_path = tmp_path / 'backup', tmp_path / 'restored'
    report = (backup.backup(source, backup_path) if artifact == 'current_writer'
              else legacy_artifact(source, backup_path, version))
    assert report['format'] == version and report['missing'] == []
    assert {f['name'] for f in report['files']} == names
    assert backup.verify(backup_path) == report
    assert backup.restore(backup_path, restored_path) == report
    assert {p.name for p in restored_path.iterdir()} == names | {'manifest.json'}
    assert snapshot(restored_path, names) == before
    assert set(before['dashboards.sqlite']) == ({'dashboards'} if version == 3 else {'dashboards', 'dashboard_collections'})
    store = DashboardStore(restored_path / 'dashboards.sqlite')
    for actor in ('view', 'other'):
        assert store.get(actor) == {'revision': 7, 'layout': legacy_layout(actor)}
        view = store.collection(actor, 'viewer')
        if version == 4:
            assert view['revision'] == 9
            assert view['default_id'] == collection(actor)['default_id']
            assert view['dashboards'] == collection(actor)['dashboards']
        else:
            assert view['revision'] == 0 and view['default_id'] == 'legacy' and view['dashboards'] == []
    assert snapshot(source, names) == before
    assert backup.verify(backup_path) == report
