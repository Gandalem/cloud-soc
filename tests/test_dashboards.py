import json
import sqlite3
from copy import deepcopy
import pytest
from cloud_soc.portal.dashboards import DashboardStore, DEFAULT, DashboardError
from test_integration_security import session_portal as session_portal, login
from cloud_soc.portal.app import create_app
from unittest.mock import Mock


def test_preferences_survive_restart_and_are_private(tmp_path):
    path = tmp_path / 'dashboards.sqlite'
    store = DashboardStore(path)
    layout = deepcopy(DEFAULT)
    layout.update(name='나의 관제', theme='dark', period=60, widgets=[{'id': 'alerts', 'size': 'wide'}])
    assert store.save('viewer', {'revision': 0, 'layout': layout})['revision'] == 1
    assert DashboardStore(path).get('viewer')['layout'] == layout
    assert store.get('other')['revision'] == 0
    with sqlite3.connect(path) as db:
        assert len(db.execute('select * from dashboards').fetchall()) == 1
    with pytest.raises(DashboardError) as conflict:
        store.save('viewer', {'revision': 0, 'layout': DEFAULT})
    assert conflict.value.status == 409
    assert store.get('viewer')['layout'] == layout


@pytest.mark.parametrize('change', [dict(widgets=[]), dict(widgets=[{'id':'unknown','size':'normal'}]),
    dict(widgets=[{'id':'alerts','size':'wide'}]*2), dict(widgets=[{'id':'alerts','size':'wide','url':'https://evil.test'}]),
    dict(period=True), dict(period=5), dict(theme='external'), dict(name=''), dict(name='x'*49),
    dict(name='password=private-canary'), dict(organization='foreign')])
def test_invalid_layout_does_not_replace_saved_config(tmp_path, change):
    store=DashboardStore(tmp_path/'config.sqlite');store.save('a',{'revision':0,'layout':DEFAULT})
    with pytest.raises(DashboardError):store.save('a',{'revision':1,'layout':{**deepcopy(DEFAULT),**change}})
    assert store.get('a')['revision']==1


def test_viewer_saves_only_own_settings_and_requires_csrf(session_portal):
    app, _, _, _ = session_portal
    view, headers = login(app, 'view')
    assert view.get('/dashboard.html').status_code == 200
    assert view.get('/operations.html').status_code == 200
    assert view.get('/api/dashboard?actor=investigate').status_code == 400
    body={'revision':0,'layout':{**deepcopy(DEFAULT),'name':'조회 전용 개인 화면','theme':'dark'}}
    assert view.post('/api/dashboard',json=body,headers={'X-Cloud-SOC':'portal'}).status_code == 403
    assert view.post('/api/dashboard',json=body,headers={**headers,'Origin':'https://evil.test'}).status_code == 403
    assert view.post('/api/dashboard',json={**body,'actor':'admin'},headers=headers).status_code == 400
    assert view.post('/api/dashboard',json=body,headers=headers).status_code == 200
    assert view.get('/api/dashboard').json['layout']['theme']=='dark'
    other, _ = login(app, 'investigate')
    assert other.get('/api/dashboard').json['revision']==0
    assert view.get('/api/detection/history').status_code==403
    assert view.post('/api/cases',json={},headers=headers).status_code==403
    assert view.get('/api/operations').status_code==200
    assert view.get('/api/operations/status').json['coverage']['state']=='unknown'


def test_storage_failures_do_not_claim_saved(session_portal):
    app, _, _, _=session_portal;view,headers=login(app,'view')
    with app.extensions['dashboards'].connect() as db:db.execute('DROP TABLE dashboards')
    assert view.get('/api/dashboard').status_code==503
    assert view.post('/api/dashboard',json={'revision':0,'layout':DEFAULT},headers=headers).status_code==503


def test_settings_contains_only_layout_metadata(tmp_path):
    store=DashboardStore(tmp_path/'store.sqlite');store.save('a',{'revision':0,'layout':DEFAULT})
    assert set(store.get('a'))=={'revision','layout'}
    assert 'source.ip' not in json.dumps(store.get('a'))


def test_legacy_diagnostic_layout_is_readable_and_never_rewritten_on_get(tmp_path):
    store = DashboardStore(tmp_path / 'legacy.sqlite')
    legacy = {**deepcopy(DEFAULT), 'widgets': [
        {'id': 'pipeline', 'size': 'wide'}, {'id': 'processing', 'size': 'normal'},
        {'id': 'alerts', 'size': 'wide'}]}
    store.save('legacy', {'revision': 0, 'layout': legacy})
    assert DashboardStore(store.path).get('legacy') == {'revision': 1, 'layout': legacy}
    assert not {'pipeline', 'processing'} & {w['id'] for w in DEFAULT['widgets']}


def test_application_restart_keeps_saved_layout(session_portal):
    app, monitor, settings, _ = session_portal
    http, headers = login(app, 'view')
    body = {'revision': 0, 'layout': {**deepcopy(DEFAULT), 'name': '재시작 후 유지', 'theme': 'dark'}}
    assert http.post('/api/dashboard', json=body, headers=headers).status_code == 200
    restarted = create_app(settings, issuer=Mock(), monitor=monitor)
    fresh, _ = login(restarted, 'view')
    assert fresh.get('/api/dashboard').json == {'revision': 1, 'layout': body['layout']}
