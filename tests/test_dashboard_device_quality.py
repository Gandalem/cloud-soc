"""Authenticated device requests and durable state after each rejection."""
from copy import deepcopy
from datetime import datetime, timezone
import json

import pytest

from cloud_soc.portal.insight_state import InsightError
import dashboard_quality_fixtures as fixtures

portal = fixtures.portal
state_snapshot = fixtures.state_snapshot


@pytest.fixture
def device(portal):
    now = [1900000000]
    store = portal.extensions['insights']
    store.clock = lambda: now[0]
    key = store.register({'request_id': 'new-device', 'organization': 'org-a', 'label': 'synthetic',
                          'interval': 30, 'days': 1}, 'admin')
    body = {'generation': key['generation'], 'sequence': 1,
            'generated_at': datetime.fromtimestamp(now[0], timezone.utc).isoformat(),
            'collector': {'state': 'running', 'queue_events': 0, 'output_failed': 0}}
    return store, now, key, body


def post(app, key, body, *, url='https://soc.test', peer='192.0.2.20', headers=None, path='/api/dashboard-heartbeat'):
    values = {'X-Cloud-SOC': 'heartbeat', 'Authorization': 'Bearer ' + key['credential']}
    values.update(headers or {})
    return app.test_client().post(path, json=body, base_url=url, headers=values,
                                 environ_overrides={'REMOTE_ADDR': peer})


def test_valid_device_https_report_commits_exact_binding(portal, device):
    store, now, key, body = device
    response = post(portal, key, body)
    assert response.status_code == 200 and response.json == {'accepted': True, 'duplicate': False, 'received_at': now[0]}
    row = store.fleet()['rows'][0]
    assert row['organization'] == 'org-a' and row['id'] == key['id'] and row['state'] == 'reporting'
    assert row['collector'] == body['collector']
    before = state_snapshot(store)
    now[0] += 5
    repeated = post(portal, key, body)
    assert repeated.status_code == 200 and repeated.json['duplicate'] is True
    assert repeated.json['received_at'] == now[0] - 5
    assert state_snapshot(store) == before
    assert key['credential'] not in json.dumps(row)


@pytest.mark.parametrize('case', ['http', 'untrusted_proxy', 'wrong_key', 'wrong_generation', 'browser_origin', 'query', 'binding_forgery'])
def test_one_invalid_request_boundary_cannot_update_report(portal, device, case):
    store, _, key, body = device
    assert post(portal, key, body).status_code == 200
    body = {**body, 'sequence': 2}
    before = state_snapshot(store)
    kwargs = {}
    expected = 401
    if case in ('http', 'untrusted_proxy'):
        kwargs['url'] = 'http://soc.test'
        expected = 503
        if case == 'untrusted_proxy':
            portal.extensions['quality_settings']['HEARTBEAT_TLS_PROXIES'] = ('192.0.2.30',)
            kwargs['headers'] = {'X-Forwarded-Proto': 'https'}
    elif case == 'wrong_key':
        key = {**key, 'credential': key['id'] + '.' + 'Z' * 43}
    elif case == 'wrong_generation':
        body['generation'] = '0' * 32
    elif case == 'browser_origin':
        kwargs['headers'] = {'Origin': 'https://soc.test'}
        expected = 403
    elif case == 'query':
        kwargs['path'] = '/api/dashboard-heartbeat?organization=org-b'
        expected = 403
    else:
        body['organization'] = 'org-b'
        expected = 400
    response = post(portal, key, body, **kwargs)
    assert response.status_code == expected
    assert state_snapshot(store) == before
    assert key['credential'] not in response.get_data(as_text=True)


def test_only_explicit_trusted_tls_proxy_can_report_over_internal_http(portal, device):
    _, _, key, body = device
    portal.extensions['quality_settings']['HEARTBEAT_TLS_PROXIES'] = ('192.0.2.30',)
    response = post(portal, key, body, url='http://soc.test', peer='192.0.2.30', headers={'X-Forwarded-Proto': 'https'})
    assert response.status_code == 200 and response.json['accepted'] is True


@pytest.mark.parametrize('action', ['pause', 'revoke', 'rotate', 'expire'])
def test_lifecycle_rejection_retains_last_report(portal, device, action):
    store, now, key, body = device
    assert post(portal, key, body).status_code == 200
    if action == 'expire':
        now[0] = key['expires']
    else:
        store.change_device(key['id'], {'action': action, 'version': 1, **({'days': 1} if action == 'rotate' else {})}, 'admin')
    before = state_snapshot(store)
    body.update(sequence=2, generated_at=datetime.fromtimestamp(now[0], timezone.utc).isoformat())
    assert post(portal, key, body).status_code == 401
    assert state_snapshot(store) == before


@pytest.mark.parametrize(('age', 'accepted'), [(-61, False), (-60, True), (90, True), (91, False)])
def test_generated_time_boundaries_are_explicit(portal, device, age, accepted):
    store, now, key, body = device
    body['generated_at'] = datetime.fromtimestamp(now[0] - age, timezone.utc).isoformat()
    before = state_snapshot(store)
    response = post(portal, key, body)
    assert response.status_code == (200 if accepted else 409)
    if not accepted:
        assert state_snapshot(store) == before


@pytest.mark.parametrize('conflict', ['lower_sequence', 'changed_payload'])
def test_conflicting_reports_do_not_replace_prior_success(portal, device, conflict):
    store, _, key, body = device
    body['sequence'] = 2
    assert post(portal, key, body).status_code == 200
    changed = deepcopy(body)
    if conflict == 'lower_sequence':
        changed['sequence'] = 1
    else:
        changed['collector']['state'] = 'stopped'
    before = state_snapshot(store)
    response = post(portal, key, changed)
    assert response.status_code == 409
    assert state_snapshot(store) == before


def test_report_write_failure_rolls_back_then_same_request_recovers(portal, device):
    store, _, key, body = device
    assert post(portal, key, body).status_code == 200
    with store.connect() as db:
        db.execute("CREATE TRIGGER reject_report BEFORE INSERT ON insight_reports BEGIN SELECT RAISE(ABORT,'synthetic'); END")
    before = state_snapshot(store)
    body['sequence'] = 2
    failed = post(portal, key, body)
    assert failed.status_code == 503 and key['credential'] not in failed.get_data(as_text=True)
    assert state_snapshot(store) == before
    with store.connect() as db:
        db.execute('DROP TRIGGER reject_report')
    assert post(portal, key, body).status_code == 200
    assert state_snapshot(store)['insight_reports'][0][2] == 2


def test_database_unavailable_is_not_authentication_success(portal, device, monkeypatch):
    store, _, key, body = device
    def fail():
        raise InsightError('state_unavailable', 503)
    monkeypatch.setattr(store, 'connect', fail)
    response = post(portal, key, body)
    assert response.status_code == 503 and response.json.get('accepted') is not True
