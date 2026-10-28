"""Slack's top-level navigation must not grant cross-site API or write access."""
import pytest
from unittest.mock import Mock

from test_integration_security import make_session_portal, login
from test_portal import AUTH, HASH, ROOT, CA
from cloud_soc.portal.app import create_app

ID = 'a' * 64
PATH = '/workbench.html?alert=' + ID
NAV = {'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate',
       'Sec-Fetch-Dest': 'document', 'Sec-Fetch-User': '?1'}


def test_external_alert_link_requires_login_and_preserves_only_exact_internal_target(tmp_path):
    app, _, _, _ = make_session_portal(tmp_path)
    http = app.test_client()
    for method in ('get', 'head'):
        result = getattr(http, method)(PATH, headers=NAV)
        assert result.status_code == 302 and result.location == '/login?alert=' + ID
        page = getattr(http, method)(result.location, headers=NAV)
        assert page.status_code == 200 and 'text/html' in page.content_type
    assert http.get(PATH).location == '/login?alert=' + ID
    assert http.get('/api/alerts/detail?id=' + ID, headers=NAV).status_code == 403
    assert http.get('/api/alerts/detail?id=' + ID).status_code == 401


def test_html_navigation_keeps_authentication_roles_and_csrf(tmp_path):
    app, _, _, _ = make_session_portal(tmp_path)
    for user in ('admin', 'view', 'investigate'):
        http, headers = login(app, user)
        assert http.get(PATH, headers=NAV).status_code == 200
        for url in ('/api/auth/me', '/api/alerts/detail?id=' + ID, '/api/settings/notifications/slack'):
            assert http.get(url, headers=NAV).status_code == 403
        assert http.post('/api/settings/notifications/slack/test', json={}, headers={**headers, **NAV}).status_code == 403
        assert http.post('/api/settings/notifications/slack/test', json={}, headers={'X-Cloud-SOC': 'portal'}).status_code == 403
        if user != 'admin':
            assert http.get('/api/settings/notifications/slack').status_code == 403


@pytest.mark.parametrize('change', [
    {'Sec-Fetch-Mode': 'cors'}, {'Sec-Fetch-Mode': 'no-cors'}, {'Sec-Fetch-Dest': 'iframe'},
    {'Sec-Fetch-Dest': 'image'}, {'Sec-Fetch-User': ''}, {'Origin': 'https://evil.test'}])
def test_cross_site_fetch_embeds_and_wrong_origin_stay_denied(tmp_path, change):
    app, _, _, _ = make_session_portal(tmp_path)
    assert app.test_client().get(PATH, headers={**NAV, **change}).status_code == 403


@pytest.mark.parametrize('path', ['/workbench.html', '/workbench.html?alert=short',
    PATH + '&alert=' + ID, PATH + '&next=https://evil.test', '/workbench.html?case=' + 'a' * 32,
    '/login?alert=//evil.test', '/settings-slack.html?alert=' + ID, '/logs.html?alert=' + ID])
def test_external_navigation_is_limited_to_allowlisted_html_and_canonical_id(tmp_path, path):
    app, _, _, _ = make_session_portal(tmp_path)
    assert app.test_client().get(path, headers=NAV).status_code == 403


def test_basic_auth_and_host_validation_are_not_bypassed(tmp_path):
    app = create_app({'STATE_DIR': tmp_path, 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': CA,
        'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://example.test:9200',
        'ADMIN_USER': 'admin', 'ADMIN_HASH': HASH}, issuer=Mock())
    http = app.test_client()
    assert http.get(PATH, headers=NAV).status_code == 401
    assert http.get(PATH, headers={**NAV, 'Authorization': AUTH}).status_code == 200
    assert http.get(PATH, base_url='http://evil.test', headers=NAV).status_code == 400


@pytest.mark.parametrize('path', ['/', '/index.html', '/login'])
@pytest.mark.parametrize('method', ['get', 'head'])
def test_external_entry_links_go_to_public_login_without_opening_protected_pages(tmp_path, path, method):
    basic = create_app({'STATE_DIR': tmp_path / 'basic', 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': CA,
        'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://example.test:9200',
        'ADMIN_USER': 'admin', 'ADMIN_HASH': HASH}, issuer=Mock())
    (tmp_path / 'session').mkdir()
    session, _, _, _ = make_session_portal(tmp_path / 'session')
    # Interstitial redirects may omit Sec-Fetch-User; they still only reach
    # the public login document, never authenticated content or APIs.
    nav = {k: v for k, v in NAV.items() if k != 'Sec-Fetch-User'}
    for app in (basic, session):
        for auth in ({}, {'Authorization': AUTH} if app is basic else {}):
            http = app.test_client()
            result = getattr(http, method)(path, headers={**nav, **auth})
            assert result.status_code == (200 if path == '/login' else 302)
            if path != '/login':
                assert result.location == '/login'
            followed = getattr(http, method)(path, headers={**nav, **auth}, follow_redirects=True)
            assert followed.status_code == 200
            if method == 'get':
                assert 'id="login-form"' in followed.get_data(as_text=True)
                assert 'id="app-shell"' not in followed.get_data(as_text=True)
    http = basic.test_client()
    assert http.get('/').status_code == 401
    assert http.get('/', headers={'Authorization': AUTH, 'Sec-Fetch-Site': 'same-origin'}).status_code == 200
    assert http.get('/api/auth/me').status_code == 401


@pytest.mark.parametrize('change', [
    {'Sec-Fetch-Mode': 'cors'}, {'Sec-Fetch-Mode': 'no-cors'}, {'Sec-Fetch-Mode': ''},
    {'Sec-Fetch-Dest': 'iframe'}, {'Sec-Fetch-Dest': 'image'}, {'Sec-Fetch-Dest': ''},
    {'Origin': 'https://evil.test'}])
def test_entry_links_do_not_exempt_fetches_embeds_or_foreign_origins(tmp_path, change):
    app, _, _, _ = make_session_portal(tmp_path)
    http, _ = login(app, 'admin')
    for path in ('/', '/index.html', '/login'):
        assert http.get(path, headers={**NAV, **change}).status_code == 403


def test_entry_redirect_cannot_open_queries_apis_or_cross_site_changes(tmp_path):
    app, _, _, _ = make_session_portal(tmp_path)
    http, headers = login(app, 'admin')
    for path in ('/?next=https://evil.test', '/index.html?next=/', '/login?next=/',
                 '/agents.html', '/logs.html', '/api/auth/me', '/api/auth/config', '/api/packages'):
        assert http.get(path, headers=NAV).status_code == 403
    assert http.get('/login', base_url='http://evil.test', headers=NAV).status_code == 400
    for path in ('/', '/index.html', '/login', '/api/auth/login', '/api/packages'):
        assert http.post(path, json={}, headers={**headers, **NAV}).status_code == 403


def test_explicit_dns_alias_requires_auth_and_exact_request_origin(tmp_path):
    app = create_app({'STATE_DIR': tmp_path, 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': CA,
        'PUBLIC_URL': 'https://public.ngrok-free.app', 'ADDITIONAL_ORIGINS': ['https://soc.example.test'],
        'ENDPOINT': 'https://receiver.test:9200', 'ADMIN_USER': 'admin', 'ADMIN_HASH': HASH}, issuer=Mock())
    http = app.test_client()
    assert http.get('/api/auth/me', base_url='https://soc.example.test').status_code == 401
    headers = {'Authorization': AUTH, 'Origin': 'https://soc.example.test'}
    assert http.get('/api/auth/me', base_url='https://soc.example.test', headers=headers).status_code == 200
    assert http.get('/api/auth/me', base_url='https://soc.example.test',
        headers={**headers, 'Origin': 'https://public.ngrok-free.app'}).status_code == 403
    assert http.get('/api/auth/me', base_url='https://evil.test', headers=headers).status_code == 400
    assert http.get('/api/auth/me', base_url='https://soc.example.test', headers={**headers, **NAV}).status_code == 403
    assert http.post('/api/auth/me', base_url='https://soc.example.test', json={}, headers=headers).status_code == 403
