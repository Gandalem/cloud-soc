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
