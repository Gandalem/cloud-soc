"""The optional browser fixture uses local stores and mock collectors only."""
from preview_portal_ux import URL, build


def test_preview_keeps_real_login_and_reports_synthetic_data(tmp_path):
    app = build(tmp_path)
    with app.test_client() as client:
        assert client.get('/api/portal', base_url=URL).status_code == 401
        assert client.get('/login/styles.css', base_url=URL).status_code == 200
        response = client.post('/api/auth/login', json={'username': 'admin', 'password': 'synthetic-password'},
                               headers={'X-Cloud-SOC': 'portal'}, base_url=URL)
        assert response.status_code == 200
        assert client.get('/api/auth/me', base_url=URL).json['role'] == 'admin'
        for path in ('/', '/dashboard.html', '/operations.html', '/agents.html', '/logs.html', '/cases.html', '/workbench.html',
                     '/collection-health.html', '/agent-status.html', '/detection-history.html', '/reprocessing-history.html'):
            response = client.get(path, base_url=URL)
            assert response.status_code == 200, path
            assert '운영 데이터 아님' in response.get_data(as_text=True)
        for path in ('/api/operations', '/api/operations/status', '/api/logs', '/api/agents/status', '/api/agents/health',
                     '/api/detection/history', '/api/reprocessing/history', '/api/cases', '/api/portal'):
            response = client.get(path, base_url=URL)
            assert response.status_code == 200, (path, response.get_data(as_text=True))
            assert response.is_json


def test_preview_blocked_and_catching_up_do_not_invent_healthy_coverage(tmp_path):
    app = build(tmp_path)
    with app.test_client() as client:
        client.post('/api/auth/login', json={'username': 'admin', 'password': 'synthetic-password'},
                    headers={'X-Cloud-SOC': 'portal'}, base_url=URL)
        for scenario, state in [('blocked', 'blocked'), ('catching_up', 'catching_up')]:
            client.get('/__fixture/scenario?value=' + scenario, base_url=URL)
            assert client.get('/api/operations/status', base_url=URL).json['coverage']['state'] == state
            rows = client.get('/api/detection/history?kind=runs&view=summary', base_url=URL).json['rows']
            assert len(rows) == 12
            assert all(row['counts']['input_events'] == 0 for row in rows)


def test_preview_basic_login_exposes_only_working_browser_auth_flow(tmp_path):
    app = build(tmp_path, session_login=False)
    with app.test_client() as client:
        assert client.get('/api/auth/config', base_url=URL).json == {'mode': 'basic'}
        assert client.get('/login', base_url=URL).status_code == 200
        assert client.get('/', base_url=URL).status_code == 401
