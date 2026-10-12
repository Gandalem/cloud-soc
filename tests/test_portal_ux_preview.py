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
        for path in ('/', '/agents.html', '/logs.html', '/cases.html', '/workbench.html',
                     '/collection-health.html', '/agent-status.html', '/detection-history.html', '/reprocessing-history.html'):
            response = client.get(path, base_url=URL)
            assert response.status_code == 200, path
            assert '운영 데이터 아님' in response.get_data(as_text=True)
        for path in ('/api/operations', '/api/logs', '/api/agents/status', '/api/agents/health',
                     '/api/detection/history', '/api/reprocessing/history', '/api/cases', '/api/portal'):
            response = client.get(path, base_url=URL)
            assert response.status_code == 200, (path, response.get_data(as_text=True))
            assert response.is_json
