"""Global replay history stays administrator-only at the actual request boundary."""

import pytest

from cloud_soc.portal.app import create_app
from test_reprocessing_history import fake
from test_integration_security import make_session_portal, login


@pytest.mark.parametrize('user', ['investigate', 'view', 'other'])
def test_scoped_session_cannot_read_foreign_history_metadata(tmp_path, user):
    _, _, settings, _ = make_session_portal(tmp_path)
    monitor = fake()
    monitor.search.return_value['hits']['hits'][0]['_source']['organization'] = {'id': 'foreign'}
    app = create_app(settings, issuer=monitor, monitor=monitor)
    http, _ = login(app, user)
    response = http.get('/api/reprocessing/history')
    assert response.status_code == 403
    assert 'test-host' not in response.get_data(as_text=True)
    monitor.indices.get_mapping.assert_not_called()
    monitor.search.assert_not_called()


def test_admin_can_read_global_history_without_granting_scoped_roles(tmp_path):
    _, _, settings, _ = make_session_portal(tmp_path)
    monitor = fake()
    app = create_app(settings, issuer=monitor, monitor=monitor)
    http, _ = login(app, 'admin')
    response = http.get('/api/reprocessing/history')
    assert response.status_code == 200 and len(response.json['rows']) == 1
    assert monitor.search.call_args.kwargs['query'] == {'match_all': {}}
