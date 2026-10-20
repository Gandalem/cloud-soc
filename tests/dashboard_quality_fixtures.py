"""Private disposable Portal state shared by the targeted quality tests."""
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from werkzeug.security import generate_password_hash

from cloud_soc.portal.app import create_app
from cloud_soc.portal.auth import COOKIE


@pytest.fixture
def portal(tmp_path):
    hashed = generate_password_hash('synthetic-password', method='pbkdf2:sha256:1000')
    users = tmp_path / 'users.json'
    users.write_text(json.dumps({name: {'role': role, 'password_hash': hashed}
                                for name, role in [('admin', 'admin'), ('reader', 'viewer')]}), encoding='utf-8')
    users.chmod(0o600)
    settings = {'STATE_DIR': tmp_path / 'state', 'AGENT_SOURCE': Path(__file__).resolve().parents[1] / 'deploy/agents',
                'CA_BYTES': b'synthetic', 'ENDPOINT': 'https://es.test:9200', 'PUBLIC_URL': 'https://soc.test',
                'ADMIN_USER': 'admin', 'ADMIN_HASH': hashed, 'ES_URL': 'https://es.test:9200',
                'ES_PASSWORD': 'synthetic', 'USERS_FILE': str(users),
                'LOG_ACCESS_POLICY': {'version': 1, 'protected_source_enabled': False,
                    'admin_source_organizations': [], 'users': [{'username': 'reader', 'password_hash': hashed,
                                                               'role': 'viewer', 'organizations': ['org-a']}]}}
    app = create_app(settings, issuer=Mock())
    app.extensions['quality_settings'] = settings
    return app


def session(app, user):
    client = app.test_client()
    token = app.extensions['sessions'].login(user, 'synthetic-password')
    client.set_cookie(COOKIE, token, domain='soc.test')
    return client, {'X-Cloud-SOC': 'portal', 'X-CSRF-Token': app.extensions['sessions'].get(token)['csrf']}


def state_snapshot(store):
    with store.connect() as db:
        return {table: [tuple(row) for row in db.execute('SELECT * FROM ' + table + ' ORDER BY rowid')]
                for table in ('insight_devices', 'insight_reports', 'insight_records', 'insight_requests', 'insight_audit')}
