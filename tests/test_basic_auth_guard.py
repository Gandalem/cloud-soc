"""Shared budgets, expiry, concurrency and unchanged portal access control."""
import base64
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import ProcessPoolExecutor
from contextlib import closing
import json
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from cloud_soc.portal.app import create_app
from cloud_soc.portal.basic_auth import BasicAuthGuard
from cloud_soc.portal.log_access import LogAccessPolicy
from test_portal import ROOT, CA, AUTH, HASH


def process_attempt(path):
    guard = BasicAuthGuard(path, LogAccessPolicy('admin', HASH), clock=lambda: 1000)
    return guard.authenticate('admin', 'invalid-test-password', '192.0.2.1')[1]


class BasicGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'basic.sqlite'
        self.now = 1000
        self.policy = LogAccessPolicy('admin', HASH)
        self.guard = self.make_guard()

    def make_guard(self):
        return BasicAuthGuard(self.path, self.policy, clock=lambda: self.now)

    def bad(self, guard=None, user='admin', peer='192.0.2.1'):
        return (guard or self.guard).authenticate(user, 'invalid-test-password', peer)

    def test_five_failures_limit_restart_instances_and_success_does_not_reset(self):
        for _ in range(3): self.assertEqual(self.bad()[1], 0)
        self.assertIsNotNone(self.guard.authenticate('admin', 'synthetic-test-password', '192.0.2.1')[0])
        for _ in range(2): self.assertEqual(self.bad()[1], 0)
        self.assertEqual(self.bad(self.make_guard()), (None, 300))
        self.assertEqual(self.guard.authenticate('admin', 'synthetic-test-password', '192.0.2.2'), (None, 300))
        self.now += 301
        self.assertIsNotNone(self.guard.authenticate('admin', 'synthetic-test-password', '192.0.2.2')[0])

    def test_parallel_requests_cannot_race_past_failure_budget(self):
        guards = [self.guard, self.make_guard()]
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda i: self.bad(guards[i % 2]), range(12)))
        self.assertEqual(sum(wait == 0 for _, wait in outcomes), 5)
        self.assertEqual(sum(wait > 0 for _, wait in outcomes), 7)

    def test_spawned_processes_share_one_atomic_failure_budget(self):
        with ProcessPoolExecutor(max_workers=3, mp_context=multiprocessing.get_context('spawn')) as pool:
            waits = list(pool.map(process_attempt, [str(self.path)] * 8))
        self.assertEqual(sum(wait == 0 for wait in waits), 5)
        self.assertEqual(sum(wait > 0 for wait in waits), 3)

    def test_unknown_names_and_changing_peers_share_bounded_bucket(self):
        for i in range(5):
            self.assertEqual(self.bad(user=f'unknown-{i}', peer=f'192.0.2.{i}')[1], 0)
        self.assertGreater(self.bad(user='another', peer='198.51.100.1')[1], 0)
        with closing(sqlite3.connect(self.path)) as db:
            rows = db.execute('SELECT bucket FROM failures').fetchall()
        self.assertEqual(len(rows), 7)
        self.assertNotIn('unknown-', json.dumps(rows))

    def test_global_and_peer_limits_cover_distributed_known_names(self):
        self.policy.users = {f'user-{i}': None for i in range(20)}
        self.policy.authenticate = Mock(return_value=None)
        for i in range(10): self.assertEqual(self.bad(user=f'user-{i}')[1], 0)
        self.assertGreater(self.bad(user='user-10')[1], 0)
        for i in range(10, 20): self.assertEqual(self.bad(user=f'user-{i}', peer=f'198.51.100.{i}')[1], 0)
        self.assertGreater(self.bad(user='admin', peer='203.0.113.1')[1], 0)

    def test_peer_storage_growth_is_bounded_even_after_rotating_peers(self):
        # Artificially raise existing budgets to exercise the storage cap itself.
        with closing(sqlite3.connect(self.path)) as db, db:
            for i in range(256):
                db.execute('INSERT INTO failures VALUES(?,1,?)', (f'peer:{i}', self.now + 300))
        self.bad()
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM failures WHERE bucket LIKE 'peer:%'").fetchone()[0], 257)
        self.bad(peer='198.51.100.2')
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT attempts FROM failures WHERE bucket=?', ('peer:overflow',)).fetchone()[0], 2)


class PortalBasicGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.settings = {'STATE_DIR': Path(self.temp.name), 'AGENT_SOURCE': ROOT / 'deploy/agents',
            'CA_BYTES': CA, 'PUBLIC_URL': 'http://localhost', 'ENDPOINT': 'https://soc.example.test:9200',
            'ADMIN_USER': 'admin', 'ADMIN_HASH': HASH}
        self.issuer = Mock()
        self.app = create_app(self.settings, issuer=self.issuer)
        self.client = self.app.test_client()
        self.bad_auth = 'Basic ' + base64.b64encode(b'admin:invalid-test-password').decode()

    def test_basic_auth_spoofed_forwarded_headers_do_not_bypass_and_public_assets_work(self):
        for i in range(5):
            response = self.client.get('/api/keys', headers={'Authorization': self.bad_auth,
                'X-Forwarded-For': f'192.0.2.{i}', 'Forwarded': f'for=192.0.2.{i}'})
            self.assertEqual(response.status_code, 401)
        app2 = create_app(self.settings, issuer=self.issuer)
        response = app2.test_client().get('/api/keys', headers={'Authorization': AUTH})
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response.headers)
        self.assertNotIn('invalid-test-password', response.get_data(as_text=True))
        with self.client.get('/login/styles.css') as public:
            self.assertEqual(public.status_code, 200)

    def test_missing_auth_challenge_is_not_a_guessed_password(self):
        for _ in range(30): self.assertEqual(self.client.get('/api/keys').status_code, 401)
        self.assertEqual(self.client.get('/api/keys', headers={'Authorization': AUTH}).status_code, 200)

    def test_malformed_authorization_is_limited_without_password_check(self):
        for _ in range(5): self.assertEqual(self.client.get('/api/keys', headers={'Authorization': 'Basic bad'}).status_code, 401)
        self.assertEqual(self.client.get('/api/keys', headers={'Authorization': 'Bearer ignored'}).status_code, 429)

    def test_storage_failure_is_closed_and_does_not_contact_issuer(self):
        with patch.object(self.app.extensions['basic_auth'], 'authenticate', side_effect=sqlite3.OperationalError('busy')):
            response = self.client.get('/api/keys', headers={'Authorization': AUTH})
        self.assertEqual(response.status_code, 503)
        self.issuer.security.get_api_key.assert_not_called()

    def test_correct_basic_requests_are_not_rate_limited(self):
        for _ in range(30):
            self.assertEqual(self.client.get('/api/keys', headers={'Authorization': AUTH}).status_code, 200)
