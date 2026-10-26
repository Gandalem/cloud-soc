"""Focused expiry-only lifecycle contracts; no live endpoints or existing keys."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time
import unittest
from unittest.mock import patch
import uuid

import test_device_management as fixture
from test_enrollment import AGENTS


class Security(fixture.Security):
    def __init__(self):
        super().__init__()
        self.updates = 0
        self.lose_response = False
        self.grants = True

    def create_api_key(self, **kwargs):
        result = super().create_api_key(**kwargs)
        result['expiration'] = self.rows[result['id']]['expiration'] = int(time.time() * 1000) + 86400000
        self.rows[result['id']].update(type='rest', username='issuer', realm='native', limited_by=[{
            'issuer': {'cluster': ['monitor', 'manage_own_api_key'], 'indices': [{
                'names': ['soc-host-raw-linux-*', 'soc-host-raw-windows-*', 'soc-agent-health-*'],
                'privileges': ['auto_configure', 'create_doc']}]}}])
        return result

    def get_api_key(self, **kwargs):
        return super().get_api_key(**kwargs)

    def authenticate(self):
        return {'authentication_type': 'realm', 'username': 'issuer', 'authentication_realm': {'name': 'native'}}

    def has_privileges(self, **kwargs):
        return {'has_all_requested': self.grants}

    def update_api_key(self, *, id, expiration, metadata, role_descriptors):
        self.updates += 1
        assert expiration.endswith('ms')
        self.rows[id].update(expiration=int(time.time() * 1000) + int(expiration[:-2]),
                             metadata=copy.deepcopy(metadata), role_descriptors=copy.deepcopy(role_descriptors))
        if self.lose_response:
            raise OSError('SENSITIVE_UPSTREAM_CANARY')
        return {'updated': True}


class KeyExtensionTests(unittest.TestCase):
    def setUp(self):
        self.env = fixture.DeviceManagementTests()
        self.env.setUp()
        self.addCleanup(self.env.doCleanups)
        self.security = Security()
        self.env.issuer.security = self.security
        self.env.issuer.options.side_effect = lambda **kwargs: self.env.issuer
        self.env.issuer.nodes.stats.side_effect = lambda **kwargs: {'_nodes': {'total': 1, 'successful': 1, 'failed': 0},
            'nodes': {'synthetic-node': {'timestamp': int(time.time() * 1000)}}}
        self.device, _ = self.env.create(os='windows')
        self.env.prepare(self.device)
        self.env.exchange_device(self.device)
        self.env.proof(host=1)
        result = self.env.machine('receipt', {'attempt': self.env.attempt, 'agents': {'host': AGENTS['host']}})
        self.assertEqual(result.status_code, 200, result.json)
        self.key_id = next(iter(self.security.rows))
        self.url = f"/api/managed-devices/{self.device['id']}/key-extension"
        self.service = self.env.app.extensions['managed_devices'].key_extensions
        self.body = {'key_id': self.key_id, 'days': 30}

    def preview(self, rid=None):
        result = self.env.request('POST', self.url + '/preview', self.body, rid)
        self.assertEqual(result.status_code, 200, result.json)
        return result.json['extension']

    def apply(self, operation, confirm=True):
        return self.env.request('POST', self.url + '/' + operation['id'], {'confirm': confirm})

    def test_same_key_remote_cache_audit_and_idempotence(self):
        old = copy.deepcopy(self.security.rows[self.key_id])
        operation = self.preview()
        result = self.apply(operation)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['extension']['state'], 'complete')
        self.assertEqual(result.json['device']['keys'][0]['expiration'], self.security.rows[self.key_id]['expiration'])
        self.assertEqual(self.apply(operation).json['extension'], result.json['extension'])
        self.assertEqual(self.security.updates, 1)
        self.assertEqual(self.security.calls, 1)
        self.assertEqual(old['role_descriptors'], self.security.rows[self.key_id]['role_descriptors'])
        for key in ('package_id', 'organization', 'enrollment_id', 'scope'):
            self.assertEqual(old['metadata'][key], self.security.rows[self.key_id]['metadata'][key])
        with self.env.app.extensions['packages'].connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM device_audit WHERE action='key_extension_complete'").fetchone()[0], 1)
        raw = result.data + self.env.app.extensions['packages'].database.read_bytes()
        self.assertNotIn(b'SENSITIVE_UPSTREAM_CANARY', raw)
        self.env.issuer.options.assert_called_with(max_retries=0, retry_on_timeout=False, request_timeout=5)

    def test_response_loss_reconciles_without_second_relative_update(self):
        operation = self.preview()
        self.security.lose_response = True
        result = self.apply(operation)
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(b'SENSITIVE_UPSTREAM_CANARY', result.data)
        self.assertEqual(self.apply(operation).status_code, 200)
        self.assertEqual(self.security.updates, 1)

    def test_local_completion_failure_rolls_back_cache_and_audit_then_reconciles(self):
        operation = self.preview()
        original = self.service._finish
        def failed(db, row, remote):
            original(db, row, remote)
            raise OSError('SENSITIVE_LOCAL_CANARY')
        with patch.object(self.service, '_finish', side_effect=failed):
            self.assertEqual(self.apply(operation).status_code, 503)
        self.assertEqual(self.env.app.extensions['packages'].key(self.key_id)['expiration'], operation['before_expiration'])
        self.assertEqual(self.apply(operation).status_code, 200)
        self.assertEqual(self.security.updates, 1)

    def test_crash_after_barrier_never_redispatches_after_restart(self):
        operation = self.preview()
        with patch.object(self.service, '_client', side_effect=SystemExit):
            with self.assertRaises(SystemExit):
                self.service.apply('admin', self.device['id'], operation['id'])
        from cloud_soc.portal.key_extension import KeyExtensions
        restarted = KeyExtensions(self.env.app.extensions['managed_devices'])
        with self.assertRaisesRegex(Exception, '확인하지 못했습니다'):
            restarted.apply('admin', self.device['id'], operation['id'])
        self.assertEqual(self.security.updates, 0)
        self.assertEqual(self.apply(operation, False).status_code, 409)

    def test_concurrent_apply_has_one_dispatch(self):
        operation = self.preview()
        def run(_):
            try:
                return self.service.apply('admin', self.device['id'], operation['id'])['state']
            except Exception:
                return 'unconfirmed'
        with ThreadPoolExecutor(max_workers=2) as pool:
            states = list(pool.map(run, range(2)))
        self.assertIn('complete', states)
        self.assertEqual(self.apply(operation).status_code, 200)
        self.assertEqual(self.security.updates, 1)

    def test_request_identity_and_actor_cannot_change(self):
        rid = uuid.uuid4().hex
        operation = self.preview(rid)
        self.body['days'] = 7
        self.assertEqual(self.env.request('POST', self.url + '/preview', self.body, rid).status_code, 409)
        with self.assertRaises(Exception):
            self.service.apply('other-admin', self.device['id'], operation['id'])
        self.assertEqual(self.security.updates, 0)

    def test_cancelled_preview_and_expired_preview_do_not_write(self):
        operation = self.preview()
        self.assertEqual(self.apply(operation, False).status_code, 200)
        self.assertEqual(self.apply(operation).status_code, 409)
        operation = self.preview()
        self.service.clock = lambda: time.time() + 601
        self.assertEqual(self.apply(operation).status_code, 409)
        self.assertEqual(self.security.updates, 0)

    def test_revoked_expired_binding_role_and_snapshot_mismatch_fail_closed(self):
        original = copy.deepcopy(self.security.rows[self.key_id])
        cases = [lambda r: r.update(invalidated=True),
                 lambda r: r.update(expiration=int(time.time() * 1000)-1),
                 lambda r: r['metadata'].update(organization='other-org'),
                 lambda r: r['role_descriptors']['cloud_soc_host']['cluster'].append('manage_own_api_key'),
                 lambda r: r['limited_by'][0]['issuer']['indices'][0].update(privileges=['create_doc'])]
        for change in cases:
            with self.subTest(change=cases.index(change)):
                self.security.rows[self.key_id] = copy.deepcopy(original)
                change(self.security.rows[self.key_id])
                self.assertEqual(self.env.request('POST', self.url+'/preview', self.body).status_code, 409)
        self.assertEqual(self.security.updates, 0)

    def test_current_owner_privilege_reduction_and_auth_failure_fail_closed(self):
        self.security.grants = False
        self.assertEqual(self.env.request('POST', self.url+'/preview', self.body).status_code, 409)
        self.security.grants = True
        with patch.object(self.security, 'authenticate', side_effect=OSError('SENSITIVE_UPSTREAM_CANARY')):
            result = self.env.request('POST', self.url+'/preview', self.body)
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(b'SENSITIVE', result.data)
        self.assertEqual(self.security.updates, 0)

    def test_cross_device_and_manual_keys_cannot_be_extended(self):
        other, _ = self.env.create(organization='other')
        path = f"/api/managed-devices/{other['id']}/key-extension/preview"
        self.assertEqual(self.env.request('POST', path, self.body).status_code, 409)
        self.assertEqual(self.security.updates, 0)

    def test_end_wins_over_preview_and_existing_revocation_still_works(self):
        operation = self.preview()
        result = self.env.request('POST', f"/api/managed-devices/{self.device['id']}/end", {'confirm': True})
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(self.apply(operation).status_code, 409)
        self.assertTrue(self.security.rows[self.key_id]['invalidated'])
        self.assertEqual(self.security.updates, 0)

    def test_csrf_auth_and_unknown_arguments_cannot_reach_issuer(self):
        for headers in ({}, {**self.env.auth, 'Origin': 'https://other.example'},
                        {'Authorization': self.env.auth['Authorization']}):
            response = self.env.client.post(self.url+'/preview', json=self.body,
                base_url='https://soc.example.test', headers=headers)
            self.assertIn(response.status_code, (401, 403))
        self.assertEqual(self.env.request('POST', self.url+'/preview?scope=all', self.body).status_code, 400)
        self.assertEqual(self.security.updates, 0)

    def test_sessions_require_admin_and_matching_csrf(self):
        from cloud_soc.portal.app import create_app
        from cloud_soc.portal.auth import COOKIE
        from werkzeug.security import generate_password_hash
        users = self.env.root/'users.json'
        users.write_text(json.dumps({name: {'role': role, 'password_hash': generate_password_hash('test-password', method='pbkdf2:sha256:1000')}
                                     for name, role in [('admin', 'admin'), ('analyst', 'analyst')]}))
        users.chmod(0o600)
        app = create_app({**self.env.settings, 'USERS_FILE': users}, issuer=self.env.issuer, monitor=self.env.monitor)
        sessions = app.extensions['sessions']
        for name in ('analyst', 'admin'):
            token = sessions.login(name, 'test-password')
            client = app.test_client()
            client.set_cookie(COOKIE, token, domain='soc.example.test')
            headers = {'X-Cloud-SOC': 'portal', 'Idempotency-Key': uuid.uuid4().hex}
            if name == 'analyst':
                headers['X-CSRF-Token'] = sessions.get(token)['csrf']
            response = client.post(self.url+'/preview', json=self.body, base_url='https://soc.example.test', headers=headers)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.security.updates, 0)

    def test_changed_remote_snapshot_and_clock_skew_do_not_dispatch(self):
        self.service.clock = lambda: time.time() + 60
        self.assertEqual(self.env.request('POST', self.url+'/preview', self.body).json['code'], 'key_extension_clock')
        self.service.clock = time.time
        operation = self.preview()
        self.security.rows[self.key_id]['metadata']['changed'] = True
        self.assertEqual(self.apply(operation).status_code, 503)
        self.assertEqual(self.security.updates, 0)
        self.service.clock = lambda: time.time() + 60
        response = self.env.request('POST', self.url+'/preview', self.body)
        self.assertEqual(response.status_code, 409)  # unresolved attempt blocks new reservations

    def test_network_and_unlimited_keys_are_not_supported(self):
        self.security.rows[self.key_id].pop('expiration')
        self.assertEqual(self.env.request('POST', self.url+'/preview', self.body).status_code, 409)
        other, _ = self.env.create(network=True)
        self.env.prepare(other)
        self.env.exchange_device(other)
        other_key = next(k for k, row in self.security.rows.items() if row['metadata']['package_id'] == other['package_id'])
        response = self.env.request('POST', f"/api/managed-devices/{other['id']}/key-extension/preview",
                                    {'key_id': other_key, 'days': 30})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.security.updates, 0)

    def test_partial_node_clock_response_never_dispatches(self):
        self.env.issuer.nodes.stats.side_effect = None
        self.env.issuer.nodes.stats.return_value = {'_nodes': {'total': 2, 'successful': 1, 'failed': 1},
            'nodes': {'one': {'timestamp': int(time.time() * 1000)}}}
        result = self.env.request('POST', self.url+'/preview', self.body)
        self.assertEqual(result.status_code, 503)
        self.assertEqual(self.security.updates, 0)

    def test_end_concurrent_with_extension_revokes_the_extended_key(self):
        operation = self.preview()
        entered, release = threading.Event(), threading.Event()
        original = self.security.update_api_key
        def wait_update(**kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Test coordination timeout')
            return original(**kwargs)
        devices = self.env.app.extensions['managed_devices']
        with patch.object(self.security, 'update_api_key', side_effect=wait_update):
            with ThreadPoolExecutor(max_workers=2) as pool:
                extending = pool.submit(self.service.apply, 'admin', self.device['id'], operation['id'])
                self.assertTrue(entered.wait(5))
                ending = pool.submit(devices.end, 'admin', self.device['id'], uuid.uuid4().hex)
                release.set()
                self.assertEqual(extending.result(timeout=10)['state'], 'complete')
                self.assertEqual(ending.result(timeout=10)['state'], 'ended')
        self.assertTrue(self.security.rows[self.key_id]['invalidated'])
        self.assertEqual(self.security.updates, 1)
