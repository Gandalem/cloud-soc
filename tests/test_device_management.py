"""Focused device lifecycle failures; only disposable state and synthetic issuers."""
import copy
import hashlib
import io
import json
import secrets
import threading
import unittest
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import test_enrollment as enrollment_fixture
from test_enrollment import AGENTS
from cloud_soc.portal.backup import backup, restore, verify
from cloud_soc.portal.app import create_app
from werkzeug.security import generate_password_hash


class Security:
    def __init__(self):
        self.rows = {}
        self.calls = 0
        self.fail_revoke = False

    def create_api_key(self, **kwargs):
        self.calls += 1
        key = {'id': 'synthetic-' + uuid.uuid4().hex, 'api_key': 'TEST_SECRET_' + secrets.token_hex(16),
               'expiration': 2000000000000}
        self.rows[key['id']] = {k: v for k, v in {**kwargs, **key, 'invalidated': False}.items() if k != 'api_key'}
        return key

    def get_api_key(self, **kwargs):
        return {'api_keys': [copy.deepcopy(r) for r in self.rows.values()
                            if r.get('name') == kwargs.get('name') or r['id'] == kwargs.get('id')]}

    def invalidate_api_key(self, **kwargs):
        if self.fail_revoke:
            raise OSError('SYNTHETIC_UPSTREAM_SECRET_MUST_NOT_LEAK')
        invalidated, previous = [], []
        for row in self.rows.values():
            if row.get('name') == kwargs.get('name') or row['id'] in kwargs.get('ids', []):
                (previous if row['invalidated'] else invalidated).append(row['id'])
                row['invalidated'] = True
        return {'invalidated_api_keys': invalidated, 'previously_invalidated_api_keys': previous, 'error_count': 0}


class DeviceManagementTests(unittest.TestCase):
    def setUp(self):
        enrollment_fixture.EnrollmentTests.setUp(self)
        from cloud_soc.portal.windows_native import source_hash
        self.native = self.root / 'native-release'
        self.native.mkdir()
        binary = b'MZ_SYNTHETIC_NOT_AN_EXECUTABLE'
        (self.native / 'cloud-soc-agent-setup.exe').write_bytes(binary)
        self.native_metadata = {'schema': 1, 'target': 'windows-x64-net48', 'mode': 'lab', 'signed': False,
                                'source_sha256': source_hash(self.app.extensions['packages'].source),
                                'sha256': hashlib.sha256(binary).hexdigest()}
        (self.native / 'release.json').write_text(json.dumps(self.native_metadata))
        store = self.app.extensions['packages']
        store.windows_installer_dir = self.native
        store.windows_installer_sha256 = self.native_metadata['sha256']
        store.windows_installer_allow_lab = True
    tearDown = enrollment_fixture.EnrollmentTests.tearDown
    admin = enrollment_fixture.EnrollmentTests.admin
    proof = enrollment_fixture.EnrollmentTests.proof
    machine = enrollment_fixture.EnrollmentTests.machine

    def request(self, action, path, data=None, rid=None):
        return self.client.open(path, method=action, json=data, base_url='https://soc.example.test',
            headers={**self.auth, 'Idempotency-Key': rid or uuid.uuid4().hex})

    def create(self, rid=None, **changes):
        body = {'label': '합성 웹 서버', 'organization': 'school', 'os': 'ubuntu', 'purpose': 'server',
                'network': False, 'system': True, 'sites': [], **changes}
        result = self.request('POST', '/api/managed-devices', body, rid)
        self.assertEqual(result.status_code, 201, result.json)
        return result.json['device'], body

    def prepare(self, device, rid=None, renew=False):
        result = self.request('POST', f"/api/managed-devices/{device['id']}/prepare", {'days': 30, 'renew': renew}, rid)
        self.assertEqual(result.status_code, 200, result.json)
        return result.json['device']

    def handoff(self, device):
        result = self.admin('GET', f"/api/managed-devices/{device['id']}/download")
        self.assertEqual(result.status_code, 200, result.json)
        with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
            if device['os'] == 'windows':
                with zipfile.ZipFile(io.BytesIO(archive.read('package.zip'))) as original:
                    spec = json.loads(original.read('package.json'))
                return json.loads(archive.read('registration.json')), archive.read('cloud-soc-agent-setup.exe'), spec
            return json.loads(archive.read('registration.json')), archive.read('runtime.zip'), json.loads(archive.read('package.json'))

    def test_native_release_guard_fails_before_mint_and_has_no_script_fallback(self):
        device, _ = self.create(os='windows')
        store = self.app.extensions['packages']
        store.windows_installer_sha256 = '0' * 64
        result = self.request('POST', f"/api/managed-devices/{device['id']}/prepare", {'days': 30, 'renew': False})
        self.assertEqual(result.status_code, 503)
        with store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM enrollments').fetchone()[0], 0)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 0)
        store.windows_installer_sha256 = self.native_metadata['sha256']
        self.prepare(device)
        result = self.admin('GET', f"/api/managed-devices/{device['id']}/download")
        with zipfile.ZipFile(io.BytesIO(result.data)) as archive:
            self.assertNotIn('bootstrap-windows.ps1', archive.namelist())
            self.assertNotIn(b'powershell', archive.read('Start.cmd').lower())
            package, original = store.get(device['package_id'], archive=True)
            self.assertEqual(archive.read('package.zip'), original)
            self.assertEqual(json.loads(archive.read('registration.json'))['package_sha256'], package['sha256'])
        (self.native / 'cloud-soc-agent-setup.exe').write_bytes(b'MZ_TAMPERED')
        self.assertEqual(self.admin('GET', f"/api/managed-devices/{device['id']}/download").status_code, 503)

    def test_windows_unsupported_scope_does_not_create_or_issue(self):
        result = self.request('POST', '/api/managed-devices', {'label': '시험', 'organization': 'school',
            'os': 'windows', 'purpose': 'server', 'network': True, 'system': True, 'sites': []})
        self.assertEqual(result.status_code, 400)
        self.assertEqual(self.app.extensions['managed_devices'].listing()['total'], 0)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 0)

    def test_lab_release_and_source_mismatch_are_rejected(self):
        device, _ = self.create(os='windows')
        store = self.app.extensions['packages']
        store.windows_installer_allow_lab = False
        self.assertEqual(self.request('POST', f"/api/managed-devices/{device['id']}/prepare", {'days': 30, 'renew': False}).status_code, 503)
        store.windows_installer_allow_lab = True
        metadata = {**self.native_metadata, 'source_sha256': '0' * 64}
        (self.native / 'release.json').write_text(json.dumps(metadata))
        self.assertEqual(self.request('POST', f"/api/managed-devices/{device['id']}/prepare", {'days': 30, 'renew': False}).status_code, 503)

    def exchange_device(self, device):
        registration, _, spec = self.handoff(device)
        self.token = registration['token']
        self.attempt = secrets.token_urlsafe(32)
        result = self.machine('enroll', {'attempt': self.attempt, 'package_id': spec['package_id'],
                                       'package_sha256': registration['package_sha256']})
        self.assertEqual(result.status_code, 200, result.json)
        return result

    def test_create_is_atomic_idempotent_and_conflicts_preserve_original(self):
        rid = uuid.uuid4().hex
        first, body = self.create(rid)
        second = self.request('POST', '/api/managed-devices', body, rid)
        self.assertEqual(second.json['device']['id'], first['id'])
        self.assertEqual(self.request('POST', '/api/managed-devices', {**body, 'label': '다른 내용'}, rid).status_code, 409)
        self.assertEqual(self.admin('GET', '/api/managed-devices').json['total'], 1)

    def test_concurrent_same_create_yields_one_device_and_package(self):
        rid = uuid.uuid4().hex
        data = {'label': '동시', 'organization': 'school', 'os': 'ubuntu', 'purpose': 'server'}
        devices = self.app.extensions['managed_devices']
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: devices.create('admin', rid, data), range(2)))
        self.assertEqual(results[0]['id'], results[1]['id'])
        self.assertEqual(devices.listing()['total'], 1)

    def test_redownload_keeps_registration_and_common_runtime_across_devices(self):
        one, _ = self.create()
        two, _ = self.create(label='합성 두번째')
        one, two = self.prepare(one), self.prepare(two)
        first, runtime_one, _ = self.handoff(one)
        again, _, _ = self.handoff(self.prepare(one))
        other, runtime_two, _ = self.handoff(two)
        self.assertEqual(first, again)
        self.assertNotEqual(first['token'], other['token'])
        self.assertEqual(runtime_one, runtime_two)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 0)
        public = self.admin('GET', '/api/managed-devices').data
        self.assertNotIn(first['token'].encode(), public)
        self.assertNotIn(first['token'].encode(), (self.root / 'portal/packages.sqlite3').read_bytes())
        with zipfile.ZipFile(io.BytesIO(runtime_one)) as archive:
            self.assertNotIn('package.json', archive.namelist())
            self.assertNotIn('registration.json', archive.namelist())

    def test_expiry_requires_explicit_renewal_and_invalidates_old_token(self):
        device, _ = self.create()
        device = self.prepare(device)
        old, _, _ = self.handoff(device)
        self.now += 1000
        self.assertEqual(self.admin('GET', f"/api/managed-devices/{device['id']}/download").status_code, 409)
        self.assertEqual(self.request('POST', f"/api/managed-devices/{device['id']}/prepare", {'days': 30, 'renew': False}).status_code, 409)
        new, _, _ = self.handoff(self.prepare(device, renew=True))
        self.assertNotEqual(new['token'], old['token'])
        self.token = old['token']
        self.assertEqual(self.machine('enroll', {'attempt': secrets.token_urlsafe(32), 'package_id': device['package_id'],
            'package_sha256': old['package_sha256']}).status_code, 409)

    def test_existing_manual_routes_cannot_issue_or_delete_managed_package(self):
        device, _ = self.create()
        root = '/api/packages/' + device['package_id']
        self.assertEqual(self.admin('POST', root + '/keys', {'days': 1}).status_code, 400)
        self.assertEqual(self.admin('POST', root + '/enrollment', {'days': 1}).status_code, 400)
        self.assertEqual(self.admin('DELETE', root, {}).status_code, 400)

    def test_receipt_then_end_retries_remote_success_after_local_failure(self):
        self.issuer.security = Security()
        device, _ = self.create(os='windows')
        device = self.prepare(device)
        self.exchange_device(device)
        self.proof(host=1)
        self.assertEqual(self.machine('receipt', {'attempt': self.attempt, 'agents': {'host': AGENTS['host']}}).status_code, 200)
        detail = self.admin('GET', '/api/managed-devices/' + device['id']).json['device']
        self.assertEqual(detail['state'], 'received')
        self.assertEqual(detail['analysis_state'], 'unknown')
        rid = uuid.uuid4().hex
        with patch.object(self.app.extensions['packages'], 'mark_revoked', side_effect=OSError('synthetic local failure')):
            result = self.request('POST', f"/api/managed-devices/{device['id']}/end", {'confirm': True}, rid)
        self.assertEqual(result.status_code, 503)
        self.assertTrue(all(r['invalidated'] for r in self.issuer.security.rows.values()))
        self.assertEqual(self.admin('GET', '/api/managed-devices?view=attention').json['total'], 1)
        result = self.request('POST', f"/api/managed-devices/{device['id']}/end", {'confirm': True}, rid)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['device']['state'], 'ended')
        self.assertFalse(result.json['device']['uninstalled'])
        self.assertEqual(self.admin('GET', '/api/managed-devices').json['total'], 0)
        self.assertEqual(self.admin('GET', '/api/managed-devices?view=history').json['total'], 1)
        self.assertEqual(self.admin('GET', '/api/key-history').json['total'], 0)
        self.assertEqual(self.admin('GET', '/api/key-history?view=history').json['total'], 1)
        self.assertEqual(self.issuer.security.calls, 1)

    def test_revocation_failure_is_visible_and_never_leaks_upstream_secret(self):
        self.issuer.security = Security()
        device, _ = self.create()
        self.prepare(device)
        self.exchange_device(device)
        self.issuer.security.fail_revoke = True
        result = self.request('POST', f"/api/managed-devices/{device['id']}/end", {'confirm': True})
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(b'SYNTHETIC_UPSTREAM_SECRET', result.data)
        self.assertEqual(self.admin('GET', '/api/managed-devices?view=history').json['total'], 0)
        self.assertEqual(self.admin('GET', '/api/managed-devices?view=attention').json['total'], 1)

    def test_missing_handoff_key_does_not_reissue_publisher_keys(self):
        device, _ = self.create()
        self.prepare(device)
        (self.root / 'portal/device-transfer.key').unlink()
        self.assertEqual(self.admin('GET', f"/api/managed-devices/{device['id']}/download").status_code, 409)
        self.handoff(self.prepare(device, renew=True))
        self.assertEqual(self.issuer.security.create_api_key.call_count, 0)

    def test_backup_roundtrip_includes_device_state_but_not_handoff_key(self):
        device, _ = self.create()
        self.prepare(device)
        report = backup(self.root / 'portal', self.root / 'device-backup')
        verify(self.root / 'device-backup')
        restore(self.root / 'device-backup', self.root / 'device-restored')
        self.assertFalse((self.root / 'device-backup/device-transfer.key').exists())
        self.assertFalse((self.root / 'device-restored/device-transfer.key').exists())
        counts = next(e['counts'] for e in report['files'] if e['name'] == 'packages.sqlite3')
        self.assertEqual(counts['managed_devices'], 1)
        self.assertEqual(counts['device_transfers'], 1)

    def test_bounded_server_key_search_finds_records_older_than_500(self):
        store = self.app.extensions['packages']
        store.record_keys(self.package['id'], [{'id': f'legacy-{i:04}', 'scope': 'host'} for i in range(520)], target_label='legacy')
        result = self.admin('GET', '/api/key-history?q=legacy-0000').json
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['keys'][0]['id'], 'legacy-0000')
        self.assertEqual(self.admin('GET', '/api/key-history?size=101').status_code, 400)
        self.assertEqual(self.admin('GET', '/api/key-history?page=1&page=2').status_code, 400)

    def test_auth_csrf_and_untrusted_fields_fail_closed(self):
        result = self.client.post('/api/managed-devices', json={}, base_url='https://soc.example.test')
        self.assertEqual(result.status_code, 401)
        result = self.client.post('/api/managed-devices', json={}, base_url='https://soc.example.test',
                                  headers={'Authorization': self.auth['Authorization']})
        self.assertEqual(result.status_code, 403)
        result = self.request('POST', '/api/managed-devices', {'label': 'forged', 'organization': 'school',
                 'os': 'ubuntu', 'purpose': 'server', 'endpoint': 'https://attacker.invalid'})
        self.assertEqual(result.status_code, 400)

    def test_session_viewer_cannot_read_device_secrets_or_manage_and_admin_needs_csrf(self):
        users = self.root / 'users.json'
        password_hash = generate_password_hash('synthetic-password', method='pbkdf2:sha256:1000')
        users.write_text(json.dumps({'admin': {'role': 'admin', 'password_hash': password_hash},
                                     'viewer': {'role': 'viewer', 'password_hash': password_hash}}))
        users.chmod(0o600)
        app = create_app({**self.settings, 'USERS_FILE': str(users)}, issuer=self.issuer, monitor=self.monitor)
        client = app.test_client()
        def login(username):
            return client.post('/api/auth/login', json={'username': username, 'password': 'synthetic-password'},
                base_url='https://soc.example.test', headers={'X-Cloud-SOC': 'portal'})
        self.assertEqual(login('viewer').status_code, 200)
        self.assertEqual(client.get('/api/managed-devices', base_url='https://soc.example.test').status_code, 403)
        self.assertEqual(client.get('/devices.html', base_url='https://soc.example.test').status_code, 403)
        self.assertEqual(login('admin').status_code, 200)
        response = client.post('/api/managed-devices', json={'label': 'blocked'}, base_url='https://soc.example.test',
            headers={'X-Cloud-SOC': 'portal', 'Idempotency-Key': uuid.uuid4().hex})
        self.assertEqual(response.status_code, 403)

    def test_device_and_package_rollback_together_on_local_failure(self):
        store = self.app.extensions['packages']
        original = store.create
        def fail(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError('SYNTHETIC_LOCAL_COMMIT_FAILURE')
        body = {'label': 'rollback', 'organization': 'school', 'os': 'ubuntu', 'purpose': 'server'}
        with patch.object(store, 'create', side_effect=fail):
            with self.assertRaises(OSError):
                self.app.extensions['managed_devices'].create('admin', uuid.uuid4().hex, body)
        self.assertEqual(self.app.extensions['managed_devices'].listing()['total'], 0)
        self.assertEqual(len(store.list()), 1)  # Only the pre-existing synthetic legacy package.

    def test_no_pipeline_means_no_successful_registration_handoff(self):
        device, _ = self.create()
        self.issuer.ingest.get_pipeline.side_effect = OSError('SENSITIVE')
        result = self.request('POST', f"/api/managed-devices/{device['id']}/prepare", {'days': 30, 'renew': False})
        self.assertEqual(result.status_code, 503)
        self.assertNotIn(b'SENSITIVE', result.data)
        self.assertEqual(self.admin('GET', f"/api/managed-devices/{device['id']}/download").status_code, 409)

    def test_end_blocks_racing_registration(self):
        device, _ = self.create()
        self.prepare(device)
        registration, _, spec = self.handoff(device)
        result = self.request('POST', f"/api/managed-devices/{device['id']}/end", {'confirm': True})
        self.assertEqual(result.status_code, 200, result.json)
        self.token = registration['token']
        response = self.machine('enroll', {'attempt': secrets.token_urlsafe(32), 'package_id': spec['package_id'],
                                         'package_sha256': registration['package_sha256']})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 0)

    def test_end_requires_exact_boolean_confirmation(self):
        device, _ = self.create()
        for body in ({'confirm': 1}, {'confirm': 'true'}, {'confirm': False}, {'confirm': True, 'purge': True}):
            self.assertEqual(self.request('POST', f"/api/managed-devices/{device['id']}/end", body).status_code, 400)
        self.assertEqual(self.admin('GET', '/api/managed-devices').json['total'], 1)

    def test_remote_key_of_another_organization_is_not_revoked_by_a_name_match(self):
        self.issuer.security = Security()
        device, _ = self.create()
        self.prepare(device)
        self.exchange_device(device)
        remote = next(iter(self.issuer.security.rows.values()))
        remote['metadata']['organization'] = 'another-organization'
        result = self.request('POST', f"/api/managed-devices/{device['id']}/end", {'confirm': True})
        self.assertEqual(result.status_code, 503)
        self.assertFalse(remote['invalidated'])

    def test_ordinary_activity_requires_exact_binding_and_final_pipeline_and_no_partial_search(self):
        self.issuer.security = Security()
        device, _ = self.create(os='windows')
        self.prepare(device)
        self.exchange_device(device)
        self.proof(host=1)
        self.assertEqual(self.machine('receipt', {'attempt': self.attempt, 'agents': {'host': AGENTS['host']}}).status_code, 200)
        index = 'soc-host-raw-windows-synthetic'
        result = {'timed_out': False, '_shards': {'failed': 0}, 'hits': {'hits': [
            {'_index': index, '_id': 'exact-original', '_source': {'event': {'ingested': '2026-10-23T00:00:00Z'}}}]}}
        self.monitor.search.side_effect = None
        self.monitor.search.return_value = result
        url = f"/api/managed-devices/{device['id']}/activity"
        activity = self.admin('GET', url)
        self.assertEqual(activity.status_code, 200, activity.json)
        self.assertEqual(activity.json['references'], [{'index': index, 'id': 'exact-original', 'scope': 'host'}])
        query = self.monitor.search.call_args.kwargs['query']['bool']
        self.assertIn({'term': {'organization.id': 'school'}}, query['filter'])
        self.assertEqual(query['must_not'], [{'term': {'event.action': 'installation_probe'}}])
        self.monitor.search.return_value = {**result, 'timed_out': True}
        self.assertEqual(self.admin('GET', url).status_code, 503)
        self.monitor.search.return_value = result
        self.monitor.indices.get_settings.side_effect = lambda **k: {k['index']: {'settings': {'index.final_pipeline': 'untrusted'}}}
        self.assertEqual(self.admin('GET', url).status_code, 503)

    def test_suspended_prepare_cannot_publish_after_explicit_renewal(self):
        devices = self.app.extensions['managed_devices']
        device, _ = self.create()
        blocked, release = threading.Event(), threading.Event()
        original = self.service.mint
        first = uuid.uuid4().hex
        def delay(identifier, data, **kwargs):
            if kwargs['sid'] == first:
                blocked.set()
                release.wait(10)
            return original(identifier, data, **kwargs)
        with patch.object(self.service, 'mint', side_effect=delay), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(devices.prepare, 'admin', device['id'], first, {'days': 30, 'renew': False})
            self.assertTrue(blocked.wait(10))
            devices.prepare('admin', device['id'], uuid.uuid4().hex, {'days': 30, 'renew': True})
            release.set()
            with self.assertRaises(Exception):
                future.result()
        handoff, _, _ = self.handoff(device)
        self.assertNotEqual(handoff['enrollment_id'], first)


if __name__ == '__main__':
    unittest.main()
