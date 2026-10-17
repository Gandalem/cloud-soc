"""Console lifecycle tests use synthetic credentials and transports only."""
import base64
from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'deploy/security-mall'
sys.path.insert(0, str(DIRECTORY))
spec = importlib.util.spec_from_file_location('validation_console', DIRECTORY / 'run_validation_console.py')
console = importlib.util.module_from_spec(spec);spec.loader.exec_module(console)
sys.path.pop(0)


def request_body():
    return json.loads((DIRECTORY / 'validation-read-key.request.example.json').read_text())


def key():
    return {'id': 'new-test-only', 'encoded': base64.b64encode(b'new-test-only:FAKE_SECRET').decode(),
            'expiration': int(time.time() * 1000) + 7200000}


class Issuer:
    owned_id = None
    def __init__(self, *, granted=True, cleanup=True, role=True):
        self.calls = [];self.key = key();self.granted = granted;self.cleanup = cleanup;self.role = role
    def call(self, method, path, body=None):
        self.calls.append((method, path, body))
        if path.endswith('_has_privileges'): return 200, {'has_all_requested': self.granted}
        if method == 'POST': return 200, self.key
        if method == 'GET':
            roles = request_body()['role_descriptors'] if self.role else {}
            return 200, {'api_keys': [dict(self.key, invalidated=False, role_descriptors=roles)]}
        if self.cleanup: return 200, {'error_count': 0, 'invalidated_api_keys': [self.owned_id]}
        return 403, None


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'lab';self.directory = self.base / 'validation-7ab/secrets'
        self.directory.mkdir(parents=True, mode=0o700)
        self.path = self.directory / 'reader-test.json'

    def run_lifecycle(self, issuer, cli_code=0, probe_status=401, save_failure=False):
        report = {}
        def save(path, value):
            if save_failure: raise OSError('PRIVATE_FAKE_ERROR')
            path.write_text(json.dumps(value));path.chmod(0o600)
        class Probe:
            def __init__(self, auth, ca): pass
            def call(self, *args): return probe_status, None
        original_lstat = Path.lstat
        def windows_mode(path, *args, **kwargs):
            info = original_lstat(path, *args, **kwargs)
            if path != self.path: return info
            values = list(info);values[0] = (info.st_mode & ~0o777) | 0o600
            return os.stat_result(values)
        with patch.object(console, 'private_save', side_effect=save), \
                patch.object(console.validation, 'validation_credential', return_value=issuer.key), \
                patch.object(console, 'Transport', Probe), \
                (patch.object(Path, 'lstat', windows_mode) if os.name == 'nt' else nullcontext()), \
                patch.object(console.os, 'getuid', return_value=self.path.stat().st_uid if self.path.exists() else os.stat(self.directory).st_uid, create=True):
            code = console.lifecycle(issuer, 'unused-ca', self.path, request_body(), lambda: cli_code, report)
        return code, report

    def test_success_and_cli_failure_both_revoke_only_new_id(self):
        for cli in (0, 1, 4):
            with self.subTest(cli=cli):
                issuer = Issuer();code, report = self.run_lifecycle(issuer, cli)
                self.assertEqual(code, 0 if cli == 0 else 1)
                self.assertTrue(report['key_invalidated'] and report['revoked_key_rejected_401'] and report['secret_removed'])
                self.assertFalse(self.path.exists())
                deletes = [call for call in issuer.calls if call[0] == 'DELETE']
                self.assertEqual(deletes, [('DELETE', '/_security/api_key', {'ids': [issuer.key['id']]})])

    def test_issuer_permission_denied_never_creates_key(self):
        issuer = Issuer(granted=False);code, report = self.run_lifecycle(issuer)
        self.assertEqual(code, 1);self.assertEqual(report['reason'], 'issuer_permission_missing')
        self.assertEqual(len(issuer.calls), 1);self.assertFalse(self.path.exists())

    def test_revoke_failure_and_missing_401_preserve_secret(self):
        for cleanup, status in [(False, 401), (True, 200)]:
            with self.subTest(cleanup=cleanup, status=status):
                issuer = Issuer(cleanup=cleanup);code, report = self.run_lifecycle(issuer, probe_status=status)
                self.assertEqual(code, 1);self.assertTrue(report['cleanup_failed'])
                self.assertTrue(self.path.exists());self.path.unlink()
                self.assertNotIn('FAKE_SECRET', json.dumps(report))

    def test_save_failure_or_role_mismatch_still_attempts_cleanup(self):
        for save_failure in (False, True):
            with self.subTest(save_failure=save_failure):
                issuer = Issuer(role=False);code, report = self.run_lifecycle(issuer, save_failure=save_failure)
                self.assertEqual(code, 1);self.assertTrue(report['key_invalidated'])
                self.assertTrue(any(c[0] == 'DELETE' for c in issuer.calls))
                self.assertNotIn('PRIVATE_FAKE_ERROR', json.dumps(report))

    def test_console_transport_forbids_documents_and_other_key_deletion(self):
        client = console.Transport.__new__(console.Transport);client.owned_id = 'new-test-only'
        for method, path, body in [('DELETE', '/_security/api_key', {'ids': ['existing-key']}),
                                  ('GET', '/_security/api_key?id=existing-key', None),
                                  ('POST', '/raw/_search', {}), ('PUT', '/x/_doc/id', {})]:
            with self.subTest(method=method, path=path), self.assertRaisesRegex(console.ConsoleError, 'console_operation_forbidden'):
                client.call(method, path, body)

    def test_actual_cli_without_terminal_fails_before_authentication(self):
        result = subprocess.run([sys.executable, str(DIRECTORY / 'run_validation_console.py'),
            '--start', '2026-10-16T00:00:00Z', '--end', '2026-10-17T00:00:00Z'],
            capture_output=True, text=True, timeout=20, env=dict(os.environ, PYTHONPATH=str(ROOT / 'src')))
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report['reason'], 'interactive_vm_console_required')
        self.assertFalse(report['key_issued']);self.assertNotIn('Traceback', result.stderr)

    def test_snapshot_accepts_only_exact_ipv4_and_mapped_loopback(self):
        for address in ('127.0.0.1:18080', '[::ffff:127.0.0.1]:18080', '0.0.0.0:18080',
                        '[::]:18080', '192.0.2.1:18080', '127.0.0.11:18080'):
            def execute(command, **kwargs):
                text = ('LISTEN 0 100 ' + address + ' *:* users:(("java",pid=123,fd=11))\n'
                        if command[0] == '/usr/bin/ss' else
                        'MainPID=456\nActiveState=active\nSubState=running\nInvocationID=test\nNRestarts=0\n')
                return subprocess.CompletedProcess(command, 0, stdout=text, stderr='')
            with self.subTest(address=address), patch.object(console.subprocess, 'run', side_effect=execute), \
                    patch.object(Path, 'read_text', return_value='123 (java) ' + ' '.join(['S'] * 19 + ['999'])):
                if address in ('127.0.0.1:18080', '[::ffff:127.0.0.1]:18080'):
                    self.assertEqual(console.snapshot()['mall'], {'pid': 123, 'start': '999'})
                else:
                    with self.assertRaisesRegex(console.ConsoleError, 'mall_identity_unavailable'): console.snapshot()

    def test_structured_listener_normalizes_ipv4_mapped_address(self):
        for address in ('127.0.0.1:18080', '[::ffff:127.0.0.1]:18080',
                        '[0:0:0:0:0:ffff:7f00:1]:18080'):
            with self.subTest(address=address):
                row = f'LISTEN 0 100 {address} *:* users:(("java",pid=674554,fd=11))\n'
                self.assertEqual(console.mall_listener(subprocess.CompletedProcess([], 0, stdout=row)), 674554)

    def test_listener_rejects_wrong_endpoint_pid_mixed_bindings_and_ss_failure(self):
        def row(address='127.0.0.1:18080', users='users:(("java",pid=123,fd=11))'):
            return f'LISTEN 0 100 {address} *:* {users}\n'
        bad = [(0, row(address)) for address in ('0.0.0.0:18080', '[::]:18080', '[::1]:18080',
               '192.0.2.1:18080', '127.0.0.2:18080', '127.0.0.1:18081', '[::ffff:127.0.0.1]:18081',
               '[::ffff:127.0.0.1%lo]:18080', '[bad]:18080', '127.0.0.1:service')]
        bad += [(0, row(users='')), (0, row(users='users:(("java",pid=123,fd=11),("java",pid=124,fd=11))')),
                (0, row(users='users:(("java",pid=0,fd=11))')),
                (0, row() + row('0.0.0.0:18080')), (0, row() + row('[::ffff:127.0.0.1]:18080')),
                (1, row()), (1, ''), (0, '')]
        for number, (code, text) in enumerate(bad):
            with self.subTest(case=number), self.assertRaisesRegex(console.ConsoleError, '^mall_identity_unavailable$'):
                console.mall_listener(subprocess.CompletedProcess([], code, stdout=text))

    def test_proc_identity_missing_mismatched_or_invalid_start_fails(self):
        def execute(command, **kwargs):
            text = ('LISTEN 0 100 127.0.0.1:18080 *:* users:(("java",pid=123,fd=11))\n'
                    if command[0] == '/usr/bin/ss' else
                    'MainPID=456\nActiveState=active\nSubState=running\nInvocationID=test\nNRestarts=0\n')
            return subprocess.CompletedProcess(command, 0, stdout=text, stderr='')
        cases = [FileNotFoundError('FAKE'), 'invalid', '124 (java) ' + ' '.join(['S'] * 19 + ['999']),
                 '123 (java) ' + ' '.join(['S'] * 19 + ['0']), '123 (java) ' + ' '.join(['S'] * 20)]
        for number, value in enumerate(cases):
            reader = patch.object(Path, 'read_text', side_effect=value) if isinstance(value, Exception) else patch.object(Path, 'read_text', return_value=value)
            with self.subTest(case=number), patch.object(console.subprocess, 'run', side_effect=execute), reader, \
                    self.assertRaisesRegex(console.ConsoleError, '^mall_identity_unavailable$'):
                console.snapshot()

    @unittest.skipUnless(os.name == 'posix', 'real main Linux guard; no authentication or ES transport')
    def test_main_detects_same_pid_with_changed_process_start(self):
        before = {'mall': {'pid': 123, 'start': '999'}}
        after = {'mall': {'pid': 123, 'start': '1000'}}
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY)
        with patch.object(console, 'BASE', self.base), \
                patch.object(sys.stdin, 'isatty', return_value=True), patch.object(sys.stderr, 'isatty', return_value=True), \
                patch.object(console, 'verify_manifest', return_value='fake'), \
                patch.object(console.validation, 'plan'), patch.object(console, 'private_directory', return_value=fd), \
                patch.object(console, 'private_save'), patch.object(console, 'payload', return_value={}), \
                patch.object(console, 'snapshot', side_effect=[before, after]), \
                patch.object(console.getpass, 'getpass', side_effect=['fake-user', 'fake-password']), \
                patch.object(console, 'Transport'), patch.object(console, 'lifecycle', return_value=0), \
                patch('sys.stdout', new_callable=io.StringIO) as output:
            result = console.main(['--start', '2026-10-16T00:00:00Z', '--end', '2026-10-17T00:00:00Z'])
        self.assertEqual(result, 1)
        report = json.loads(output.getvalue())
        self.assertFalse(report['services_unchanged']);self.assertFalse(report['integration_complete'])

    @unittest.skipUnless(os.name == 'posix', 'actual Linux exclusive-file creation')
    def test_linux_private_save_modes_symlink_and_overwrite_rejection(self):
        with patch.object(console, 'BASE', self.base):
            console.private_save(self.path, key())
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError): console.private_save(self.path, key())
            link = self.directory / 'reader-link.json';link.symlink_to(self.path)
            with self.assertRaises(FileExistsError): console.private_save(link, key())
            self.assertEqual(json.loads(self.path.read_text())['id'], 'new-test-only')


if __name__ == '__main__':
    unittest.main()
