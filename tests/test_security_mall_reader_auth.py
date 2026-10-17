"""Synthetic credentials/ES only. Standard library tests also run on Linux without pytest."""
import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error

FILE = Path(__file__).resolve().parents[1] / 'deploy/security-mall/validate_correlation_triage.py'
spec = importlib.util.spec_from_file_location('reader_auth_tool', FILE)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
CANARY = 'SYNTHETIC_SECRET_NEVER_PRINT'


def credential():
    return {'id': 'test-id', 'encoded': base64.b64encode(('test-id:' + CANARY).encode()).decode(),
            'expiration': int(time.time() * 1000) + 7200000}


def grants():
    return {'cluster': [], 'global': [], 'applications': [], 'run_as': [], 'indices': [{
        'names': list(tool.APPROVED_INDICES), 'privileges': ['read', 'view_index_metadata'],
        'allow_restricted_indices': False}]}


def assigned_grants():
    role = grants();role.pop('global')
    return {'api_keys': [{'id': 'test-id', 'invalidated': False, 'expiration': credential()['expiration'],
                         'role_descriptors': {'mall_7ab_validation_reader': role}}]}


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'lab'
        self.directory = self.base / 'validation-7ab/secrets'
        self.directory.mkdir(mode=0o700, parents=True)
        self.key = self.directory / 'reader-test.json'
        self.key.write_text(json.dumps(credential()), encoding='utf-8')
        self.key.chmod(0o600)
        self.base_patch = patch.object(tool, 'BASE', self.base)
        self.base_patch.start();self.addCleanup(self.base_patch.stop)

    def reader(self):
        with patch.object(tool, 'validation_credential', return_value=credential()), \
                patch.object(tool.ssl, 'create_default_context', return_value=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)):
            return tool.Reader(self.key, self.base / 'ca.crt')

    def test_path_is_explicit_and_service_files_are_forbidden(self):
        for path in [self.base / 'portal-lab/config/es-read-api-key', self.base / 'collection-services/secrets/key.json',
                     Path('reader-test.json'), self.directory / '../reader-test.json', self.directory / 'key.json']:
            with self.subTest(path_kind=path.name), self.assertRaisesRegex(tool.ValidationError, 'reader_path_forbidden'):
                tool.validation_credential(path)

    @unittest.skipUnless(os.name == 'posix', 'actual UID/mode/openat checks require Linux')
    def test_linux_valid_file_and_missing_file(self):
        self.assertEqual(tool.validation_credential(self.key), credential() | {'expiration': json.loads(self.key.read_text())['expiration']})
        with self.assertRaisesRegex(tool.ValidationError, 'reader_file_missing'):
            tool.validation_credential(self.directory / 'reader-absent.json')

    @unittest.skipUnless(os.name == 'posix', 'actual UID/mode/openat checks require Linux')
    def test_linux_permissions_owner_symlinks_and_hardlinks(self):
        for mode in [0o644, 0o640, 0o400, 0o660]:
            self.key.chmod(mode)
            with self.subTest(file_mode=mode), self.assertRaisesRegex(tool.ValidationError, 'reader_file_permissions'):
                tool.validation_credential(self.key)
        self.key.chmod(0o600);self.directory.chmod(0o750)
        with self.assertRaisesRegex(tool.ValidationError, 'reader_directory_permissions'):
            tool.validation_credential(self.key)
        self.directory.chmod(0o700)
        original_fstat = os.fstat
        def wrong_owner(fd):
            info = original_fstat(fd)
            values = list(info);values[4] = os.getuid() + 1
            return os.stat_result(values)
        with patch.object(tool.os, 'fstat', side_effect=wrong_owner), self.assertRaisesRegex(tool.ValidationError, 'reader_directory_permissions'):
            tool.validation_credential(self.key)
        def wrong_file_owner(fd):
            info = original_fstat(fd)
            if not tool.stat.S_ISREG(info.st_mode): return info
            values = list(info);values[4] = os.getuid() + 1
            return os.stat_result(values)
        with patch.object(tool.os, 'fstat', side_effect=wrong_file_owner), self.assertRaisesRegex(tool.ValidationError, 'reader_file_permissions'):
            tool.validation_credential(self.key)
        other = self.directory / 'reader-link.json';other.symlink_to(self.key)
        with self.assertRaisesRegex(tool.ValidationError, 'reader_file_unsafe_or_unreadable'):
            tool.validation_credential(other)
        other.unlink();os.link(self.key, other)
        with self.assertRaisesRegex(tool.ValidationError, 'reader_file_invalid'):
            tool.validation_credential(self.key)
        other.unlink()
        moved = self.directory.with_name('private-real');self.directory.rename(moved);self.directory.symlink_to(moved)
        with self.assertRaisesRegex(tool.ValidationError, 'reader_file_unsafe_or_unreadable'):
            tool.validation_credential(self.key)

    @unittest.skipUnless(os.name == 'posix', 'actual protected-file reader requires Linux')
    def test_linux_expiration_and_malformed_credentials(self):
        for value, reason in [(credential() | {'expiration': 1}, 'reader_expired'),
                              (credential() | {'expiration': True}, 'reader_file_invalid'),
                              (credential() | {'encoded': '\r\nAuthorization: CANARY'}, 'reader_file_invalid'),
                              (credential() | {'id': 'another'}, 'reader_file_invalid'),
                              (credential() | {'extra': CANARY}, 'reader_file_invalid')]:
            self.key.write_text(json.dumps(value))
            with self.subTest(reason=reason), self.assertRaisesRegex(tool.ValidationError, reason):
                tool.validation_credential(self.key)

    def test_tls_context_verifies_ca_and_hostname(self):
        reader = self.reader()
        handler = next(h for h in reader.opener.handlers if isinstance(h, tool.urllib.request.HTTPSHandler))
        self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(handler._context.check_hostname)
        with patch.object(tool, 'validation_credential', return_value=credential()), \
                patch.object(tool.ssl, 'create_default_context', side_effect=ssl.SSLError(CANARY)), \
                self.assertRaisesRegex(tool.ValidationError, 'reader_ca_invalid'):
            tool.Reader(self.key, self.base / 'ca.crt')

    def test_real_request_construction_parsing_and_operations(self):
        reader = self.reader()
        with patch.object(reader.opener, 'open', return_value=io.BytesIO(b'{"ok": true}')) as opened:
            self.assertEqual(reader.request('POST', '/' + tool.APPROVED_INDICES[0] + '/_search', {'size': 1}), {'ok': True})
            req = opened.call_args.args[0]
            self.assertTrue(req.full_url.startswith('https://127.0.0.1:19200/'))
            self.assertEqual(json.loads(req.data), {'size': 1})
            self.assertEqual(req.get_header('Authorization'), 'ApiKey ' + credential()['encoded'])
        for method, path, body in [('POST', '/unapproved/_search', {}), ('POST', '/*/_search', {}),
                                  ('POST', '/_security/api_key', {}), ('GET', '/', None),
                                  ('GET', '/_security/user/_privileges', None),
                                  ('GET', '/_security/api_key?id=another-key', None),
                                  ('DELETE', '/' + tool.APPROVED_INDICES[0], None),
                                  ('POST', '/' + tool.APPROVED_INDICES[0] + '/_mget', {'docs': [{'_index': 'other'}]})]:
            with self.subTest(path=path), self.assertRaisesRegex(tool.ValidationError, 'es_operation_forbidden'):
                reader.request(method, path, body)

    def test_http_errors_do_not_print_server_body_or_key(self):
        reader = self.reader()
        for status, reason in [(400, 'es_http_error'), (401, 'reader_authentication_failed'), (403, 'reader_permission_denied'),
                               (302, 'es_http_error'), (500, 'es_http_error')]:
            error = urllib.error.HTTPError('https://127.0.0.1:19200', status, CANARY, {}, io.BytesIO(CANARY.encode()))
            with patch.object(reader.opener, 'open', side_effect=error), self.subTest(status=status), \
                    self.assertRaisesRegex(tool.ValidationError, '^' + reason + '$'):
                reader.request('GET', '/_security/api_key?id=' + reader.key_id)

    def test_transport_tls_timeout_and_invalid_response(self):
        reader = self.reader()
        for error, reason in [(urllib.error.URLError(ssl.SSLCertVerificationError(CANARY)), 'es_tls_verification_failed'),
                              (urllib.error.URLError(ConnectionRefusedError(CANARY)), 'es_connection_failed'),
                              (urllib.error.URLError(TimeoutError(CANARY)), 'es_connection_timeout'),
                              (TimeoutError(CANARY), 'es_connection_timeout')]:
            with patch.object(reader.opener, 'open', side_effect=error), self.subTest(reason=reason), \
                    self.assertRaisesRegex(tool.ValidationError, '^' + reason + '$'):
                reader.request('GET', '/_security/api_key?id=' + reader.key_id)
        with patch.object(reader.opener, 'open', return_value=io.BytesIO(CANARY.encode())), \
                self.assertRaisesRegex(tool.ValidationError, 'es_response_invalid'):
            reader.request('GET', '/_security/api_key?id=' + reader.key_id)
        reader.expiration = 1
        with patch.object(reader.opener, 'open') as opened, self.assertRaisesRegex(tool.ValidationError, 'reader_expired'):
            reader.request('GET', '/_security/api_key?id=' + reader.key_id)
        opened.assert_not_called()

    def test_missing_cli_auth_argument_and_posix_fail_closed(self):
        result = subprocess.run([sys.executable, str(FILE), '--profile', 'continuous',
                                 '--start', '2026-10-01T00:00:00Z', '--end', '2026-10-01T00:10:00Z',
                                 '--output-dir', str(self.base / 'validation-7ab/unused')],
                                capture_output=True, text=True, timeout=20,
                                env=dict(os.environ, PYTHONPATH=str(FILE.parents[2] / 'src')))
        self.assertEqual(result.returncode, 2)
        self.assertIn('--api-key-file', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        if os.name != 'posix':
            with self.assertRaisesRegex(tool.ValidationError, 'reader_posix_permissions_required'):
                tool.validation_credential(self.key)

    def test_summary_write_error_has_safe_nonzero_exit(self):
        original = Path.open
        def failing_summary(path, *args, **kwargs):
            if path.name == 'summary.json': raise OSError(CANARY)
            return original(path, *args, **kwargs)
        with patch.object(tool, 'plan', return_value=(None, list(tool.APPROVED_INDICES))), \
                patch.object(tool, 'Reader'), patch.object(tool, 'reader_policy'), \
                patch.object(tool, 'permissions', return_value=list(tool.APPROVED_INDICES)), \
                patch.object(Path, 'open', failing_summary), patch('sys.stdout', new_callable=io.StringIO) as output:
            code = tool.main(['--profile', 'continuous', '--start', '2026-10-01T00:00:00Z',
                              '--end', '2026-10-01T00:10:00Z', '--output-dir', str(self.base / 'validation-7ab/error'),
                              '--api-key-file', str(self.key)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())['reason'], 'summary_write_failed')
        self.assertNotIn(CANARY, output.getvalue())

    def test_effective_privileges_are_exact_read_only_scope(self):
        class Fake:
            key_id = 'test-id'
            expiration = credential()['expiration']
            value = assigned_grants()
            def request(self, *args): return self.value
        client = Fake();client.value['api_keys'][0]['expiration'] = client.expiration
        tool.reader_policy(client)
        for change, reason in [('cluster', 'reader_excess_privileges'), ('index', 'reader_excess_index_scope'),
                               ('write', 'reader_excess_privileges')]:
            client.value = assigned_grants();client.value['api_keys'][0]['expiration'] = client.expiration
            role = client.value['api_keys'][0]['role_descriptors']['mall_7ab_validation_reader']
            if change == 'cluster': role['cluster'] = ['monitor']
            if change == 'index': role['indices'][0]['names'].append('soc-host-raw-mall-*')
            if change == 'write': role['indices'][0]['privileges'].append('create_doc')
            with self.subTest(change=change), self.assertRaisesRegex(tool.ValidationError, reason): tool.reader_policy(client)

    def test_own_key_metadata_rejects_wrong_identity_expiry_and_inheritance(self):
        class Fake:
            key_id = 'test-id'
            expiration = credential()['expiration']
            def request(self, method, path):
                self.call = (method, path)
                return self.value
        client = Fake()
        for change, reason in [('id', 'reader_key_metadata_mismatch'), ('expiration', 'reader_key_metadata_mismatch'),
                               ('invalidated', 'reader_key_metadata_mismatch'), ('roles', 'reader_assigned_roles_missing')]:
            client.value = assigned_grants();row = client.value['api_keys'][0];row['expiration'] = client.expiration
            if change == 'id': row['id'] = 'other-key'
            if change == 'expiration': row['expiration'] = 1
            if change == 'invalidated': row['invalidated'] = True
            if change == 'roles': row['role_descriptors'] = {}
            with self.subTest(change=change), self.assertRaisesRegex(tool.ValidationError, reason): tool.reader_policy(client)
            self.assertEqual(client.call, ('GET', '/_security/api_key?id=test-id'))

    def test_response_index_cannot_escape_requested_scope(self):
        class Fake:
            def request(self, *args):
                return {'hits': {'total': {'value': 1, 'relation': 'eq'}, 'hits': [{'_index': 'other'}]}}
        scope = tool.Scope('mall-isolated', 'soc-mall-lab', 'mall-host-isolated', 'security-mall',
                           (tool.APPROVED_CURRENT[2],), (tool.APPROVED_CURRENT[0],), (tool.APPROVED_CURRENT[1],),
                           (tool.APPROVED_HISTORY[2],))
        with self.assertRaisesRegex(tool.ValidationError, 'unexpected_response_index'):
            tool.search(Fake(), tool.APPROVED_CURRENT[2], scope, {'start': '2026-10-01', 'end': '2026-10-02'},
                        '2026-10-03', 'normalized')

    def cli(self, mode):
        """Subprocess uses real main/Reader/requests/engines; only ES transport is a double."""
        code = '''
import importlib.util,io,json,os,pathlib,ssl,sys,urllib.error
spec=importlib.util.spec_from_file_location('auth_cli',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.BASE=pathlib.Path(sys.argv[2]);mode=sys.argv[3]
if mode=='legacy':
 legacy={};exec(compile(pathlib.Path(sys.argv[4]).read_text(),sys.argv[4],'exec'),legacy)
 exec(compile(legacy['LEGACY_SOURCE'],sys.argv[4],'exec'),m.__dict__)
scope=m.Scope('mall-isolated','soc-mall-lab','mall-host-isolated','security-mall',(m.APPROVED_HISTORY[1],m.APPROVED_CURRENT[2]),(m.APPROVED_HISTORY[0],m.APPROVED_CURRENT[0]),(m.APPROVED_CURRENT[1],),(m.APPROVED_HISTORY[2],))
# Use the production plan() with exact private config schema supplied by parent.
if os.name!='posix':
    m.validation_credential=lambda p: json.loads(pathlib.Path(p).read_text()) if mode!='expired' else (_ for _ in ()).throw(m.ValidationError('reader_expired'))
ctx=ssl.create_default_context();m.ssl.create_default_context=lambda **kw: ctx
raw={'_index':m.APPROVED_CURRENT[0],'_id':'synthetic-app','_seq_no':1,'_primary_term':1,'_version':1,'_source':{
 '@timestamp':'2026-10-01T00:00:01Z','organization':{'id':'mall-isolated'},'host':{'id':'mall-host-isolated'},
 'labels':{'log_source':'security_mall_audit'},'event':{'ingested':'2026-10-01T00:01:00Z'},'security_mall':{'audit':{
 'schema_version':1,'@timestamp':'2026-10-01T00:00:01Z','event_id':'00000000-0000-4000-8000-000000000001',
 'service_name':'security-mall','event_action':'login','event_outcome':'failure','source_ip':'127.0.0.1',
 'account_id':'a'*64,'account_key_id':'lab-v1'}}}}
identifier,record,event=m.normalize(raw,'2026-10-01T00:02:00Z');assert record['status']=='normalized'
norm={'_index':m.APPROVED_CURRENT[2],'_id':identifier,'_seq_no':1,'_primary_term':1,'_version':1,'_source':event}
calls=[]
class Opener:
 def open(self,req,timeout):
  path=req.full_url.removeprefix('https://127.0.0.1:19200');calls.append(path)
  if mode in ('401','403'): raise urllib.error.HTTPError(req.full_url,int(mode),'PRIVATE_RESPONSE',{},io.BytesIO(b'PRIVATE_RESPONSE'))
  if mode=='tls': raise urllib.error.URLError(ssl.SSLCertVerificationError('PRIVATE_RESPONSE'))
  if mode=='policy_http400' or mode=='search_http500' and path=='/'+m.APPROVED_CURRENT[0]+'/_search':
   raise urllib.error.HTTPError(req.full_url,400 if mode=='policy_http400' else 500,'PRIVATE_RESPONSE',{},io.BytesIO(b'PRIVATE_RESPONSE'))
  if path=='/_security/user/_privileges': raise urllib.error.HTTPError(req.full_url,400,'PRIVATE_RESPONSE',{},io.BytesIO(b'PRIVATE_RESPONSE'))
  if path=='/_security/api_key?id=test-id':
   key=json.loads((m.BASE/'validation-7ab/secrets/reader-test.json').read_text())
   role={'cluster':[],'applications':[],'run_as':[],'indices':[{'names':list(m.APPROVED_INDICES),'privileges':['read','view_index_metadata'],'allow_restricted_indices':False}]}
   if mode=='excess':role['indices'][0]['names']=['*']
   data={'api_keys':[{'id':key['id'],'expiration':key['expiration'],'invalidated':False,'role_descriptors':{'mall_7ab_validation_reader':role}}]}
  elif path=='/_security/user/_has_privileges':
   data={'cluster':{'all':False,'manage':False},'index':{n:{p:p in ('read','view_index_metadata') for p in m.PRIVILEGES} for n in m.APPROVED_INDICES}}
   if mode=='missing':data['index'][m.APPROVED_CURRENT[0]]['read']=False
  else:
   index,operation=path.strip('/').split('/');body=json.loads(req.data)
   hits=[h for h in (raw,norm) if h['_index']==index]
   if operation=='_search':
    assert body['size']==500 and 'organization.id' in json.dumps(body['query'])
    data={'hits':{'total':{'value':len(hits),'relation':'eq'},'hits':hits}}
   elif operation=='_mget':data={'docs':[dict(h,found=True) for h in hits]}
   else:raise AssertionError('unexpected_operation')
  return io.BytesIO(json.dumps(data).encode())
m.urllib.request.build_opener=lambda *a:Opener()
rc=m.main(['--profile','continuous','--start','2026-10-01T00:00:00Z','--end','2026-10-01T00:10:00Z','--output-dir',str(m.BASE/'validation-7ab/result'),'--api-key-file',str(m.BASE/'validation-7ab/secrets/reader-test.json')])
(m.BASE/'calls.json').write_text(json.dumps(calls));raise SystemExit(rc)
'''
        # Configs mirror production fields; no operational files are read.
        portal = self.base / 'portal-lab/config';portal.mkdir(parents=True)
        scope = {'raw': tool.APPROVED_HISTORY[0], 'normalized': tool.APPROVED_HISTORY[1], 'alerts': tool.APPROVED_HISTORY[2]}
        (portal / 'mall-scope.json').write_text(json.dumps(scope));(portal / 'mall-scope.json').chmod(0o600)
        configdir = self.base / 'collection-services/config';configdir.mkdir(parents=True)
        config = {'organization_id': 'mall-isolated', 'host_id': 'mall-host-isolated',
                  **dict(zip(('app_index', 'edge_index', 'normalized_index'), tool.APPROVED_CURRENT))}
        if mode == 'index': config['edge_index'] = 'unapproved'
        (configdir / 'collection.json').write_text(json.dumps(config));(configdir / 'collection.json').chmod(0o600)
        if mode == 'expired':
            self.key.write_text(json.dumps(credential() | {'expiration': 1}))
        if mode == 'absent': self.key.unlink()
        if mode == 'filemode': self.key.chmod(0o640)
        if mode == 'dirmode': self.directory.chmod(0o750)
        wrapper = self.base / 'cli_double.py';wrapper.write_text(code)
        return subprocess.run([sys.executable, str(wrapper), str(FILE), str(self.base), mode,
                               str(FILE.parents[2] / 'tests/fixtures/mall_reader_policy_legacy.py')],
                              capture_output=True, text=True, timeout=30,
                              env=dict(os.environ, PYTHONPATH=str(FILE.parents[2] / 'src')))

    def test_cli_real_engines_and_query_shapes(self):
        result = self.cli('ok')
        self.assertEqual(result.returncode, 4, result.stderr + result.stdout)
        report = json.loads(result.stdout)
        self.assertEqual(report['raw_normalized_verified'], 1)
        self.assertEqual(report['queue_items'], 1)
        self.assertEqual(report['three_stream_bundles'], 0)
        self.assertTrue(report['existing_documents_unchanged'])
        calls = json.loads((self.base / 'calls.json').read_text())
        self.assertEqual(calls[0], '/_security/api_key?id=test-id')
        self.assertNotIn('/_security/user/_privileges', calls)
        self.assertTrue(all('/' + n + '/_search' in calls for n in tool.APPROVED_INDICES))
        self.assertTrue((self.base / 'validation-7ab/result/correlation.sqlite').is_file())
        self.assertTrue((self.base / 'validation-7ab/result/triage.sqlite').is_file())

    def test_recorded_legacy_policy_failure_uses_actual_cli_path(self):
        result = self.cli('legacy')
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report['reason'], 'es_http_error')
        self.assertEqual(report['failed_stage'], 'api_key_policy')
        self.assertEqual(report['index_queries'], [])
        self.assertFalse(report['correlation_triage_started'])
        self.assertEqual(json.loads((self.base / 'calls.json').read_text()), ['/_security/user/_privileges'])

    def test_cli_retains_safe_http_status_stage_and_partial_query_counts(self):
        for mode, stage, status, operation in [('policy_http400', 'api_key_policy', 400, 'self_api_key_metadata'),
                                               ('search_http500', 'index_search', 500, 'index_search')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                previous = self.base, self.directory, self.key
                self.base = Path(folder) / 'lab';self.directory = self.base / 'validation-7ab/secrets'
                self.directory.mkdir(parents=True, mode=0o700);self.key = self.directory / 'reader-test.json'
                self.key.write_text(json.dumps(credential()));self.key.chmod(0o600)
                try:
                    result = self.cli(mode);self.assertEqual(result.returncode, 1)
                    report = json.loads(result.stdout)
                    self.assertEqual((report['failed_stage'], report['http_status'], report['failed_operation']),
                                     (stage, status, operation))
                    self.assertFalse(report['correlation_triage_started'])
                    self.assertNotIn('PRIVATE_RESPONSE', result.stdout + result.stderr)
                    self.assertNotIn(credential()['encoded'], result.stdout + result.stderr)
                    if mode == 'search_http500':
                        self.assertEqual(len(report['index_queries']), 4)
                        self.assertEqual(report['index_queries'][-1]['status'], 'failed')
                        self.assertIsNone(report['index_queries'][-1]['document_count'])
                        self.assertTrue(all(row['status'] == 'succeeded' and row['document_count'] == 0
                                            for row in report['index_queries'][:-1]))
                        self.assertEqual(len(report['counts']), 3)
                    else: self.assertEqual(report['index_queries'], [])
                finally: self.base, self.directory, self.key = previous

    def test_cli_auth_failure_exit_codes_and_no_secret_output(self):
        expected = {'401': 'reader_authentication_failed', '403': 'reader_permission_denied',
                    'tls': 'es_tls_verification_failed', 'expired': 'reader_expired',
                    'index': 'unapproved_configured_index', 'excess': 'reader_excess_index_scope',
                    'missing': 'reader_scope_missing'}
        # Each CLI invocation has an isolated directory; no replay of successful live validation.
        for mode, reason in expected.items():
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                previous = (self.base, self.directory, self.key)
                self.base = Path(folder) / 'lab';self.directory = self.base / 'validation-7ab/secrets'
                self.directory.mkdir(parents=True, mode=0o700);self.key = self.directory / 'reader-test.json'
                self.key.write_text(json.dumps(credential()));self.key.chmod(0o600)
                try:
                    result = self.cli(mode)
                    self.assertEqual(result.returncode, 4 if mode == 'missing' else 1, result.stderr + result.stdout)
                    self.assertEqual(json.loads(result.stdout)['reason'], reason)
                    text = result.stdout + result.stderr
                    self.assertFalse(any(v in text for v in (CANARY, credential()['encoded'], 'PRIVATE_RESPONSE', 'Authorization', 'Traceback')))
                    calls = json.loads((self.base / 'calls.json').read_text())
                    self.assertFalse(any(p.endswith('/_search') for p in calls))
                finally:
                    self.base, self.directory, self.key = previous

    @unittest.skipUnless(os.name == 'posix', 'real CLI protected-file rejection requires Linux')
    def test_linux_cli_bad_files_stop_before_network(self):
        for mode, reason in [('absent', 'reader_file_missing'), ('filemode', 'reader_file_permissions'),
                             ('dirmode', 'reader_directory_permissions')]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                previous = self.base, self.directory, self.key
                self.base = Path(folder) / 'lab';self.directory = self.base / 'validation-7ab/secrets'
                self.directory.mkdir(parents=True, mode=0o700);self.key = self.directory / 'reader-test.json'
                self.key.write_text(json.dumps(credential()));self.key.chmod(0o600)
                try:
                    result = self.cli(mode)
                    self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                    self.assertEqual(json.loads(result.stdout)['reason'], reason)
                    self.assertEqual(json.loads((self.base / 'calls.json').read_text()), [])
                finally:
                    self.base, self.directory, self.key = previous


if __name__ == '__main__':
    unittest.main()
