"""Opt-in disposable TLS ES 9.5.2; never connects to a supplied server.

SOC_TEST_KEY_EXTENSION_ES=1 SOC_TEST_DOCKER=<docker executable> pytest this-file
No VM, host collector, existing volume, service or key is touched.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time
import unittest
from unittest.mock import patch
import uuid

from elasticsearch import Elasticsearch, AuthenticationException, AuthorizationException, BadRequestError
from elastic_transport import TlsError

import test_device_management as fixture
from test_device_management_tls import certificates
from test_enrollment import AGENTS
from cloud_soc.portal.key_extension import policy
from cloud_soc.portal.status_setup import install_receipt_pipeline, configure_template


IMAGE = 'docker.elastic.co/elasticsearch/elasticsearch:9.5.2'


@unittest.skipUnless(os.getenv('SOC_TEST_KEY_EXTENSION_ES') == '1', 'explicit disposable ES opt-in required')
class KeyExtensionLiveTests(unittest.TestCase):
    def test_tls_real_owner_expiry_same_key_ingestion_and_reconciliation(self):
        docker = os.getenv('SOC_TEST_DOCKER') or shutil.which('docker')
        self.assertTrue(docker, 'Docker executable required')
        env = fixture.DeviceManagementTests()
        env.setUp()
        self.addCleanup(env.doCleanups)
        clients = []
        name = 'soc-key-extension-' + uuid.uuid4().hex[:12]
        volume = name + '-tls'
        def run(*args, check=True):
            result = subprocess.run([docker, *args], capture_output=True, timeout=120)
            if check and result.returncode:
                raise RuntimeError('Disposable Docker operation failed: ' + args[0])
            return result
        try:
            tls = env.root / 'tls'
            tls.mkdir()
            cert, private = certificates(tls)
            password, issuer_password = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            (tls / 'password').write_text(password)
            run('volume', 'create', '--label', 'cloud-soc.lab='+name, volume)
            run('run', '--rm', '--name', name+'-init', '--network', 'none', '--user', '0',
                '--entrypoint', 'sh', '--mount', f'type=bind,src={tls},dst=/source,readonly',
                '--mount', f'type=volume,src={volume},dst=/target', IMAGE, '-c',
                'cp /source/* /target/ && chown 1000:0 /target/* && chmod 640 /target/*')
            run('run', '-d', '--name', name, '--label', 'cloud-soc.lab='+name, '--memory', '2g',
                '-p', '127.0.0.1::9200', '--mount', f'type=volume,src={volume},dst=/usr/share/elasticsearch/config/lab,readonly',
                '-e', 'discovery.type=single-node', '-e', 'xpack.security.enabled=true',
                '-e', 'xpack.security.http.ssl.enabled=true', '-e', 'xpack.security.http.ssl.key=lab/test-key.pem',
                '-e', 'xpack.security.http.ssl.certificate=lab/test-ca.pem',
                '-e', 'ELASTIC_PASSWORD_FILE=/usr/share/elasticsearch/config/lab/password',
                '-e', 'ES_JAVA_OPTS=-Xms512m -Xmx512m', IMAGE)
            address = run('port', name, '9200/tcp').stdout.decode().strip()
            url = 'https://' + address
            admin = Elasticsearch(url, ca_certs=str(cert), basic_auth=('elastic', password), request_timeout=5, max_retries=0)
            clients.append(admin)
            deadline = time.monotonic()+150
            while True:
                try:
                    self.assertEqual(admin.info()['version']['number'], '9.5.2')
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Disposable ES readiness deadline exceeded') from None
                    time.sleep(1)
            install_receipt_pipeline(admin, [])
            source = Path(__file__).resolve().parents[1] / 'deploy/agents/index-template.json'
            template = configure_template(json.loads(source.read_text()))
            template['template']['settings']['number_of_replicas'] = 0
            admin.indices.put_index_template(name=name, body=template)
            owner_role = {'cluster': ['monitor', 'read_pipeline', 'manage_own_api_key'], 'indices': [{
                'names': ['soc-host-raw-linux-*', 'soc-agent-health-*'], 'privileges': ['auto_configure', 'create_doc']}]}
            admin.security.put_role(name='disposable_issuer', **owner_role)
            admin.security.put_user(username='disposable_issuer', password=issuer_password, roles=['disposable_issuer'])
            issuer = Elasticsearch(url, ca_certs=str(cert), basic_auth=('disposable_issuer', issuer_password), request_timeout=5, max_retries=0)
            clients.append(issuer)
            env.issuer = issuer
            env.service.issuer, env.service.monitor, env.service.clock = issuer, admin, time.time
            env.now = int(time.time())
            devices = env.app.extensions['managed_devices']
            device, _ = env.create()
            env.prepare(device)
            exchange = env.exchange_device(device).json
            key = exchange['keys'][0]
            publisher = Elasticsearch(url, ca_certs=str(cert), api_key=tuple(key['key'].split(':', 1)), request_timeout=5, max_retries=0)
            clients.append(publisher)
            index = 'soc-host-raw-linux-key-extension'
            at = datetime.now(timezone.utc).isoformat()
            publisher.index(index=index, id='probe', op_type='create', document={
                '@timestamp': at, 'agent': {'id': AGENTS['host'], 'type': 'filebeat'},
                'labels': {'installation_probe': exchange['probe']}, 'event': {'action': 'installation_probe'}})
            admin.indices.refresh(index=index)
            self.assertTrue(env.machine('receipt', {'attempt': env.attempt, 'agents': {'host': AGENTS['host']}}).json['verified'])
            publisher.index(index=index, id='before', op_type='create', document={'@timestamp': at, 'message': 'SYNTHETIC before'})
            base = f"/api/managed-devices/{device['id']}/key-extension"
            def preview(days=1):
                result = env.request('POST', base+'/preview', {'key_id': key['id'], 'days': days})
                self.assertEqual(result.status_code, 200, result.json)
                return result.json['extension']
            def apply(operation):
                return env.request('POST', base+'/'+operation['id'], {'confirm': True})
            old = issuer.security.get_api_key(id=key['id'], owner=True, with_limited_by=True)['api_keys'][0]
            operation = preview()
            result = apply(operation)
            self.assertEqual(result.status_code, 200, result.json)
            new = issuer.security.get_api_key(id=key['id'], owner=True, with_limited_by=True)['api_keys'][0]
            self.assertGreater(new['expiration'], old['expiration'])
            self.assertEqual(new['role_descriptors'], old['role_descriptors'])
            self.assertEqual(new['limited_by'], old['limited_by'])
            self.assertEqual(new['expiration'], result.json['device']['keys'][0]['expiration'])
            self.assertEqual(apply(operation).json['extension'], result.json['extension'])
            publisher.index(index=index, id='after', op_type='create', document={'@timestamp': at, 'message': 'SYNTHETIC after'})
            for action in (lambda: publisher.search(index=index),
                           lambda: publisher.index(index='outside-scope', id='no', op_type='create', document={}),
                           lambda: publisher.security.create_api_key(name='no', role_descriptors=policy('linux'))):
                with self.assertRaises(AuthorizationException):
                    action()
            # A real remote update followed by a lost response is read-only on retry.
            operation = preview(7)
            extension = devices.key_extensions
            client = extension._client()
            update = client.security.update_api_key
            calls = []
            def lose(**kwargs):
                calls.append(1)
                update(**kwargs)
                raise OSError('SYNTHETIC_RESPONSE_LOST')
            with patch.object(extension, '_client', return_value=client), patch.object(client.security, 'update_api_key', side_effect=lose):
                self.assertEqual(apply(operation).status_code, 503)
            self.assertEqual(apply(operation).status_code, 200)
            self.assertEqual(len(calls), 1)
            # A real remote success and rolled-back local completion are reconciled.
            operation = preview(1)
            finish = extension._finish
            def fail_commit(db, row, remote):
                finish(db, row, remote)
                raise OSError('SYNTHETIC_LOCAL_COMMIT_FAILURE')
            with patch.object(extension, '_finish', side_effect=fail_commit):
                self.assertEqual(apply(operation).status_code, 503)
            self.assertEqual(apply(operation).status_code, 200)
            # Current issuer policy may not silently reduce or expand the key.
            admin.security.put_role(name='disposable_issuer', cluster=['monitor', 'manage_own_api_key'], indices=[])
            self.assertEqual(env.request('POST', base+'/preview', {'key_id': key['id'], 'days': 1}).status_code, 409)
            admin.security.put_role(name='disposable_issuer', **owner_role)
            bad = Elasticsearch(url, ca_certs=str(cert), basic_auth=('disposable_issuer', 'wrong'), max_retries=0)
            clients.append(bad)
            with patch.object(extension, '_client', return_value=bad):
                failure = env.request('POST', base+'/preview', {'key_id': key['id'], 'days': 1})
                self.assertEqual(failure.status_code, 503)
                self.assertNotIn(b'wrong', failure.data)
            # Restoring old DB metadata cannot revive a remotely invalidated key.
            issuer.security.invalidate_api_key(ids=[key['id']], owner=True)
            self.assertEqual(env.request('POST', base+'/preview', {'key_id': key['id'], 'days': 1}).status_code, 409)
            ended = env.request('POST', f"/api/managed-devices/{device['id']}/end", {'confirm': True})
            self.assertEqual(ended.status_code, 200, ended.json)
            self.assertEqual(ended.json['device']['state'], 'ended')
            with self.assertRaises(AuthenticationException):
                publisher.index(index=index, id='revoked', op_type='create', document={})
            short = issuer.security.create_api_key(name='disposable-expired', expiration='1ms', role_descriptors=policy('linux'))
            time.sleep(0.05)
            with self.assertRaises(BadRequestError):
                issuer.security.update_api_key(id=short['id'], expiration='1d')
            # Real TLS trust/auth failures; no verification bypasses.
            with self.assertRaises(AuthenticationException):
                bad.security.authenticate()
            bad_tls = Elasticsearch(url, max_retries=0)
            clients.append(bad_tls)
            with self.assertRaises(TlsError):
                bad_tls.info()
            wrong_name = Elasticsearch(url.replace('127.0.0.1', 'localhost'), ca_certs=str(cert), max_retries=0)
            clients.append(wrong_name)
            with self.assertRaises(TlsError):
                wrong_name.info()
            admin.indices.refresh(index=index)
            self.assertEqual(admin.get(index=index, id='before')['_source']['message'], 'SYNTHETIC before')
            self.assertEqual(admin.get(index=index, id='after')['_source']['message'], 'SYNTHETIC after')
        finally:
            for client in clients:
                client.close()
            removed = run('rm', '--force', '--volumes', name, check=False)
            self.assertEqual(removed.returncode, 0, 'Disposable ES cleanup failed')
            self.assertEqual(run('volume', 'rm', volume, check=False).returncode, 0, 'Disposable TLS cleanup failed')
