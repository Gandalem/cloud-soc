"""Explicit native-agent lab controller. Fresh WSL distro/Windows VM only.

Requires --run, a private disposable state directory and a separately prepared
guest SSH connection. No host agent install, production access or automatic reboot.
"""
import argparse
import base64
import hashlib
from datetime import datetime, timedelta, timezone
import http.server
import io
import ipaddress
import json
import logging
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from elasticsearch import Elasticsearch
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server, WSGIRequestHandler

from cloud_soc.portal.app import create_app
from cloud_soc.portal.status_setup import configure_reader, configure_template, install_receipt_pipeline
from cloud_soc.processing.setup import prepare as prepare_processing, ROLE as NORMALIZER_ROLE
from cloud_soc.processing.worker import run_once as normalize_once
from cloud_soc.detection.worker import run_once as detect_once
from cloud_soc.detection.engine import event_evidence
from cloud_soc.elastic.repository import SECURITY_ALERTS_MAPPING

PROJECT = Path(__file__).resolve().parents[2]
ES_IMAGE = 'docker.elastic.co/elasticsearch/elasticsearch:9.5.2'
HOST = '192.168.235.1'
PORTAL_PORT, CRL_PORT = 18770, 18766


class Quiet(WSGIRequestHandler):
    def log_request(self, *args):
        pass


def certs(root):
    at = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Windows Cryptnet caches CRLs by URL. Never reuse one URL/DN for different
    # disposable CA keys; a previous trial's still-valid CRL is not this CA's CRL.
    identity = hashlib.sha256(key.public_key().public_bytes(serialization.Encoding.DER,
                              serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:24]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable native agent lab CA '+identity)])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=2))
        .not_valid_after(at+timedelta(hours=12)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False).sign(key, hashes.SHA256()))
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
        .issuer_name(name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(at-timedelta(minutes=2)).not_valid_after(at+timedelta(hours=8))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(HOST)),
            x509.IPAddress(ipaddress.ip_address('127.0.0.1')), x509.DNSName('elasticsearch')]), False)
        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(f'http://{HOST}:{CRL_PORT}/crl-{identity}.der')],
            relative_name=None, reasons=None, crl_issuer=None)]), False).sign(key, hashes.SHA256()))
    crl = (x509.CertificateRevocationListBuilder().issuer_name(name).last_update(at-timedelta(minutes=1))
        .next_update(at+timedelta(hours=8)).add_extension(x509.CRLNumber(1), False).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False).sign(key, hashes.SHA256()))
    for path, content in (('ca.pem', ca.public_bytes(serialization.Encoding.PEM)),
                          ('server.pem', leaf.public_bytes(serialization.Encoding.PEM)),
                          ('server.key', server_key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8, serialization.NoEncryption())),
                          ('crl.der', crl.public_bytes(serialization.Encoding.DER))):
        (root/path).write_bytes(content)


def wait(check, seconds=120):
    deadline = time.monotonic()+seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError('Bounded lab wait expired')


class Lab:
    def __init__(self, docker, root, distro):
        self.docker, self.root, self.distro = docker, root, distro
        self.label = 'soc-os-lab-'+uuid.uuid4().hex[:10]
        self.secret_values = []
        self.clients, self.servers, self.containers, self.volumes, self.devices = [], [], [], [], []
        self.report = {'checks': [], 'native_wsl': 'not_started', 'native_windows': 'not_started',
                       'reboot': 'not_run', 'scope': 'fresh WSL distro and specified Windows VM'}
        self.log_dir = root/('native-'+self.label)
        self.log_dir.mkdir(exist_ok=False)
        self.tls = self.log_dir/'tls'
        self.tls.mkdir()
        self.initial = datetime.now(timezone.utc)-timedelta(seconds=60)
        self.origin = f'https://{HOST}:{PORTAL_PORT}'

    def safe(self, text):
        for value in self.secret_values:
            text = text.replace(value, '[REDACTED]')
        return text

    def record(self, name):
        self.report['checks'].append(name)
        self.save()
        print(name, flush=True)

    def save(self):
        content = json.dumps(self.report, indent=2)+'\n'
        (self.root/'native-report.json').write_text(content)
        (self.log_dir/'report.json').write_text(content)

    def command(self, args, *, data=None, timeout=120, name=None, check=True):
        p = subprocess.run(list(map(str, args)), input=data, capture_output=True, timeout=timeout)
        text = self.safe((p.stdout+p.stderr).decode('utf-8', 'replace'))
        if name:
            (self.log_dir/(name+'.log')).write_text(text, encoding='utf-8')
        if check and p.returncode:
            (self.log_dir/'last-failure.log').write_text(text, encoding='utf-8')
            raise RuntimeError(f'Lab command failed ({name or Path(str(args[0])).name}, exit {p.returncode})')
        return p.stdout.decode('utf-8', 'replace').strip()

    def dk(self, *args, **kwargs):
        return self.command([self.docker, *args], **kwargs)

    def wsl(self, *args, **kwargs):
        return self.command(['wsl.exe', '-d', self.distro, '-u', 'root', '--', *args], **kwargs)

    def linux_python(self, code, **kwargs):
        return self.wsl('python3', '-c', code, **kwargs)

    def start(self):
        certs(self.tls)
        leaf = x509.load_pem_x509_certificate((self.tls/'server.pem').read_bytes())
        crl_uri = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value[0].full_name[0].value
        self.crl_path = '/' + crl_uri.rsplit('/', 1)[1]
        password, issuer, monitor, self.admin_password = [secrets.token_urlsafe(32) for _ in range(4)]
        self.secret_values.extend([password, issuer, monitor, self.admin_password])
        (self.tls/'elastic-password').write_text(password)
        volume, name = self.label+'-tls', self.label+'-es'
        self.dk('volume', 'create', '--label', 'cloud-soc.lab='+self.label, volume)
        self.volumes.append(volume)
        self.dk('run', '--rm', '--name', self.label+'-init', '--network', 'none', '--user', '0',
            '--entrypoint', 'sh', '--mount', f'type=bind,src={self.tls},dst=/source,readonly',
            '--mount', f'type=volume,src={volume},dst=/target', ES_IMAGE, '-c',
            'cp /source/ca.pem /source/server.pem /source/server.key /source/elastic-password /target/ && '
            'chmod 640 /target/* && chown 1000:0 /target/*')
        self.containers.append(name)
        self.dk('run', '-d', '--name', name, '--label', 'cloud-soc.lab='+self.label, '--memory', '3g',
            '-p', HOST+'::9200', '--mount', f'type=volume,src={volume},dst=/usr/share/elasticsearch/config/lab,readonly',
            '-e', 'discovery.type=single-node', '-e', 'xpack.security.enabled=true',
            '-e', 'xpack.security.http.ssl.enabled=true', '-e', 'xpack.security.http.ssl.key=lab/server.key',
            '-e', 'xpack.security.http.ssl.certificate=lab/server.pem',
            '-e', 'xpack.security.http.ssl.certificate_authorities=lab/ca.pem',
            '-e', 'ELASTIC_PASSWORD_FILE=/usr/share/elasticsearch/config/lab/elastic-password',
            '-e', 'ES_JAVA_OPTS=-Xms1g -Xmx1g', ES_IMAGE)
        published = wait(lambda: self.dk('port', name, '9200/tcp', check=False), 30)
        self.endpoint = 'https://'+published
        self.client = Elasticsearch(self.endpoint, ca_certs=str(self.tls/'ca.pem'), basic_auth=('elastic', password),
                                    request_timeout=5, max_retries=0)
        self.clients.append(self.client)
        def ready():
            try:
                return self.client.info()['version']['number'] == '9.5.2'
            except Exception:
                return False
        wait(ready, 180)
        install_receipt_pipeline(self.client, [])
        for name, file in [('cloud-soc-host', 'index-template.json'), ('cloud-soc-health', 'health-index-template.json')]:
            template = json.loads((PROJECT/'deploy/agents'/file).read_text())
            template['template']['settings']['number_of_replicas'] = 0
            self.client.indices.put_index_template(name=name, body=configure_template(template))
        self.client.security.put_role(name='cloud_soc_issuer', cluster=['monitor', 'read_pipeline', 'manage_own_api_key'],
            indices=[{'names': ['soc-host-raw-*', 'soc-network-*', 'soc-agent-health-*'],
                      'privileges': ['auto_configure', 'create_doc']}])
        self.client.security.put_user(username='cloud_soc_issuer', password=issuer, roles=['cloud_soc_issuer'])
        configure_reader(self.client, monitor)
        prepare_processing(self.client)
        self.client.indices.create(index='security-alerts', settings={'number_of_replicas': 0}, mappings=SECURITY_ALERTS_MAPPING)
        self.app = create_app({'STATE_DIR': self.log_dir/'portal', 'AGENT_SOURCE': PROJECT/'deploy/agents',
            'CA_BYTES': (self.tls/'ca.pem').read_bytes(), 'CA_FILE': str(self.tls/'ca.pem'),
            'ENDPOINT': self.endpoint, 'PUBLIC_URL': self.origin, 'ENROLLMENT_ENABLED': True,
            'ADMIN_USER': 'admin', 'ADMIN_HASH': generate_password_hash(self.admin_password),
            'ES_URL': self.endpoint, 'ES_PASSWORD': issuer, 'MONITOR_PASSWORD': monitor})
        self.clients.extend([self.app.extensions['issuer'], self.app.extensions['monitor']])
        server = make_server(HOST, PORTAL_PORT, self.app, threaded=True,
            ssl_context=(str(self.tls/'server.pem'), str(self.tls/'server.key')), request_handler=Quiet)
        self.servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        owner = self
        class CRL(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.path != owner.crl_path:
                    self.send_error(404)
                    return
                body = (owner.tls/'crl.der').read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'application/pkix-crl')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        crl = http.server.ThreadingHTTPServer((HOST, CRL_PORT), CRL)
        self.servers.append(crl)
        threading.Thread(target=crl.serve_forever, daemon=True).start()
        self.context = ssl.create_default_context(cafile=str(self.tls/'ca.pem'))
        self.basic = 'Basic '+base64.b64encode(('admin:'+self.admin_password).encode()).decode()
        self.normalizer = self.limited(NORMALIZER_ROLE)
        self.detector = self.limited({'cluster': [], 'indices': [
            {'names': ['soc-normalized-v1'], 'privileges': ['read', 'view_index_metadata']},
            {'names': ['security-alerts'], 'privileges': ['create_doc', 'view_index_metadata']},
            {'names': ['soc-pipeline-status'], 'privileges': ['index']}]})
        self.record('fresh_es_tls_crl_product_portal_limited_worker_accounts_ready')

    def limited(self, role):
        key = self.client.security.create_api_key(name=self.label+'-worker-'+secrets.token_hex(3), role_descriptors={'worker': role})
        self.secret_values.append(key['api_key'])
        client = Elasticsearch(self.endpoint, ca_certs=str(self.tls/'ca.pem'), api_key=(key['id'], key['api_key']),
                               request_timeout=15, max_retries=0)
        self.clients.append(client)
        return client

    def call(self, path, data=None, expected=200):
        headers = {'Authorization': self.basic, 'X-Cloud-SOC': 'portal'}
        if data is not None:
            headers.update({'Content-Type': 'application/json', 'Idempotency-Key': uuid.uuid4().hex})
        request = urllib.request.Request(self.origin+path, headers=headers,
            data=json.dumps(data).encode() if data is not None else None)
        try:
            response = urllib.request.urlopen(request, context=self.context, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            if response.code != expected:
                raise RuntimeError('Portal lab HTTP '+str(response.code)+' '+path.rsplit('/', 1)[-1])
            return json.loads(body) if 'json' in response.headers.get('Content-Type', '') else body

    def device(self, platform, log_root):
        site = {'id': platform+'-site', 'name': 'Synthetic '+platform, 'server_type': 'apache',
            'log_path': log_root+('/access.log' if platform == 'ubuntu' else '\\access.log'),
            'start_at': self.initial.isoformat(), 'modsecurity': {
                'log_path': log_root+('/audit.json' if platform == 'ubuntu' else '\\audit.json'), 'timezone': '+00:00'}}
        device = self.call('/api/managed-devices', {'label': 'Native '+platform+' lab', 'organization': 'oslab',
            'os': platform, 'purpose': 'web', 'system': False, 'network': False, 'sites': [site]}, expected=201)['device']
        self.devices.append(device['id'])
        self.call('/api/managed-devices/'+device['id']+'/prepare', {'days': 1, 'renew': False})
        payload = self.call('/api/managed-devices/'+device['id']+'/download')
        with zipfile.ZipFile(io.BytesIO(payload)) as z:
            self.secret_values.append(json.loads(z.read('registration.json'))['token'])
        return device, payload

    def raw(self, device_id, source=None):
        query = {'bool': {'filter': [{'term': {'organization.id': 'oslab'}},
            {'term': {'cloud_soc_enrollment.package_id': self.app.extensions['managed_devices'].detail(device_id)['package_id']}}]}}
        if source:
            query['bool']['filter'].append({'term': {'labels.log_source': source}})
        self.client.indices.refresh(index='soc-host-raw-*', ignore_unavailable=True)
        return self.client.search(index='soc-host-raw-*', allow_no_indices=True, ignore_unavailable=True,
            query=query, size=100, allow_partial_search_results=False)['hits']['hits']

    def pipeline(self, expected, minimum_events):
        # Explicit lab receipt policy, unchanged rule thresholds and real wall clock.
        self.client.indices.refresh(index='soc-host-raw-*', ignore_unavailable=True)
        # The real worker advances a bounded five-minute receipt window per
        # cycle. Installation/download time can span multiple such windows.
        target = self.client.search(index='soc-host-raw-*', size=0,
            aggs={'last_received': {'max': {'field': 'event.ingested'}}})['aggregations']['last_received']['value']
        if target is None:
            raise RuntimeError('Missing receipt time')
        ahead = max(0, target/1000-datetime.now(timezone.utc).timestamp())
        self.report['receipt_ahead_seconds'] = ahead
        self.save()
        if ahead > 60:
            raise RuntimeError('Lab clock mismatch exceeds bounded tolerance')
        # WSL/Docker and the Windows worker can differ by a few seconds. Wait
        # for the recorded receipt to be in the real past, never edit its time.
        if ahead:
            wait(lambda: datetime.now(timezone.utc).timestamp() > target/1000, 61)
        for _ in range(24):
            result = normalize_once(self.normalizer, str(self.log_dir/'normalizer.sqlite'), self.initial.isoformat(),
                web_site_v2_start=self.initial.isoformat(), receipt_lag_seconds=0)
            self.report['normalizer_range'] = result['range']
            self.report['normalizer_checkpoint'] = result['checkpoint']
            if datetime.fromisoformat(result['checkpoint'].replace('Z', '+00:00')).timestamp()*1000 >= target:
                break
        else:
            raise RuntimeError('Lab receipt range did not catch up')
        self.client.indices.refresh(index='soc-normalized-v1')
        normalized_count = self.client.count(index='soc-normalized-v1')['count']
        self.report['normalized_count'] = normalized_count
        self.save()
        if normalized_count < minimum_events:
            self.report['processing_reasons'] = self.client.search(index='soc-processing-v1', size=0,
                aggs={'reasons': {'terms': {'field': 'reason'}}})['aggregations']['reasons']['buckets']
            self.save()
            raise RuntimeError('Expected synthetic inputs were not normalized')
        detected = detect_once(self.detector, rule_ids=['WEB-SITE-WAF-001'])
        self.client.indices.refresh(index='security-alerts')
        alerts = self.client.search(index='security-alerts', query={'match_all': {}}, size=100)['hits']['hits']
        assert len(alerts) == expected, 'Unexpected alert count'
        self.report['normalization'] = result['counts']
        self.report['detection'] = detected
        self.save()
        return alerts

    @staticmethod
    def waf(request, peer, rule):
        at = datetime.now(timezone.utc)
        # Explicit UTC input, synthetic metadata only; no real HTTP attack.
        return {'transaction': {'unique_id': request, 'client_ip': peer,
            'time_stamp': at.strftime('%a %b %d %H:%M:%S %Y'),
            'request': {'method': 'GET', 'uri': '/synthetic?discard=COLLECTOR_PRIVACY_CANARY'},
            'response': {'http_code': 403}, 'producer': {'secrules_engine': 'DetectionOnly'},
            'is_interrupted': False, 'messages': [{'message': 'synthetic', 'details': {'ruleId': rule, 'ver': 'OWASP_CRS/4.10.0'}}]}}

    def linux(self):
        self.report['native_wsl'] = 'running'
        self.save()
        self.linux_python("from pathlib import Path; assert 'VERSION_ID=\"24.04\"' in Path('/etc/os-release').read_text(); "
            "assert Path('/proc/1/comm').read_text().strip()=='systemd'; "
            "assert not any(Path(p).exists() for p in ['/opt/cloud-soc-agent','/var/lib/cloud-soc-enrollment','/var/lib/cloud-soc-bundles']); "
            "print('supported clean native WSL target')", name='wsl-preflight')
        self.linux_root = '/root/'+self.label
        self.linux_logs = '/var/log/'+self.label
        self.linux_python("from pathlib import Path; import os;os.umask(0o077); "
            f"r=Path({self.linux_root!r});r.mkdir();(r/'bundle').mkdir(); "
            f"p=Path({self.linux_logs!r});p.mkdir();(p/'access.log').touch();(p/'audit.json').touch()")
        device, payload = self.device('ubuntu', self.linux_logs)
        self.linux_device = device['id']
        self.linux_python("import io,sys,zipfile,os;from pathlib import Path;os.umask(0o077); "
            f"r=Path({self.linux_root+'/bundle'!r}); "
            "z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read())); "
            "assert all('/' not in n and chr(92) not in n for n in z.namelist()); "
            "[r.joinpath(n).write_bytes(z.read(n)) for n in z.namelist()]", data=payload, name='wsl-bundle-extract')
        self.wsl('python3', self.linux_root+'/bundle/bootstrap-linux.py', 'install', timeout=1500, name='wsl-install')
        detail = self.call('/api/managed-devices/'+device['id'])['device']
        assert detail['state'] == 'received'
        self.linux_python(f"from pathlib import Path;import shutil;r=Path({self.linux_root!r})/'bundle'; "
            f"assert r.parent==Path({self.linux_root!r});shutil.rmtree(r)")
        self.wsl('python3', '/var/lib/cloud-soc-bundles/'+device['id']+'/agent-manager.py', 'status', name='wsl-status')
        self.record('wsl_actual_installer_tls_crl_keystore_services_receipt_original_bundle_removed')
        initial_rows = [self.waf('wsl-positive-'+str(n), '203.0.113.44', '942100') for n in range(2)]
        initial_rows += [self.waf('wsl-negative-'+str(n), '198.51.100.9', '930100') for n in range(3)]
        self.append_linux(initial_rows)
        wait(lambda: len(self.raw(device['id'], 'generic_modsecurity')) == 5)
        self.pipeline(0, 5)
        self.record('wsl_real_collection_two_sqli_and_three_non_sqli_no_alert')
        self.append_linux([self.waf('wsl-positive-2', '203.0.113.44', '942100')])
        wait(lambda: len(self.raw(device['id'], 'generic_modsecurity')) == 6)
        alerts = self.pipeline(1, 6)
        self.verify_alert(alerts[0], device['id'])
        self.pipeline(1, 6)
        self.record('wsl_three_distinct_sqli_requests_one_alert_replay_no_duplicate_exact_raw')
        for action in ('stop', 'start'):
            self.wsl('python3', '/var/lib/cloud-soc-bundles/'+device['id']+'/agent-manager.py', action, name='wsl-'+action)
        self.record('wsl_owned_service_stop_start')
        self.wsl('python3', '/var/lib/cloud-soc-bundles/'+device['id']+'/agent-manager.py', 'uninstall',
                 data=b'1\n', name='wsl-uninstall-preserve')
        self.linux_python("from pathlib import Path;assert not Path('/opt/cloud-soc-agent').exists(); "
            "assert not Path('/etc/systemd/system/cloud-soc-filebeat.service').exists(); "
            "r=list(Path('/var/lib/cloud-soc-enrollment').glob('retired-*/cloud-soc-agent/data'));assert len(r)==1; "
            "assert any(r[0].rglob('*'));print('retired queue/registry preserved')", name='wsl-preservation')
        self.call('/api/managed-devices/'+device['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+device['id'])['device']['state'] == 'ended'
        self.report['native_wsl'] = 'passed'
        self.record('wsl_real_local_uninstall_queue_preservation_remote_revocation')

    def append_linux(self, rows):
        self.linux_python("import sys;from pathlib import Path; "
            f"p=Path({self.linux_logs+'/audit.json'!r}); "
            "f=p.open('ab');f.write(sys.stdin.buffer.read());f.close()", data=''.join(json.dumps(row)+'\n' for row in rows).encode())

    def verify_alert(self, alert, device_id):
        # Reuse product evidence semantics; never invent missing references.
        doc = alert['_source']
        assert doc.get('rule', {}).get('id') == 'WEB-SITE-WAF-001'
        visible = self.call('/api/alerts/detail?id='+alert['_id'])
        assert visible['alert']['id'] == alert['_id'] and visible['evidence_count'] == 3
        evidence = doc['cloud_soc']['provenance']['evidence']
        assert len(evidence) == 3 and all(row['complete'] is True for row in evidence)
        package = self.app.extensions['managed_devices'].detail(device_id)['package_id']
        for row in evidence:
            normalized_ref, raw_ref = row['normalized'], row['raw']
            normalized = self.client.get(index=normalized_ref['index'], id=normalized_ref['id'])['_source']
            normalized['_cloud_soc_meta'] = {'index': normalized_ref['index'], 'document_id': normalized_ref['id']}
            assert event_evidence(normalized) == row
            original = self.client.get(index=raw_ref['index'], id=raw_ref['id'])['_source']
            assert original['organization']['id'] == doc['organization']['id'] == 'oslab'
            assert original['cloud_soc_enrollment']['package_id'] == package
            assert original['host']['id'] == doc['host']['id']
            assert original['service']['id'] == doc['service']['id']
        self.report.setdefault('alerts', []).append({'id': alert['_id'], 'rule': doc['rule']['id']})
        raw = self.raw(device_id, 'generic_modsecurity')
        assert len(raw) >= 3 and all('COLLECTOR_PRIVACY_CANARY' not in json.dumps(hit['_source']) for hit in raw)
        self.report['alert_document_fields'] = sorted(doc)
        self.save()

    def close(self):
        for device in self.devices:
            try:
                self.call('/api/managed-devices/'+device+'/end', {'confirm': True})
            except Exception:
                self.report.setdefault('cleanup_errors', []).append('device_revocation')
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for client in self.clients:
            client.close()
        for name in reversed(self.containers):
            self.dk('rm', '-f', '-v', name, check=False)
        for name in self.volumes:
            self.dk('volume', 'rm', name, check=False)
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--distro', required=True)
    args = parser.parse_args()
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    root = args.state.resolve(strict=True)
    if not root.is_relative_to((PROJECT/'state/install-device-ux').resolve()):
        raise ValueError('Private disposable lab state required')
    lab = Lab(args.docker, root, args.distro)
    try:
        lab.start()
        lab.linux()
        lab.report['native_windows'] = 'awaiting_guest_access'
        lab.record('native_linux_phase_finished_windows_transport_pending')
    except Exception as error:
        lab.report.update(failure_type=type(error).__name__, failure_location=[
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        lab.save()
        print('Native lab stopped ('+type(error).__name__+'); inspect redacted lab log.', flush=True)
        return 1
    finally:
        lab.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
