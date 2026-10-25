"""Opt-in real TLS ES/Filebeat device API lab. Never installs host services.

Run explicitly with --run and --docker PATH. Creates only fresh labelled Docker
resources and a private temporary directory. No mocks; not an OS installer test.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import io
import ipaddress
import json
import logging
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
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
from elasticsearch import Elasticsearch, ApiError
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server, WSGIRequestHandler

from cloud_soc.portal.app import create_app
from cloud_soc.portal.status_setup import configure_reader, configure_template, install_receipt_pipeline

PROJECT = Path(__file__).resolve().parents[2]
ES_IMAGE = 'docker.elastic.co/elasticsearch/elasticsearch:9.5.2'
BEAT_IMAGE = 'docker.elastic.co/beats/filebeat:9.5.2'


class QuietHandler(WSGIRequestHandler):
    def log_request(self, *args):
        pass


def certificates(root):
    at = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable device lab CA')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=1))
          .not_valid_after(at+timedelta(hours=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'elasticsearch')]))
            .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(at-timedelta(minutes=1)).not_valid_after(at+timedelta(hours=2))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('elasticsearch'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ca_key, hashes.SHA256()))
    (root/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root/'server.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (root/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def wait_for(check, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(1)
    raise RuntimeError('Bounded lab wait expired')


def run(docker, report):
    label = 'soc-install-ux-' + uuid.uuid4().hex[:12]
    area = PROJECT/'state/install-device-ux'
    area.mkdir(parents=True, exist_ok=True)
    root = Path(tempfile.mkdtemp(prefix=label+'-', dir=area)).resolve()
    result = {'scope': 'real TLS ES9.5.2/Filebeat9.5.2 and device HTTP API; no OS install',
              'checks': [], 'cleanup': False}
    containers, network, volumes = [], False, []
    server = thread = None
    clients = []
    sensitive = []

    def redact(value):
        for secret in sensitive:
            value = value.replace(secret, '[REDACTED]')
        return value

    def command(*args, timeout=120, check=True):
        reply = subprocess.run([docker, *map(str, args)], capture_output=True, timeout=timeout)
        if check and reply.returncode:
            # Docker output can contain configuration; do not print it or credentials.
            result['docker_error'] = redact(reply.stderr.decode('utf-8', 'replace'))[-2000:]
            raise RuntimeError('Docker lab action failed: ' + str(args[0]))
        output = reply.stdout + (reply.stderr if args[0] == 'logs' else b'')
        return output.decode('utf-8', 'replace').strip()

    def record(message):
        result['checks'].append(message)
        print(message, flush=True)

    try:
        if __import__('os').name == 'nt':
            user = subprocess.check_output(['whoami'], text=True).strip()
            subprocess.run(['icacls', str(root), '/inheritance:r', '/grant:r', f'{user}:(OI)(CI)F',
                            'SYSTEM:(OI)(CI)F'], check=True, capture_output=True)
        certificates(root)
        password, issuer_password, monitor_password, admin_password = [secrets.token_urlsafe(32) for _ in range(4)]
        sensitive.extend([password, issuer_password, monitor_password, admin_password])
        (root/'elastic-password').write_text(password)
        # Dedicated bridge with ES management bound only to host loopback; no egress claim.
        command('network', 'create', '--label', 'cloud-soc.lab='+label, label)
        network = True
        es_name, beat_name = label+'-es', label+'-beat'
        volume = label+'-tls'
        command('volume', 'create', '--label', 'cloud-soc.lab='+label, volume)
        volumes.append(volume)
        containers.append(label+'-init')
        # Windows bind mounts present mode777. Stage only the fresh lab files
        # into a POSIX volume so ES can enforce its secret-file permissions.
        command('run', '--rm', '--name', label+'-init', '--label', 'cloud-soc.lab='+label,
            '--network', 'none', '--user', '0', '--entrypoint', 'sh',
            '--mount', f'type=bind,src={root},dst=/source,readonly',
            '--mount', f'type=volume,src={volume},dst=/target', ES_IMAGE, '-c',
            'cp /source/ca.pem /source/server.pem /source/server.key /source/elastic-password /target/ && '
            'chmod 640 /target/* && chown 1000:0 /target/*')
        containers.append(es_name)
        command('run', '-d', '--name', es_name, '--label', 'cloud-soc.lab='+label,
            '--network', label, '--network-alias', 'elasticsearch', '--memory', '3g',
            '-p', '127.0.0.1::9200',
            '--mount', f'type=volume,src={volume},dst=/usr/share/elasticsearch/config/lab,readonly',
            '-e', 'discovery.type=single-node', '-e', 'xpack.security.enabled=true',
            '-e', 'xpack.security.http.ssl.enabled=true',
            '-e', 'xpack.security.http.ssl.key=lab/server.key',
            '-e', 'xpack.security.http.ssl.certificate=lab/server.pem',
            '-e', 'xpack.security.http.ssl.certificate_authorities=lab/ca.pem',
            '-e', 'ELASTIC_PASSWORD_FILE=/usr/share/elasticsearch/config/lab/elastic-password',
            '-e', 'ES_JAVA_OPTS=-Xms1g -Xmx1g', ES_IMAGE)
        def published_port():
            if command('inspect', '--format', '{{.State.Status}}', es_name) == 'exited':
                raise RuntimeError('Elasticsearch lab exited before readiness')
            return command('port', es_name, '9200/tcp', check=False)
        port = wait_for(published_port, 30).rsplit(':', 1)[1]
        endpoint = 'https://127.0.0.1:' + port
        client = Elasticsearch(endpoint, ca_certs=str(root/'ca.pem'), basic_auth=('elastic', password),
                               request_timeout=5, max_retries=0)
        clients.append(client)
        def ready():
            try:
                return client.info()['version']['number'] == '9.5.2'
            except Exception:
                return False
        wait_for(ready, 180)
        record('real_elasticsearch_9.5.2_tls_ready')
        install_receipt_pipeline(client, [])
        template = json.loads((PROJECT/'deploy/agents/index-template.json').read_text())
        template['template']['settings']['number_of_replicas'] = 0
        client.indices.put_index_template(name='cloud-soc-host', body=configure_template(template))
        client.security.put_role(name='cloud_soc_issuer', cluster=['monitor', 'read_pipeline', 'manage_own_api_key'],
            indices=[{'names': ['soc-host-raw-*', 'soc-network-*', 'soc-agent-health-*'],
                      'privileges': ['auto_configure', 'create_doc']}])
        client.security.put_user(username='cloud_soc_issuer', password=issuer_password, roles=['cloud_soc_issuer'])
        configure_reader(client, monitor_password)
        # Create real limited clients through the product factory, never inject an admin/fake issuer.
        settings = {'STATE_DIR': root/'portal', 'AGENT_SOURCE': PROJECT/'deploy/agents',
            'CA_BYTES': (root/'ca.pem').read_bytes(), 'CA_FILE': str(root/'ca.pem'),
            'ENDPOINT': endpoint, 'PUBLIC_URL': 'https://127.0.0.1', 'ENROLLMENT_ENABLED': True,
            'ADMIN_USER': 'admin', 'ADMIN_HASH': generate_password_hash(admin_password),
            'ES_URL': endpoint, 'ES_PASSWORD': issuer_password, 'MONITOR_PASSWORD': monitor_password}
        app = create_app(settings)
        clients.extend([app.extensions['issuer'], app.extensions['monitor']])
        server = make_server('127.0.0.1', 0, app, threaded=True,
            ssl_context=(str(root/'server.pem'), str(root/'server.key')), request_handler=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f'https://127.0.0.1:{server.server_port}'
        context = ssl.create_default_context(cafile=str(root/'ca.pem'))
        basic = 'Basic ' + base64.b64encode(('admin:'+admin_password).encode()).decode()

        def call(path, data=None, *, token=None, rid=None, expected=200):
            headers = {'Host': '127.0.0.1', 'Authorization': 'Bearer '+token if token else basic,
                       'X-Cloud-SOC': 'installer' if token else 'portal'}
            if data is not None:
                headers['Content-Type'] = 'application/json'
            if rid:
                headers['Idempotency-Key'] = rid
            request = urllib.request.Request(origin+path, headers=headers,
                data=json.dumps(data).encode() if data is not None else None)
            try:
                response = urllib.request.urlopen(request, context=context, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read()
                if response.code != expected:
                    raise RuntimeError(f'HTTP contract failed: {path.rsplit("/", 1)[-1]} {response.code}')
                return json.loads(body) if 'json' in response.headers.get('Content-Type', '') else body

        rid = uuid.uuid4().hex
        body = {'label': 'Synthetic isolated Linux', 'organization': 'labschool', 'os': 'ubuntu', 'purpose': 'server'}
        device = call('/api/managed-devices', body, rid=rid, expected=201)['device']
        assert call('/api/managed-devices', body, rid=rid, expected=201)['device']['id'] == device['id']
        base = '/api/managed-devices/' + device['id']
        call(base+'/prepare', {'days': 1, 'renew': False}, rid=uuid.uuid4().hex)
        archive = call(base+'/download')
        with zipfile.ZipFile(io.BytesIO(archive)) as stream:
            registration = json.loads(stream.read('registration.json'))
            spec = json.loads(stream.read('package.json'))
            assert spec['managed_device_id'] == device['id']
        with zipfile.ZipFile(io.BytesIO(call(base+'/download'))) as stream:
            assert json.loads(stream.read('registration.json')) == registration
        attempt = secrets.token_urlsafe(32)
        enrollment = {'attempt': attempt, 'package_id': device['package_id'],
                      'package_sha256': registration['package_sha256']}
        reply = call('/api/installer/enroll', enrollment, token=registration['token'])
        assert reply == call('/api/installer/enroll', enrollment, token=registration['token'])
        assert reply['receipt_verified'] is False and len(reply['keys']) == 1
        host_key = reply['keys'][0]['key']
        sensitive.extend([host_key, host_key.split(':', 1)[1], registration['token'], attempt])
        record('device_create_prepare_redownload_real_key_exchange_idempotent')

        # Only these two synthetic lines are mounted into Filebeat; no host logs/socket.
        synthetic = {'@timestamp': datetime.now(timezone.utc).isoformat(),
            'event': {'action': 'installation_probe', 'kind': 'event'},
            'labels': {'installation_probe': reply['probe']}, 'message': 'Synthetic proof '+ 'x'*1100}
        (root/'synthetic.ndjson').write_text(json.dumps(synthetic)+'\n')
        beat_area = root/'beat'
        beat_area.mkdir()
        # Secrets are confined to a private temporary config; never argv/env/log/report.
        config = {'filebeat.inputs': [{'type': 'filestream', 'id': 'isolated-device-lab',
            'paths': ['/input/synthetic.ndjson'], 'prospector.scanner.check_interval': '1s',
            'prospector.scanner.fingerprint.length': 64,
            'parsers': [{'ndjson': {'target': '', 'add_error_key': True}}]}],
            'processors': [{'add_fields': {'target': 'organization', 'fields': {'id': 'forged-organization'}}}],
            'setup.ilm.enabled': False, 'setup.template.enabled': False,
            'queue.disk': {'max_size': '16MB', 'segment_size': '1MB'},
            'output.elasticsearch': {'hosts': ['https://elasticsearch:9200'], 'api_key': host_key,
                'ssl.certificate_authorities': ['/input/ca.pem'], 'ssl.verification_mode': 'full',
                'index': 'soc-host-raw-linux-lab', 'worker': 1, 'bulk_max_size': 2},
            'logging.level': 'error', 'logging.metrics.enabled': False}
        (beat_area/'filebeat.yml').write_text(json.dumps(config))
        # Narrow read-only input mount: do not expose the ES/admin/portal directory to the collector.
        inputs = root/'inputs'
        inputs.mkdir()
        shutil.copyfile(root/'ca.pem', inputs/'ca.pem')
        shutil.copyfile(root/'synthetic.ndjson', inputs/'synthetic.ndjson')
        containers.append(beat_name)
        command('run', '-d', '--name', beat_name, '--label', 'cloud-soc.lab='+label,
            '--network', label, '--memory', '384m', '--user', 'root',
            '--mount', f'type=bind,src={inputs},dst=/input,readonly',
            '--mount', f'type=bind,src={beat_area},dst=/usr/share/filebeat/data',
            BEAT_IMAGE, 'filebeat', '-e', '--strict.perms=false', '-c', '/usr/share/filebeat/data/filebeat.yml')

        def documents():
            try:
                client.indices.refresh(index='soc-host-raw-linux-lab')
                return client.search(index='soc-host-raw-linux-lab', query={'match_all': {}}, size=10)['hits']['hits']
            except ApiError as error:
                if error.status_code == 404:
                    return []
                raise
        hits = wait_for(documents)
        assert len(hits) == 1
        proof = hits[0]['_source']
        agent = proof['agent']['id']
        assert proof['organization']['id'] == 'labschool'
        assert proof['cloud_soc_enrollment']['key_id'] == reply['keys'][0]['id']
        receipt = call('/api/installer/receipt', {'attempt': attempt, 'agents': {'host': agent}},
                       token=registration['token'])
        assert receipt['verified'] is True
        assert call(base)['device']['state'] == 'received'
        assert call(base+'/activity')['observed_at'] is None
        record('real_filebeat_proof_metadata_binding_receipt_not_general_activity')
        normal = {'@timestamp': datetime.now(timezone.utc).isoformat(),
                  'event': {'action': 'synthetic_security_log'}, 'message': 'Synthetic security log '+'y'*1100}
        with (inputs/'synthetic.ndjson').open('a') as stream:
            stream.write(json.dumps(normal)+'\n')
        wait_for(lambda: len(documents()) == 2)
        activity = call(base+'/activity')
        assert activity['observed_at'] and len(activity['references']) == 1
        reference = activity['references'][0]
        raw = client.get(index=reference['index'], id=reference['id'])['_source']
        assert raw['message'] == normal['message'] and raw['agent']['id'] == agent
        assert raw['organization']['id'] == 'labschool'
        assert activity['heartbeat'] == activity['analysis'] == 'unknown'
        record('real_general_log_exact_index_id_organization_agent_reference')
        limited = Elasticsearch(endpoint, ca_certs=str(root/'ca.pem'), api_key=tuple(host_key.split(':', 1)),
                                max_retries=0, request_timeout=5)
        clients.append(limited)
        assert limited.info()['version']['number'] == '9.5.2'
        for name, action in (
                ('read', lambda: limited.search(index='soc-host-raw-linux-lab')),
                ('roles', lambda: limited.security.put_role(name='forbidden-lab-role', cluster=['all'])),
                ('delete', lambda: limited.delete(index=reference['index'], id=reference['id']))):
            try:
                action()
            except ApiError as error:
                result.setdefault('permission_status', {})[name] = error.status_code
                assert error.status_code == 403
            else:
                raise AssertionError('Publisher unexpectedly authorized')
        record('authenticated_publisher_cannot_read_change_roles_or_delete_raw')
        for url, ctx in ((origin, ssl.create_default_context()),
                         (origin.replace('127.0.0.1', 'localhost'), context)):
            try:
                urllib.request.urlopen(url+'/api/managed-devices', context=ctx, timeout=5)
            except urllib.error.URLError as error:
                assert isinstance(error.reason, ssl.SSLCertVerificationError)
            else:
                raise AssertionError('Invalid TLS accepted')
        denied = urllib.request.Request(origin+'/api/managed-devices', headers={
            'Host': '127.0.0.1', 'Authorization': 'Basic '+base64.b64encode(b'admin:wrong').decode()})
        try:
            urllib.request.urlopen(denied, context=context, timeout=5)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError('Invalid authentication accepted')
        record('portal_wrong_ca_hostname_password_fail_closed')
        for route in (base, '/api/managed-devices', base+'/diagnostics', '/api/key-history'):
            public = call(route)
            encoded = public if isinstance(public, bytes) else json.dumps(public).encode()
            assert host_key.encode() not in encoded and registration['token'].encode() not in encoded
        record('metadata_and_diagnostics_exclude_registration_and_publisher_secrets')
        end_id = uuid.uuid4().hex
        ended = call(base+'/end', {'confirm': True}, rid=end_id)['device']
        assert ended['state'] == 'ended' and ended['uninstalled'] is False
        assert call(base+'/end', {'confirm': True}, rid=end_id)['device']['state'] == 'ended'
        assert call('/api/managed-devices')['total'] == 0
        assert call('/api/managed-devices?view=history')['total'] == 1
        try:
            limited.info()
        except ApiError as error:
            assert error.status_code == 401
        else:
            raise AssertionError('Revoked publisher still authenticated')
        call('/api/installer/enroll', enrollment, token=registration['token'], expected=409)
        assert len(documents()) == 2
        record('real_remote_revocation_retry_history_old_credentials_blocked_raw_preserved')
        result['passed'] = True
    except Exception as error:
        result['passed'] = False
        result['failure_type'] = type(error).__name__
        # Avoid upstream exception bodies or credential-bearing HTTP objects.
        print('Lab failed ('+type(error).__name__+'); no upstream body printed.', flush=True)
        result['failure_location'] = [{'file': Path(frame.filename).name, 'line': frame.lineno}
                                      for frame in traceback.extract_tb(error.__traceback__)]
    finally:
        if result.get('passed') is False:
            result['container_errors'] = [redact(command('logs', '--tail', '18', name, check=False))[-6000:]
                                          for name in containers]
        if server:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        for client in clients:
            client.close()
        cleanup_errors = []
        for name in reversed(containers):
            command('rm', '-f', '-v', name, check=False)
            if command('ps', '-a', '--filter', 'name=^/'+name+'$', '--format', '{{.Names}}'):
                cleanup_errors.append('container')
        if network:
            command('network', 'rm', label, check=False)
            if command('network', 'ls', '--filter', 'name=^'+label+'$', '--format', '{{.Name}}'):
                cleanup_errors.append('network')
        for volume in volumes:
            command('volume', 'rm', volume, check=False)
            if command('volume', 'ls', '--filter', 'name=^'+volume+'$', '--format', '{{.Name}}'):
                cleanup_errors.append('volume')
        if root.is_relative_to(area.resolve()) and root.name.startswith(label):
            shutil.rmtree(root)
        result['cleanup'] = not root.exists() and not cleanup_errors
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2)+'\n')
        if not result['cleanup']:
            raise RuntimeError('Lab cleanup incomplete')
    return result['passed']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--report', type=Path, default=PROJECT/'state/install-device-ux/live-lab.json')
    args = parser.parse_args()
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    raise SystemExit(0 if run(args.docker, args.report) else 1)
