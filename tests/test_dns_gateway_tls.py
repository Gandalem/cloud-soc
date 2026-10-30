"""Opt-in real Caddy TLS/Host routing to the actual Portal on disposable loopback ports."""
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from unittest.mock import Mock

import pytest
from werkzeug.serving import make_server, WSGIRequestHandler

from cloud_soc.portal.app import create_app
from test_portal import AUTH, HASH, ROOT, CA

CADDY = os.environ.get('SOC_TEST_CADDY')


def port():
    with socket.socket() as stream:
        stream.bind(('127.0.0.1', 0))
        return stream.getsockname()[1]


class QuietHandler(WSGIRequestHandler):
    def log(self, *args, **kwargs):
        pass


@pytest.mark.skipif(not CADDY or not shutil.which('openssl'), reason='Verified Caddy and OpenSSL are needed')
def test_actual_tls_alias_and_existing_host_keep_authentication_and_origin_checks(tmp_path):
    cert, key = tmp_path / 'server.crt', tmp_path / 'server.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=soc.example.test', '-addext', 'subjectAltName=DNS:soc.example.test,DNS:extra.example.test',
        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True, timeout=30)
    app = create_app({'STATE_DIR': tmp_path / 'portal', 'AGENT_SOURCE': ROOT / 'deploy/agents', 'CA_BYTES': CA,
        'PUBLIC_URL': 'https://school.ngrok-free.app',
        'ADDITIONAL_ORIGINS': ['https://soc.example.test', 'https://extra.example.test'],
        'ENDPOINT': 'https://receiver.test:9200', 'ADMIN_USER': 'admin', 'ADMIN_HASH': HASH}, issuer=Mock())
    server = make_server('127.0.0.1', 0, app, request_handler=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
    process = None
    try:
        env = {k: v for k, v in os.environ.items() if not k.startswith('SOC_')}
        env.update(SOC_PUBLIC_HOST='soc.example.test', SOC_PORTAL_LAN_ORIGIN='https://school.ngrok-free.app',
                   SOC_PORTAL_TLS_ORIGINS='https://extra.example.test', SOC_ADMIN_ALLOWED_CIDRS='127.0.0.1/32')
        adapted = subprocess.run([CADDY, 'adapt', '--adapter', 'caddyfile', '--config',
            str(ROOT / 'deploy/server/Caddyfile')], check=True, capture_output=True, text=True, timeout=20, env=env)
        config = json.loads(adapted.stdout)
        substitutions = {'/certs/server.crt': str(cert), '/certs/server.key': str(key),
                         'portal:8000': '127.0.0.1:' + str(server.server_port),
                         'kibana:5601': '127.0.0.1:' + str(server.server_port)}
        def replace(value):
            if isinstance(value, dict):
                return {k: replace(v) for k, v in value.items()}
            if isinstance(value, list):
                return [replace(v) for v in value]
            return substitutions.get(value, value) if isinstance(value, str) else value
        config = replace(config)
        config['admin'] = {'disabled': True, 'config': {'persist': False}}
        config['storage'] = {'module': 'file_system', 'root': str(tmp_path / 'caddy-storage')}
        env.update(XDG_DATA_HOME=str(tmp_path / 'caddy-data'), XDG_CONFIG_HOME=str(tmp_path / 'caddy-config'))
        target = None
        for row in config['apps']['http']['servers'].values():
            chosen = port()
            if ':443' in row['listen']:
                target = chosen
            row['listen'] = ['127.0.0.1:' + str(chosen)]
        assert target is not None
        path = tmp_path / 'caddy.json';path.write_text(json.dumps(config), encoding='utf-8')
        with (tmp_path / 'caddy.log').open('wb') as log:
            process = subprocess.Popen([CADDY, 'run', '--config', str(path)], env=env, stdout=log, stderr=log)
            deadline = time.monotonic() + 10
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', target), timeout=0.2):
                        break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        pytest.fail('Disposable gateway did not start')
                    time.sleep(0.05)
            def get(host, *, auth=False, origin=None, context=None, sni='soc.example.test'):
                context = context or ssl.create_default_context(cafile=str(cert))
                connection = http.client.HTTPConnection('127.0.0.1', target, timeout=5)
                raw = socket.create_connection(('127.0.0.1', target), timeout=5)
                try:
                    connection.sock = context.wrap_socket(raw, server_hostname=sni)
                    headers = {'Host': host}
                    if auth:
                        headers['Authorization'] = AUTH
                    if origin:
                        headers['Origin'] = origin
                    connection.request('GET', '/api/auth/me', headers=headers)
                    response = connection.getresponse();response.read()
                    return response.status
                finally:
                    connection.close();raw.close()
            assert get('school.ngrok-free.app') == 401
            assert get('school.ngrok-free.app', auth=True) == 200
            assert get('extra.example.test', sni='extra.example.test') == 401
            assert get('extra.example.test', sni='extra.example.test', auth=True,
                       origin='https://extra.example.test') == 200
            assert get('extra.example.test', auth=True, origin='https://school.ngrok-free.app') == 403
            with pytest.raises(ssl.SSLCertVerificationError):
                get('extra.example.test', context=ssl.create_default_context())
            # Unknown SNI may be rejected by Caddy before a certificate is sent.
            with pytest.raises(ssl.SSLError):
                get('extra.example.test', sni='unknown.example.test')
    finally:
        if process is not None:
            process.terminate();process.wait(timeout=10)
        server.shutdown();server.server_close();thread.join(timeout=5)
