"""Real loopback TLS handshake; disposable certificates and no host-service queries."""
from contextlib import contextmanager
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import sqlite3
import ssl
import subprocess
import threading
from urllib.error import URLError

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('quality_device_reporter', ROOT / 'tools/device_heartbeat.py')
reporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reporter)
CREDENTIAL = 'a' * 32 + '.' + 'b' * 43
GENERATION = 'c' * 32


@pytest.fixture(scope='module')
def certificates(tmp_path_factory):
    openssl = shutil.which('openssl')
    if not openssl and os.name == 'nt':
        candidate = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/usr/bin/openssl.exe'
        if candidate.is_file():
            openssl = str(candidate)
    if not openssl:
        pytest.skip('Real loopback TLS requires openssl to generate disposable certificates')
    folder = tmp_path_factory.mktemp('tls-certificates')
    for name in ('server', 'unrelated'):
        result = subprocess.run([openssl, 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                                 '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                                 '-keyout', str(folder / (name + '.key')), '-out', str(folder / (name + '.crt'))],
                                capture_output=True, timeout=30, env={**os.environ, 'MSYS_NO_PATHCONV': '1'})
        assert result.returncode == 0, 'Disposable certificate generation failed'
        (folder / (name + '.key')).chmod(0o600)
    yield folder
    # The pytest temporary directory is disposable; remove private keys explicitly.
    for path in folder.iterdir():
        path.unlink()


@contextmanager
def server(certificates):
    records = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            records.append((self.path, dict(self.headers), body))
            payload = b'{"accepted":true}'
            self.send_response(200)
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
    http = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificates / 'server.crt', certificates / 'server.key')
    http.socket = context.wrap_socket(http.socket, server_side=True)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield http.server_address[1], records
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


def config(tmp_path, port, hostname='localhost'):
    path = tmp_path / 'reporter.json'
    path.write_text(json.dumps({'url': f'https://{hostname}:{port}/api/dashboard-heartbeat',
                              'credential': CREDENTIAL, 'generation': GENERATION, 'service': 'synthetic.service'}), encoding='utf-8')
    path.chmod(0o600)
    return path


def sequence(path):
    with sqlite3.connect(path) as db:
        return db.execute('SELECT value FROM sequences WHERE generation=?', (GENERATION,)).fetchone()[0]


def test_real_tls_valid_ca_and_hostname_sequences_and_no_secret_state(certificates, tmp_path, monkeypatch):
    monkeypatch.setattr(reporter, 'collector', lambda _: {'state': 'running'})
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:1')
    with server(certificates) as (port, records):
        settings = config(tmp_path, port)
        state = tmp_path / 'sequence.sqlite'
        assert reporter.send(settings, state, certificates / 'server.crt') == {'accepted': True, 'sequence': 1}
        assert reporter.send(settings, state, certificates / 'server.crt') == {'accepted': True, 'sequence': 2}
        assert [row[2]['sequence'] for row in records] == [1, 2]
        assert records[0][0] == '/api/dashboard-heartbeat'
        assert records[0][1]['Authorization'] == 'Bearer ' + CREDENTIAL
        assert records[0][2]['generation'] == GENERATION
        assert set(records[0][2]) == {'generation', 'sequence', 'generated_at', 'collector'}
        assert CREDENTIAL.encode() not in state.read_bytes()
        assert sequence(state) == 2


@pytest.mark.parametrize('failure', ['untrusted_ca', 'wrong_hostname'])
def test_real_certificate_failures_send_no_application_request(certificates, tmp_path, monkeypatch, failure):
    monkeypatch.setattr(reporter, 'collector', lambda _: {'state': 'running'})
    with server(certificates) as (port, records):
        settings = config(tmp_path, port, '127.0.0.1' if failure == 'wrong_hostname' else 'localhost')
        ca = certificates / ('unrelated.crt' if failure == 'untrusted_ca' else 'server.crt')
        state = tmp_path / 'sequence.sqlite'
        with pytest.raises(URLError) as error:
            reporter.send(settings, state, ca)
        assert isinstance(error.value.reason, ssl.SSLCertVerificationError)
        assert records == [] and sequence(state) == 1
        # Retry uses the next durable sequence, without resetting the generation or copying credentials to state.
        settings = config(tmp_path, port)
        assert reporter.send(settings, state, certificates / 'server.crt')['sequence'] == 2
        assert len(records) == 1 and CREDENTIAL.encode() not in state.read_bytes()


def test_reporter_cli_does_not_print_secret_exception(tmp_path, monkeypatch, capsys):
    import sys
    monkeypatch.setattr(sys, 'argv', ['reporter', '--config', str(tmp_path / 'private.json'), '--state', str(tmp_path / 's.sqlite'), '--ca', 'synthetic.crt'])
    def fail(*_):
        raise ValueError(CREDENTIAL)
    monkeypatch.setattr(reporter, 'send', fail)
    assert reporter.main() == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {'accepted': False, 'error': 'state_report_failed'}
    assert CREDENTIAL not in captured.out + captured.err
