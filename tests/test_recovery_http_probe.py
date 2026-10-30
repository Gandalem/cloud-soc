"""Real localhost HTTP/TLS, disposable keys, and no existing Docker or services."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import ssl
import subprocess
import sys
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from cloud_soc.deployment.recovery_health import HTTP_PROBE


@pytest.fixture(scope='module')
def tls_files(tmp_path_factory):
    folder = tmp_path_factory.mktemp('recovery-http-tls')
    now = datetime.now(timezone.utc)
    def ca(name):
        key = rsa.generate_private_key(65537, 2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
                .sign(key, hashes.SHA256()))
        return key, cert
    issuer, authority = ca('Disposable recovery CA')
    _, wrong = ca('Different disposable CA')
    key = rsa.generate_private_key(65537, 2048)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(authority.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), False)
            .sign(issuer, hashes.SHA256()))
    for name, value in (('ca.crt', authority), ('wrong.crt', wrong), ('server.crt', cert)):
        (folder / name).write_bytes(value.public_bytes(serialization.Encoding.PEM))
    (folder / 'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(folder / 'server.crt', folder / 'server.key')
    return folder, context


@contextmanager
def server(status, context=None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status if self.path == '/login' else 404)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *_):
            pass
    instance = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    if context:
        instance.socket = context.wrap_socket(instance.socket, server_side=True)
    thread = threading.Thread(target=instance.serve_forever, kwargs={'poll_interval': .02}, daemon=True)
    thread.start()
    try:
        yield instance.server_address[1]
    finally:
        instance.shutdown();instance.server_close();thread.join(timeout=2)


@pytest.mark.parametrize('fault,expected', [
    ('none', True), ('restricted', True), ('allowed_but_403', False), ('blocked_but_200', False),
    ('wrong_ca', False), ('wrong_hostname', False), ('backend_503', False), ('gateway_502', False),
])
def test_real_http_and_tls_require_readiness_and_keep_peer_policy(tls_files, fault, expected):
    folder, context = tls_files
    backend_status = 503 if fault == 'backend_503' else 200
    gateway_status = 403 if fault in ('restricted', 'allowed_but_403') else 502 if fault == 'gateway_502' else 200
    restricted = fault in ('restricted', 'blocked_but_200')
    with server(backend_status) as portal_port, server(gateway_status, context) as gateway_port:
        payload = {'seconds': 3, 'portal_host': 'portal.test', 'portal_port': portal_port,
                   'gateway': '127.0.0.1', 'gateway_host': 'wrong.test' if fault == 'wrong_hostname' else 'localhost',
                   'gateway_ports': [gateway_port], 'allowed': '192.0.2.0/24' if restricted else '127.0.0.1/32'}
        result = subprocess.run([sys.executable, '-c', HTTP_PROBE], input=json.dumps(payload),
            text=True, capture_output=True, timeout=8,
            env={**os.environ, 'SOC_CA_FILE': str(folder / ('wrong.crt' if fault == 'wrong_ca' else 'ca.crt'))})
    assert (result.returncode == 0) is expected
    assert result.stdout.strip() == ('recovery_http_ready' if expected else '')
    assert not result.stderr
