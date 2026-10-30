"""Real OpenSSL and loopback TLS; no existing server/agent data or Docker."""
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import ssl
import sys
import threading
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import ipaddress
import os
import pytest

if os.name != 'posix':
    pytest.skip('Enrollment PKI manages Ubuntu ownership and file locks', allow_module_level=True)

SERVER = Path(__file__).resolve().parents[1] / 'deploy/server'
sys.path.insert(0, str(SERVER))
import enrollment_pki as pki


def write_key(path, key):
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.TraditionalOpenSSL,
                                      serialization.NoEncryption()))
    path.chmod(0o600)


@pytest.fixture
def state(tmp_path):
    root = tmp_path / 'state'
    for folder in ('tls', 'private', 'portal', 'runtime'):
        (root / folder).mkdir(parents=True, mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key, server_key = rsa.generate_private_key(65537, 2048), rsa.generate_private_key(65537, 2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Isolated test CA')])
    ca = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
          .not_valid_after(now + timedelta(days=800))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(subject).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=100))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName('localhost'), x509.DNSName('elasticsearch'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (root / 'tls/ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / 'tls/server.crt').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (root / 'tls/server.crt').chmod(0o644)
    write_key(root / 'private/ca.key', ca_key)
    write_key(root / 'tls/server.key', server_key)
    (root / 'portal/data.sqlite').write_bytes(b'UNCHANGED_DATABASE')
    (root / 'runtime/registration.json').write_bytes(b'UNCHANGED_REGISTRATION')
    return root


def preserved(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in root.rglob('*') if path.is_file()
            and str(path.relative_to(root)) in {
                'tls/ca.crt', 'private/ca.key', 'tls/server.key',
                'portal/data.sqlite', 'runtime/registration.json'}}


def test_repair_preserves_ca_keys_data_sans_subject_and_allows_exact_rollback(state):
    before = preserved(state)
    old = (state / 'tls/server.crt').read_bytes()
    original = x509.load_pem_x509_certificate(old)
    result = pki.repair(state, 'https://127.0.0.1')
    assert preserved(state) == before
    assert result['server_certificate_reissued'] is True
    leaf = x509.load_pem_x509_certificate((state / 'tls/server.crt').read_bytes())
    assert leaf.subject == original.subject
    assert leaf.public_key().public_numbers() == original.public_key().public_numbers()
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value == original.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    points = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert points[0].full_name[0].value == 'https://127.0.0.1' + pki.CRL_PATH
    crl = x509.load_der_x509_crl((state / 'tls/ca.crl').read_bytes())
    ca = x509.load_pem_x509_certificate((state / 'tls/ca.crt').read_bytes())
    assert crl.is_signature_valid(ca.public_key())
    assert pki.restore(state, result['backup'])['restored']
    assert (state / 'tls/server.crt').read_bytes() == old
    assert not (state / 'tls/ca.crl').exists()
    assert preserved(state) == before


def test_refresh_keeps_existing_certificate_and_revocation_history(state):
    pki.repair(state, 'https://127.0.0.1')
    leaf = (state / 'tls/server.crt').read_bytes()
    # An independently recorded revoked serial must not disappear on renewal.
    ledger = state / 'private/enrollment-crl-index'
    ledger.write_text('R\t300101000000Z\t261001000000Z\t01\tunknown\t/CN=old-test-certificate\n')
    result = pki.repair(state, 'https://127.0.0.1')
    assert not result['server_certificate_reissued']
    assert (state / 'tls/server.crt').read_bytes() == leaf
    assert ledger.read_text().startswith('R\t')
    assert x509.load_der_x509_crl((state / 'tls/ca.crl').read_bytes()).get_revoked_certificate_by_serial_number(1)


def test_failed_publication_restores_previous_files(state):
    old = (state / 'tls/server.crt').read_bytes()
    original = pki.replace_file
    calls = 0
    def fail_once(*args, **kwargs):
        nonlocal calls
        if Path(args[0]).parent == state / 'private' or Path(args[0]).parent == state / 'tls':
            calls += 1
        if calls == 3:
            raise OSError('simulated failure')
        return original(*args, **kwargs)
    with patch.object(pki, 'replace_file', side_effect=fail_once):
        with pytest.raises(OSError):
            pki.repair(state, 'https://127.0.0.1')
    assert (state / 'tls/server.crt').read_bytes() == old
    assert not (state / 'tls/ca.crl').exists()
    assert not (state / 'private/enrollment-crl-index').exists()


def test_invalid_scope_symlink_and_changed_backup_refused(state, tmp_path):
    before = preserved(state)
    for url in ('http://127.0.0.1', 'https://other.invalid', 'https://127.0.0.1/?token=private'):
        with pytest.raises(ValueError):
            pki.repair(state, url)
    assert preserved(state) == before
    link = tmp_path / 'linked-state'
    link.symlink_to(state, target_is_directory=True)
    with pytest.raises(ValueError):
        pki.repair(link, 'https://127.0.0.1')
    result = pki.repair(state, 'https://127.0.0.1')
    backup = Path(result['backup'])
    (backup / 'server.crt').write_bytes(b'tampered')
    current = (state / 'tls/server.crt').read_bytes()
    with pytest.raises(ValueError):
        pki.restore(state, backup)
    assert (state / 'tls/server.crt').read_bytes() == current


def test_real_ubuntu_enrollment_tls_accepts_repaired_certificate_and_signed_crl(state):
    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            # Enrollment also performs TLS-only handshakes without HTTP.
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError):
                pass
        def do_GET(self):
            if self.path != pki.CRL_PATH:
                self.send_error(404)
                return
            self.send_response(200)
            self.end_headers()
            self.wfile.write((state / 'tls/ca.crl').read_bytes())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    origin = f'https://127.0.0.1:{server.server_port}'
    try:
        pki.repair(state, origin)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(state / 'tls/server.crt', state / 'tls/server.key')
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        location = Path(__file__).resolve().parents[1] / 'deploy/agents/enrollment-linux.py'
        spec = importlib.util.spec_from_file_location('isolated_enrollment_linux', location)
        enrollment = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(enrollment)
        trusted = enrollment.tls_context(state / 'tls', origin)
        assert trusted.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    finally:
        if 'thread' in locals():
            server.shutdown()
            thread.join(timeout=5)
        server.server_close()


def test_new_installation_produces_enrollment_compatible_tls(tmp_path):
    import prepare
    root = tmp_path / 'new-server'
    with patch.object(prepare.os, 'chown'):
        prepare.prepare('127.0.0.1', '127.0.0.1', root, 'isolated-test-password')
    leaf = x509.load_pem_x509_certificate((root / 'tls/server.crt').read_bytes())
    points = leaf.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
    assert points[0].full_name[0].value == 'https://127.0.0.1' + pki.CRL_PATH
    assert (root / 'tls/ca.crl').is_file()
    assert (root / 'compose.env').is_file()


def test_old_backup_cannot_erase_a_later_crl_refresh(state):
    first = pki.repair(state, 'https://127.0.0.1')
    pki.repair(state, 'https://127.0.0.1')
    current = (state / 'tls/ca.crl').read_bytes()
    with pytest.raises(ValueError):
        pki.restore(state, first['backup'])
    assert (state / 'tls/ca.crl').read_bytes() == current


def test_mismatched_key_is_refused_before_certificate_change(state):
    original = (state / 'tls/server.crt').read_bytes()
    write_key(state / 'tls/server.key', rsa.generate_private_key(65537, 2048))
    with pytest.raises(ValueError, match='개인키'):
        pki.repair(state, 'https://127.0.0.1')
    assert (state / 'tls/server.crt').read_bytes() == original
    assert not (state / 'tls/ca.crl').exists()
