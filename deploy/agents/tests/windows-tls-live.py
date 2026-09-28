"""Loopback-only Schannel tests. No trust-store changes or agent installation.

Run with Python + cryptography on Windows. Temporary keys are synthetic and are
removed after the test; never use these certificates for a deployed server.
"""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(401)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *_):
        pass


@unittest.skipUnless(os.name == "nt", "Windows Schannel required")
class SchannelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloud-soc-tls-")
        self.root = Path(self.temp.name).resolve()
        self.servers = []
        self.now = datetime.now(timezone.utc)
        self.ca_key = rsa.generate_private_key(65537, 2048)
        self.ca = self.certificate(self.ca_key, "Synthetic Cloud SOC CA", ca=True)
        self.ca_path = self.root / "ca.crt"
        self.ca_path.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))
        self.curl = Path(os.environ['SystemRoot']) / 'System32/curl.exe'

    def certificate(self, key, name, *, ca=False, expired=False, wrong_host=False):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        builder = (x509.CertificateBuilder().subject_name(subject)
                   .issuer_name(subject if ca else self.ca.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(self.now - timedelta(days=2))
                   .not_valid_after(self.now + timedelta(days=-1 if expired else 1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if not ca:
            san = x509.DNSName("wrong.invalid") if wrong_host else x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
            builder = (builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
        return builder.sign(key if ca else self.ca_key, hashes.SHA256())

    def serve(self, **options):
        key = rsa.generate_private_key(65537, 2048)
        cert = self.certificate(key, 'Synthetic server', **options)
        cert_path, key_path = self.root / 'server.crt', self.root / 'server.key'
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        return f'https://127.0.0.1:{server.server_port}/'

    def probe(self, url, *, compatibility=False, ca=None):
        args = [str(self.curl), '--disable', '--silent', '--show-error', '--noproxy', '*',
                '--proto', '=https', '--tlsv1.2', '--retry', '0', '--max-redirs', '0',
                '--connect-timeout', '3', '--max-time', '8', '--cacert', str(ca or self.ca_path),
                '--output', 'NUL', '--write-out', '%{http_code}']
        if compatibility:
            args.append('--ssl-revoke-best-effort')
        return subprocess.run([*args, '--', url], capture_output=True, text=True, timeout=12)

    def test_private_ca_requires_explicit_compatibility(self):
        url = self.serve()
        strict = self.probe(url)
        self.assertEqual(strict.returncode, 60, strict.stderr)
        compatible = self.probe(url, compatibility=True)
        self.assertEqual(compatible.returncode, 0, compatible.stderr)
        self.assertEqual(compatible.stdout, '401')

    def test_wrong_host_still_rejected(self):
        self.assertEqual(self.probe(self.serve(wrong_host=True), compatibility=True).returncode, 60)

    def test_expired_still_rejected(self):
        self.assertEqual(self.probe(self.serve(expired=True), compatibility=True).returncode, 60)

    def test_wrong_ca_still_rejected(self):
        url = self.serve()
        other = self.certificate(rsa.generate_private_key(65537, 2048), 'Other CA', ca=True)
        path = self.root / 'other.crt'
        path.write_bytes(other.public_bytes(serialization.Encoding.PEM))
        self.assertEqual(self.probe(url, compatibility=True, ca=path).returncode, 60)

    def tearDown(self):
        for server, thread in self.servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
        # Only clean the exact temporary directory created by this test.
        assert self.root.parent == Path(tempfile.gettempdir()).resolve()
        assert self.root.name.startswith('cloud-soc-tls-')
        self.temp.cleanup()


if __name__ == '__main__':
    unittest.main()
