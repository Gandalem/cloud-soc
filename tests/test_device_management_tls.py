"""Actual loopback HTTPS API flow, with synthetic issuer/search. Not a real Beat/ES deployment."""
import base64
from datetime import datetime, timedelta, timezone
import io
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from werkzeug.serving import make_server, WSGIRequestHandler

import test_device_management as fixture
from test_enrollment import AGENTS


class QuietHandler(WSGIRequestHandler):
    def log_request(self, *args):
        pass


def certificates(root):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable SOC test')])
    at = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=1))
        .not_valid_after(at+timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
        .sign(key, hashes.SHA256()))
    cert, private = root / 'test-ca.pem', root / 'test-key.pem'
    cert.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    return cert, private


class DeviceTLSFlowTests(unittest.TestCase):
    def test_https_create_download_register_receipt_end_and_tls_auth_failures(self):
        environment = fixture.DeviceManagementTests()
        environment.setUp()
        server = None
        try:
            environment.issuer.security = fixture.Security()
            environment.proof(host=1)
            with tempfile.TemporaryDirectory() as temporary:
                cert, private = certificates(Path(temporary))
                context = ssl.create_default_context(cafile=str(cert))
                server = make_server('127.0.0.1', 0, environment.app, threaded=True,
                                     ssl_context=(str(cert), str(private)), request_handler=QuietHandler)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                origin = f'https://127.0.0.1:{server.server_port}'
                basic = 'Basic ' + base64.b64encode(b'admin:synthetic-password').decode()
                def call(path, data=None, authorization=basic, request_id=None, machine=False):
                    headers = {'Host': 'soc.example.test', 'Authorization': authorization,
                        'X-Cloud-SOC': 'installer' if machine else 'portal'}
                    if request_id:
                        headers['Idempotency-Key'] = request_id
                    if data is not None:
                        headers['Content-Type'] = 'application/json'
                    request = urllib.request.Request(origin + path, headers=headers,
                        data=json.dumps(data).encode() if data is not None else None)
                    with urllib.request.urlopen(request, context=context, timeout=5) as response:
                        body = response.read()
                        return json.loads(body) if 'json' in response.headers.get('Content-Type', '') else body
                request_id = uuid.uuid4().hex
                spec = {'label': '합성 TLS 장치', 'organization': 'school', 'os': 'windows', 'purpose': 'server'}
                device = call('/api/managed-devices', spec, request_id=request_id)['device']
                self.assertEqual(device['id'], call('/api/managed-devices', spec, request_id=request_id)['device']['id'])
                base = '/api/managed-devices/' + device['id']
                call(base + '/prepare', {'days': 1, 'renew': False}, request_id=uuid.uuid4().hex)
                payload = call(base + '/download')
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    registration = json.loads(archive.read('registration.json'))
                    self.assertIn('package.zip', archive.namelist())
                    self.assertIn('cloud-soc-agent-setup.exe', archive.namelist())
                    self.assertNotIn('bootstrap-windows.ps1', archive.namelist())
                attempt = secrets.token_urlsafe(32)
                authorization = 'Bearer ' + registration['token']
                reply = call('/api/installer/enroll', {'attempt': attempt, 'package_id': device['package_id'],
                    'package_sha256': registration['package_sha256']}, authorization=authorization, machine=True)
                self.assertFalse(reply['receipt_verified'])
                self.assertEqual(environment.issuer.security.calls, 1)
                complete = call('/api/installer/receipt', {'attempt': attempt, 'agents': {'host': AGENTS['host']}},
                                authorization=authorization, machine=True)
                self.assertTrue(complete['verified'])
                self.assertEqual(call(base)['device']['state'], 'received')
                end_id = uuid.uuid4().hex
                self.assertEqual(call(base + '/end', {'confirm': True}, request_id=end_id)['device']['state'], 'ended')
                self.assertEqual(call(base + '/end', {'confirm': True}, request_id=end_id)['device']['state'], 'ended')
                self.assertEqual(call('/api/managed-devices')['total'], 0)
                self.assertEqual(call('/api/managed-devices?view=history')['total'], 1)
                with self.assertRaises(urllib.error.HTTPError) as error:
                    call('/api/managed-devices', authorization='Basic ' + base64.b64encode(b'admin:wrong').decode())
                self.assertEqual(error.exception.code, 401)
                with self.assertRaises(urllib.error.URLError):
                    urllib.request.urlopen(origin + '/api/managed-devices', context=ssl.create_default_context(), timeout=5)
                with self.assertRaises(urllib.error.URLError):
                    urllib.request.urlopen(origin.replace('127.0.0.1', 'localhost') + '/api/managed-devices', context=context, timeout=5)
                self.assertNotIn(registration['token'].encode(), call(base).__str__().encode())
        finally:
            if server:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            environment.tearDown()
            environment.doCleanups()
            self.assertFalse(environment.root.exists())


if __name__ == '__main__':
    unittest.main()
