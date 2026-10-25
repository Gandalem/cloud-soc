"""Explicit VM-only negative TLS acceptance; no agent installation or OS trust changes."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import http.server
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import threading
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from device_os_live import HOST, PROJECT
from device_windows_live import WindowsLab


class TlsLab(WindowsLab):
    def save(self):
        body = json.dumps(self.report, indent=2) + '\n'
        (self.root/'native-tls-report.json').write_text(body)
        (self.log_dir/'report.json').write_text(body)

    def run(self):
        self.report.update(scope='Windows native pinned CA online revocation and hostname verification', checks=[])
        compiler = 'C:/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        probe = self.log_dir/'tls-probe.exe'
        subprocess.run([compiler, '/nologo', '/target:exe', '/platform:x64', '/define:NATIVE_INSTALLER',
                        '/main:NativeTlsProbeTest', '/out:'+str(probe),
                        str(PROJECT/'deploy/agents/tls-probe.cs'), str(PROJECT/'deploy/agents/native/TlsChain.cs'),
                        str(PROJECT/'deploy/agents/tests/native-tls-probe.cs')], check=True)
        root = self.guest_root
        self.ps("$r='"+root+"';if(Test-Path $r){throw 'Existing trial directory'};New-Item -ItemType Directory -Path $r | Out-Null;"
                "icacls $r /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null")
        self.upload(root+'\\probe.exe', probe.read_bytes())
        assert self.ps("(Get-FileHash '"+root+"\\probe.exe' -Algorithm SHA256).Hash.ToLowerInvariant()").strip() == hashlib.sha256(probe.read_bytes()).hexdigest()
        owner = self
        owner.crls = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = owner.crls.get(self.path)
                if self.server.server_port == 18766 and body is None:
                    self.send_error(503)
                    return
                body = body if body is not None else b'ok'
                self.send_response(200)
                self.send_header('Content-Type', 'application/pkix-crl' if self.server.server_port == 18766 else 'text/plain')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        crl_server = http.server.ThreadingHTTPServer((HOST, 18766), Handler)
        threading.Thread(target=crl_server.serve_forever, daemon=True).start()
        try:
            for case, expected in [('valid', 0), ('wrong_ca', 1), ('wrong_hostname', 1),
                                   ('revoked', 1), ('crl_unavailable', 1), ('expired', 1)]:
                now = datetime.now(timezone.utc)
                ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Native TLS '+uuid.uuid4().hex)])
                ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
                      .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
                      .not_valid_before(now-timedelta(days=2)).not_valid_after(now+timedelta(hours=2))
                      .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                      .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                      .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
                      .sign(ca_key, hashes.SHA256()))
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                serial = x509.random_serial_number()
                crl_path = '/crl-'+uuid.uuid4().hex+'.der'
                names = [x509.DNSName('wrong.example.test')] if case == 'wrong_hostname' else [x509.IPAddress(ipaddress.ip_address(HOST))]
                leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
                        .issuer_name(ca_name).public_key(key.public_key()).serial_number(serial)
                        .not_valid_before(now-timedelta(days=1)).not_valid_after(now-timedelta(hours=1) if case == 'expired' else now+timedelta(hours=1))
                        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
                        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
                        .add_extension(x509.SubjectAlternativeName(names), False)
                        .add_extension(x509.CRLDistributionPoints([x509.DistributionPoint(
                            full_name=[x509.UniformResourceIdentifier('http://'+HOST+':18766'+crl_path)],
                            relative_name=None, reasons=None, crl_issuer=None)]), False).sign(ca_key, hashes.SHA256()))
                crl = (x509.CertificateRevocationListBuilder().issuer_name(ca_name).last_update(now-timedelta(minutes=1))
                       .next_update(now+timedelta(hours=1)).add_extension(x509.CRLNumber(1), False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False))
                if case == 'revoked':
                    crl = crl.add_revoked_certificate(x509.RevokedCertificateBuilder().serial_number(serial)
                                                    .revocation_date(now-timedelta(minutes=1)).build())
                if case != 'crl_unavailable':
                    self.crls[crl_path] = crl.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
                (self.tls/'server.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
                (self.tls/'server.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                if case == 'valid':
                    first_ca = ca.public_bytes(serialization.Encoding.PEM)
                trusted = first_ca if case == 'wrong_ca' else ca.public_bytes(serialization.Encoding.PEM)
                self.upload(root+'\\ca.pem', trusted)
                server = http.server.ThreadingHTTPServer((HOST, 18771), Handler)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(str(self.tls/'server.pem'), str(self.tls/'server.key'))
                server.socket = context.wrap_socket(server.socket, server_side=True)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    output = self.ps("& '"+root+"\\probe.exe' 'https://"+HOST+":18771' '"+root+"\\ca.pem';'exit_code='+$LASTEXITCODE", timeout=90, check=False)
                    assert 'exit_code='+str(expected) in output, case+': unexpected native TLS result'
                    assert ('tls_validated' if expected == 0 else 'tls_rejected') in output
                    self.record('native_tls_'+case)
                finally:
                    server.shutdown()
                    server.server_close()
            assert self.ps('Get-ExecutionPolicy').strip() == 'Restricted'
            self.report['policy_unchanged'] = True
        finally:
            crl_server.shutdown()
            crl_server.server_close()
            (self.tls/'server.key').unlink(missing_ok=True)
            self.cleanup_guest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    lab = TlsLab('', args.state.resolve(strict=True), 'unused')
    lab.run()
    lab.save()


if __name__ == '__main__':
    main()
