"""Ubuntu single-token installation and explicit failed-install re-enrollment.

Standard library + openssl/systemd. Secrets remain in process memory and stdin.
Protected receipts contain public identity/hashes; queues are never restored.
"""
import argparse
import datetime
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

STATE = Path('/var/lib/cloud-soc-enrollment')
ROOTS = {'host': Path('/opt/cloud-soc-agent'), 'network': Path('/opt/cloud-soc-network')}
SERVICES = {'host': 'cloud-soc-filebeat', 'network': 'cloud-soc-packetbeat'}
UNIT_ROOT = Path('/etc/systemd/system')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def private(path, directory=False):
    """Reject links/non-root writers, including every existing parent."""
    path = Path(path)
    for entry in [path, *path.parents]:
        info = entry.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
            raise RuntimeError('Untrusted installation ownership/path')
    if directory and not path.is_dir():
        raise RuntimeError('Directory required')


def save(path, data):
    private(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        private(path)
    temporary = path.with_name('.receipt-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def run(args, **kwargs):
    return subprocess.run([str(v) for v in args], check=True, **kwargs)


def system(*args):
    return run(['systemctl', *args])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def read_url(url, context=None, headers=None, data=None, limit=32768):
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, headers=headers or {}, data=data)
    try:
        with opener.open(request, timeout=15) as response:
            body = response.read(limit + 1)
            if response.status != 200 or len(body) > limit:
                raise RuntimeError('Unexpected response status/size')
            return body
    except urllib.error.HTTPError as error:
        raise RuntimeError('Enrollment request refused (HTTP %d)' % error.code) from None


def tls_context(source, portal):
    """Validate HTTPS identity, then a same-host signed CRL before sending keys.

    Public CRL transport may use HTTP: OpenSSL validates its signature and the
    final TLS handshake enforces issuer, validity and leaf revocation. No TLS or
    revocation relaxation is offered.
    """
    url = urllib.parse.urlsplit(portal)
    ca = source / 'ca.crt'
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((url.hostname, url.port or 443), timeout=15) as connection:
        with context.wrap_socket(connection, server_hostname=url.hostname) as tls:
            leaf = tls.getpeercert(binary_form=True)
    description = run(['openssl', 'x509', '-inform', 'DER', '-text', '-noout'], input=leaf, capture_output=True).stdout.decode()
    section = description.split('CRL Distribution Points:', 1)
    if len(section) != 2:
        raise RuntimeError('Server certificate requires an available signed CRL distribution point')
    links = re.findall(r'URI:(https?://[^\s]+)', section[1].split('X509v3', 1)[0])
    if len(links) != 1:
        raise RuntimeError('One same-host CRL URL is required')
    distribution = urllib.parse.urlsplit(links[0])
    if distribution.hostname != url.hostname or distribution.username or distribution.password or distribution.query or distribution.fragment:
        raise RuntimeError('CRL distribution authority differs')
    crl = read_url(links[0], context=context, limit=262144)
    with tempfile.TemporaryDirectory(prefix='cloud-soc-public-crl-') as temporary:
        directory = Path(temporary)
        os.chmod(directory, 0o700)
        der = directory / 'crl.der'
        der.write_bytes(crl)
        run(['openssl', 'crl', '-inform', 'DER', '-in', der, '-CAfile', ca, '-verify', '-noout'], capture_output=True)
        pem = run(['openssl', 'crl', '-inform', 'DER', '-in', der, '-outform', 'PEM'], capture_output=True).stdout
        trust = directory / 'trust.pem'
        trust.write_bytes(ca.read_bytes() + b'\n' + pem)
        context.load_verify_locations(cafile=str(trust))
    context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    with socket.create_connection((url.hostname, url.port or 443), timeout=15) as connection:
        with context.wrap_socket(connection, server_hostname=url.hostname):
            pass
    return context


class Client:
    def __init__(self, spec, context, token):
        self.spec, self.context, self.token = spec, context, token
        self.attempt = secrets.token_urlsafe(32)

    def post(self, action, body):
        headers = {'Authorization': 'Bearer ' + self.token, 'X-Cloud-SOC': 'installer', 'Content-Type': 'application/json'}
        payload = json.dumps({'attempt': self.attempt, **body}).encode()
        for attempt in range(3):
            try:
                return json.loads(read_url(self.spec['portal_url'] + '/api/installer/' + action,
                                           self.context, headers, payload))
            except (OSError, ValueError, RuntimeError):
                if attempt == 2:
                    raise RuntimeError('Enrollment request failed; no insecure retry') from None
                time.sleep(2)


def validate_reply(reply, spec, token, recovery=None):
    scopes = ['host', 'network'] if spec['network'] else ['host']
    if (not isinstance(reply, dict) or reply.get('id') != token[:32] or reply.get('endpoint') != spec['endpoint']
            or reply.get('organization') != spec['organization'] or reply.get('receipt_verified') is not False
            or not re.fullmatch(r'[a-f0-9]{64}', reply.get('probe', ''))
            or reply.get('recovery_probe') != recovery or not isinstance(reply.get('keys'), list)):
        raise RuntimeError('Enrollment response binding differs')
    keys = {}
    for entry in reply['keys']:
        scope = entry.get('scope')
        if scope not in scopes or scope in keys or not re.fullmatch(r'[A-Za-z0-9_-]+:[A-Za-z0-9_-]+', entry.get('key', '')):
            raise RuntimeError('Enrollment roles differ')
        keys[scope] = entry['key']
    if set(keys) != set(scopes):
        raise RuntimeError('Missing enrollment role')
    return keys


def roles(spec):
    return ['host', 'network'] if spec['network'] else ['host']


def units(spec):
    return [SERVICES[s] + '.service' for s in roles(spec)] + ['cloud-soc-discovery.service', 'cloud-soc-discovery.timer']


def beat_args(scope):
    root = ROOTS[scope]
    name = 'filebeat' if scope == 'host' else 'packetbeat'
    return [root / name / name, '--path.home', root / name, '--path.config', root,
            '--path.data', root / 'data', '--path.logs', root / 'logs', '-c', root / (name + '.yml')]


def stable(spec, owner):
    files = {}
    for scope in roles(spec):
        root = ROOTS[scope]
        private(root, directory=True)
        if (root / 'enrollment-owner.txt').read_text() != owner:
            raise RuntimeError('Enrollment root ownership differs')
        name = 'filebeat' if scope == 'host' else 'packetbeat'
        for relative in [name + '.yml', 'ca.crt', 'privacy.js', 'enrollment-owner.txt', 'data/' + name + '.keystore', name + '/' + name]:
            path = root / relative
            private(path)
            files[str(path)] = sha(path)
    for name in units(spec):
        path = UNIT_ROOT / name
        private(path)
        files[str(path)] = sha(path)
    return files


def validate_failed(source, spec, receipt):
    if (receipt.get('schema') != 1 or receipt.get('state') not in ('failed', 'preparing', 'starting')
            or not re.fullmatch(r'[a-f0-9]{32}', receipt.get('owner', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', receipt.get('probe', ''))):
        raise RuntimeError('Only a recognized failed enrollment can be re-enrolled')
    old = receipt['spec']
    if any(old[f] != spec[f] for f in ('os', 'network', 'endpoint', 'organization')) or receipt['ca_sha256'] != sha(source / 'ca.crt'):
        raise RuntimeError('Server/CA/organization/scope migration refused')
    if receipt.get('files') and stable(spec, receipt['owner']) != receipt['files']:
        raise RuntimeError('Protected failed installation changed')
    if not receipt.get('files'):
        for scope in roles(spec):
            root = ROOTS[scope]
            if not root.exists():
                continue
            private(root, directory=True)
            if (root / 'enrollment-owner.txt').read_text() != receipt['owner']:
                raise RuntimeError('Partial root ownership differs')
            for entry in root.rglob('*'):
                private(entry)
        for name in units(spec):
            unit = UNIT_ROOT / name
            if unit.exists():
                private(unit)
                root = ROOTS['network'] if name == 'cloud-soc-packetbeat.service' else ROOTS['host']
                # Partial units are archived, never executed or adopted.
                text = unit.read_text()
                identity = ('Unit=cloud-soc-discovery.service' in text if name == 'cloud-soc-discovery.timer'
                            else str(root) in text)
                if not identity:
                    raise RuntimeError('Partial unit identity differs')
    for name in units(spec):
        status = subprocess.run(['systemctl', 'is-active', '--quiet', name])
        if status.returncode == 0:
            raise RuntimeError('Collectors/Discovery must be stopped for re-enrollment')
    for scope in roles(spec):
        if subprocess.run(['pgrep', '-x', 'filebeat' if scope == 'host' else 'packetbeat'], stdout=subprocess.DEVNULL).returncode == 0:
            raise RuntimeError('Collector process is active')
    return receipt


def verify_source(source, network=False):
    seen = set()
    for line in (source / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([a-f0-9]{64})  ([A-Za-z0-9_.-]+)', line)
        if not match or match[2] in seen or sha(source / match[2]) != match[1]:
            raise RuntimeError('Bundle integrity check failed')
        seen.add(match[2])
    required = {'package.json','ca.crt','enrollment-linux.py','install-ubuntu.sh','discover-linux.sh','privacy.js'}
    if network:
        required |= {'install-network-ubuntu.sh', 'packetbeat.base.json'}
    if not required <= seen:
        raise RuntimeError('Incomplete bundle integrity list')


def probe(client, spec, marker, source_id):
    root = ROOTS['host']
    path = root / ('installation-probe-' + source_id + '.ndjson')
    definition = root / 'inputs' / ('installation-probe-' + source_id + '.yml')
    if path.exists() or definition.exists():
        raise RuntimeError('Synthetic probe already exists')
    event = {'@timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'event': {'action': 'installation_probe', 'kind': 'event'},
             'labels': {'installation_probe': marker}, 'message': 'Cloud SOC installation verification. ' + 'x' * 1100}
    path.write_text(json.dumps(event) + '\n')
    definition.write_text(json.dumps([{'type': 'filestream', 'id': 'installation-' + source_id, 'paths': [str(path)],
                                     'parsers': [{'ndjson': {'target': '', 'add_error_key': True}}]}]))
    if spec['network']:
        endpoint = urllib.parse.urlsplit(spec['endpoint'])
        with socket.create_connection((endpoint.hostname, endpoint.port or 443), timeout=10):
            pass
    agents = {s: json.loads((ROOTS[s] / 'data/meta.json').read_text())['uuid'] for s in roles(spec)}
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        for scope in roles(spec):
            system('is-active', '--quiet', SERVICES[scope])
        result = client.post('receipt', {'agents': agents})
        if result.get('verified') is True and result.get('state') == 'complete' and result.get('id') == client.token[:32]:
            print('Actual central documents verified for every required Linux collector.')
            return agents
        print('Waiting for actual central log/network documents...', flush=True)
        time.sleep(5)
    raise RuntimeError('Central receipt NOT verified; services stopped, keys revoked, queues retained')


def execute(source, spec, digest, interface, recovery, dry_run):
    if os.geteuid() != 0:
        raise RuntimeError('Administrator root is required')
    if not re.fullmatch(r'[a-f0-9]{64}', digest):
        raise RuntimeError('Supply the verified public archive SHA-256; never a token argument')
    if spec.get('os') != 'ubuntu' or spec.get('enrollment_protocol') != 1 or type(spec.get('network')) is not bool:
        raise RuntimeError('Fresh compatible Ubuntu package required')
    if spec['network'] and not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,14}', interface or ''):
        raise RuntimeError('Explicit capture interface required')
    verify_source(source, spec['network'])
    if dry_run:
        pending = STATE / 'pending.json'
        if recovery:
            private(pending)
            validate_failed(source, spec, json.loads(pending.read_text()))
        elif (pending.exists() or pending.is_symlink() or any(ROOTS[s].exists() or ROOTS[s].is_symlink() for s in roles(spec))
              or any((UNIT_ROOT / n).exists() or (UNIT_ROOT / n).is_symlink() for n in units(spec))):
            raise RuntimeError('Existing installation; no automatic replacement')
        print('DRY RUN: no token, network, key, file or service changes; local identity validated.')
        return
    import fcntl
    STATE.mkdir(mode=0o700, exist_ok=True)
    private(STATE, directory=True)
    lock_fd = os.open(STATE / 'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    private(STATE / 'install.lock')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending = STATE / 'pending.json'
        receipt = None
        if recovery:
            private(pending)
            receipt = validate_failed(source, spec, json.loads(pending.read_text()))
        else:
            if pending.exists() or pending.is_symlink() or any(ROOTS[s].exists() or ROOTS[s].is_symlink() for s in roles(spec)):
                raise RuntimeError('Existing installation/receipt; no automatic replacement')
            if any((UNIT_ROOT / name).exists() or (UNIT_ROOT / name).is_symlink() for name in units(spec)):
                raise RuntimeError('Existing unit; no automatic replacement')
        if spec['network'] and interface != 'any' and not (Path('/sys/class/net') / interface).is_dir():
            raise RuntimeError('Capture interface unavailable')
        if receipt and receipt.get('files') and spec['network']:
            configured = json.loads((ROOTS['network'] / 'packetbeat.yml').read_text())
            if configured.get('packetbeat.interfaces', {}).get('device') != interface:
                raise RuntimeError('Capture interface migration refused during re-enrollment')
        context = tls_context(source, spec['portal_url'])
        token = getpass.getpass('Paste ONE installation token (hidden input): ')
        if not re.fullmatch(r'[a-f0-9]{32}\.[A-Za-z0-9_-]{43}', token):
            raise RuntimeError('Invalid installation token')
        client = Client(spec, context, token)
        body = {'package_id': spec['package_id'], 'package_sha256': digest}
        if receipt:
            body['recovery_probe'] = receipt['probe']
        verified = False
        owner = receipt['owner'] if receipt else uuid.uuid4().hex
        state = {'schema': 1, 'state': 'preparing', 'owner': owner, 'spec': spec,
                 'ca_sha256': sha(source / 'ca.crt'), 'files': {}, 'probe': None, 'session': token[:32]}
        try:
            reply = client.post('enroll', body)
            keys = validate_reply(reply, spec, token, body.get('recovery_probe'))
            state['probe'] = reply['probe']
            if receipt and not receipt.get('files'):
                validate_failed(source, spec, receipt)
                archive = STATE / ('partial-backup-' + uuid.uuid4().hex)
                archive.mkdir(mode=0o700)
                save(archive / 'before.json', receipt)
                for scope in roles(spec):
                    if ROOTS[scope].exists():
                        ROOTS[scope].rename(archive / scope)
                for name in units(spec):
                    path = UNIT_ROOT / name
                    if path.exists():
                        path.rename(archive / name)
                system('daemon-reload')
                owner = uuid.uuid4().hex
                state['owner'] = owner
                receipt = None
            if receipt:
                backup = STATE / ('backup-' + uuid.uuid4().hex)
                backup.mkdir(mode=0o700)
                # Verify the whole stopped snapshot, preserve every queue/registry byte.
                for scope in roles(spec):
                    for path in ROOTS[scope].rglob('*'):
                        private(path)
                    shutil.copytree(ROOTS[scope], backup / scope, symlinks=False)
                    for path in ROOTS[scope].rglob('*'):
                        if path.is_symlink():
                            raise RuntimeError('Linked backup source refused')
                        if path.is_file() and sha(path) != sha(backup / scope / path.relative_to(ROOTS[scope])):
                            raise RuntimeError('Backup differs')
                save(backup / 'before.json', receipt)
                validate_failed(source, spec, receipt)
                for scope in roles(spec):
                    root = ROOTS[scope]
                    name = 'filebeat' if scope == 'host' else 'packetbeat'
                    config_path = root / (name + '.yml')
                    config = json.loads(config_path.read_text())
                    if scope == 'host':
                        config['processors'][-1]['add_fields']['fields']['installation_probe'] = state['probe']
                    else:
                        config['processors'][2]['add_fields']['fields']['installation_probe'] = state['probe']
                    save(config_path, config)
            save(pending, state)
            for scope in roles(spec):
                if receipt:
                    key_name = 'CLOUD_SOC_API_KEY' if scope == 'host' else 'CLOUD_SOC_NETWORK_API_KEY'
                    run(beat_args(scope) + ['keystore', 'add', key_name, '--stdin', '--force'], input=(keys[scope] + '\n').encode())
                    run(beat_args(scope) + ['test', 'config'])
                    run(beat_args(scope) + ['test', 'output'], timeout=90)
                else:
                    script = 'install-ubuntu.sh' if scope == 'host' else 'install-network-ubuntu.sh'
                    args = ['bash', source / script, '--endpoint', spec['endpoint'], '--ca', source / 'ca.crt', '--organization', spec['organization'],
                            '--prepare-only', '--enrollment-key-stdin', '--installation-probe', state['probe'], '--enrollment-owner', owner]
                    if scope == 'network':
                        args += ['--interface', interface]
                    run(args, input=(keys[scope] + '\n').encode(), timeout=1500)
            keys.clear()
            state['files'] = stable(spec, owner)
            state['state'] = 'starting'
            save(pending, state)
            for scope in roles(spec):
                system('enable', '--now', SERVICES[scope])
            system('enable', '--now', 'cloud-soc-discovery.timer')
            system('start', 'cloud-soc-discovery.service')
            time.sleep(3)
            state['agents'] = probe(client, spec, state['probe'], token[:32])
            verified = True
            state['state'] = 'complete'
            state['files'] = stable(spec, owner)
            save(STATE / ('complete-' + token[:32] + '.json'), state)
            pending.unlink()
            print('Cloud SOC installation completed; Linux central receipt verified.')
        finally:
            if not verified:
                for scope in roles(spec):
                    root = ROOTS[scope]
                    marker = root / 'enrollment-owner.txt'
                    if marker.exists() and marker.read_text() == owner:
                        subprocess.run(['systemctl', 'disable', '--now', SERVICES[scope]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if scope == 'host':
                            subprocess.run(['systemctl', 'disable', '--now', 'cloud-soc-discovery.timer'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                            subprocess.run(['systemctl', 'stop', 'cloud-soc-discovery.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    client.post('abort', {})
                    print('Failed installation keys revoked.')
                except Exception:
                    print('Key revocation NOT confirmed; cancel this enrollment in the portal.', file=sys.stderr)
                state['state'] = 'failed'
                try:
                    state['files'] = stable(spec, owner)
                except Exception:
                    state['files'] = {}
                if state['probe']:
                    save(pending, state)
            client.token = None
    finally:
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-sha256', required=True)
    parser.add_argument('--interface')
    parser.add_argument('--reenroll', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    os.umask(0o077)
    try:
        spec = json.loads((source / 'package.json').read_text())
        execute(source, spec, args.package_sha256, args.interface, args.reenroll, args.dry_run)
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        print('Enrollment NOT complete. Protected state retained; inspect the enrollment history before explicit --reenroll.', file=sys.stderr)
        return 1
    except Exception:
        print('Enrollment NOT complete. Protected state retained; inspect the enrollment history and use explicit --reenroll only after validation.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
