"""Preserving enrollment TLS repair using the existing CA and server key.

Only certificates, a public CRL and its private issuance ledger are changed.
No Docker operations, credentials, application databases or agent state access.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import urlsplit

CRL_PATH = '/.well-known/cloud-soc/ca.crl'


def openssl(*args, input=None):
    result = subprocess.run(['openssl', *map(str, args)], input=input,
                            capture_output=True, timeout=30, check=False)
    if result.returncode:
        # OpenSSL diagnostics may contain protected paths; do not expose them.
        raise ValueError('인증서 또는 CRL 처리 실패. 기존 CA와 키는 변경하지 않았습니다')
    return result.stdout


def safe_path(root, relative, *, required=False):
    path = root / relative
    current = path
    while current != root:
        if current.is_symlink():
            raise ValueError('보호 경로의 심볼릭 링크는 허용하지 않습니다')
        current = current.parent
    if required and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError('필수 보호 파일이 없거나 공유된 파일입니다')
    if path.exists() and not path.is_file():
        raise ValueError('보호 파일 경로가 일반 파일이 아닙니다')
    return path


def distribution_url(portal):
    url = urlsplit(portal)
    if (url.scheme != 'https' or not url.hostname or url.username or url.password
            or url.query or url.fragment or url.path not in ('', '/')
            or any(c.isspace() for c in portal)):
        raise ValueError('--portal-url에는 실제 HTTPS 포털 주소만 지정하세요')
    if url.port is not None and not 1 <= url.port <= 65535:
        raise ValueError('포털 포트가 올바르지 않습니다')
    if not re.fullmatch(r'[A-Za-z0-9.:-]+', url.hostname):
        raise ValueError('포털 DNS 또는 IP가 올바르지 않습니다')
    return f'https://{url.netloc}{CRL_PATH}'


def subject_alternatives(cert):
    description = openssl('x509', '-in', cert, '-noout', '-ext', 'subjectAltName').decode('ascii')
    if 'Subject Alternative Name:' not in description:
        raise ValueError('기존 서버 인증서에 SAN이 없어 자동 변경하지 않았습니다')
    names = []
    for item in description.split('Subject Alternative Name:', 1)[1].strip().split(','):
        item = item.strip()
        if item.startswith('DNS:') and re.fullmatch(r'[A-Za-z0-9.*-]+', item[4:]):
            names.append(item)
        elif item.startswith('IP Address:'):
            names.append('IP:' + str(ipaddress.ip_address(item.split(':', 1)[1])))
        else:
            raise ValueError('미지원 SAN 형식이 있어 수동 인증서 관리가 필요합니다')
    if not names:
        raise ValueError('기존 인증서 SAN이 없습니다')
    return names


@contextmanager
def locked(state):
    path = safe_path(state, 'private/enrollment-pki.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def replace_file(path, data, *, metadata=None, mode=0o600):
    fd, name = tempfile.mkstemp(prefix='.enrollment-pki-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode) if metadata else mode)
            if metadata:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def repair(state, portal, *, days=7):
    state = Path(state).absolute()
    if state.is_symlink() or state.resolve() != state:
        raise ValueError('서버 상태는 심볼릭 링크가 없는 절대 경로여야 합니다')
    if type(days) is not int or not 1 <= days <= 30:
        raise ValueError('CRL 유효기간은 1..30일입니다')
    ca = safe_path(state, 'tls/ca.crt', required=True)
    ca_key = safe_path(state, 'private/ca.key', required=True)
    key = safe_path(state, 'tls/server.key', required=True)
    cert = safe_path(state, 'tls/server.crt', required=True)
    distribution = distribution_url(portal)
    with locked(state):
        return _repair(state, distribution, ca, ca_key, key, cert, days)


def _repair(state, distribution, ca, ca_key, key, cert, days):
    for certificate, private_key in ((ca, ca_key), (cert, key)):
        public = openssl('x509', '-in', certificate, '-pubkey', '-noout')
        if public != openssl('pkey', '-in', private_key, '-pubout'):
            raise ValueError('기존 인증서와 개인키가 일치하지 않아 중단했습니다')
    openssl('verify', '-CAfile', ca, cert)
    url = urlsplit(distribution)
    try:
        ipaddress.ip_address(url.hostname)
        check = '-checkip'
    except ValueError:
        check = '-checkhost'
    # OpenSSL -checkhost may report mismatch with exit 0; verify is fail-closed.
    openssl('verify', '-CAfile', ca, '-verify_ip' if check == '-checkip' else '-verify_hostname', url.hostname, cert)
    sans = subject_alternatives(cert)
    extension = openssl('x509', '-in', cert, '-noout', '-ext', 'crlDistributionPoints').decode()
    existing_urls = re.findall(r'URI:(\S+)', extension)
    if existing_urls and existing_urls != [distribution]:
        raise ValueError('기존 CRL 배포 정책이 달라 자동 변경하지 않았습니다')
    ledger_rel = 'private/enrollment-crl-index'
    number_rel = 'private/enrollment-crl-number'
    crl_rel = 'tls/ca.crl'
    paths = {relative: safe_path(state, relative) for relative in (ledger_rel, number_rel, crl_rel)}
    present = [p.exists() for p in paths.values()]
    if any(present) and not all(present):
        raise ValueError('기존 CRL 관리 자료가 불완전해 초기화하지 않았습니다')
    if existing_urls and not all(present):
        raise ValueError('기존 CRL 폐기 이력을 찾을 수 없어 새 빈 CRL로 대체하지 않았습니다')
    protected = {p: hashlib.sha256(p.read_bytes()).hexdigest() for p in (ca, ca_key, key)}
    targets = [cert, *paths.values()]
    before = {p: (p.read_bytes(), p.stat()) if p.exists() else None for p in targets}
    with tempfile.TemporaryDirectory(prefix='enrollment-pki-', dir=state / 'private') as folder:
        work = Path(folder)
        index, number = work / 'index', work / 'crlnumber'
        index.write_bytes(paths[ledger_rel].read_bytes() if all(present) else b'')
        number.write_bytes(paths[number_rel].read_bytes() if all(present) else b'01\n')
        config = work / 'ca.cnf'
        # Quoted OpenSSL paths; refuse config metacharacters rather than escaping secrets.
        for path in (ca, ca_key, work):
            if any(c in str(path) for c in ('\n', '\r', '"', '$', '\\')):
                raise ValueError('OpenSSL 설정에 사용할 수 없는 상태 경로입니다')
        config.write_text('[ca]\ndefault_ca=issuer\n[issuer]\n'
                          f'database="{index}"\ncrlnumber="{number}"\n'
                          f'certificate="{ca}"\nprivate_key="{ca_key}"\n'
                          f'default_md=sha256\ndefault_crl_days={days}\n'
                          'crl_extensions=crl_ext\n[crl_ext]\nauthorityKeyIdentifier=keyid:always\n')
        pem, der = work / 'crl.pem', work / 'ca.crl'
        openssl('ca', '-batch', '-config', config, '-gencrl', '-out', pem)
        openssl('crl', '-in', pem, '-CAfile', ca, '-verify', '-noout')
        openssl('crl', '-in', pem, '-outform', 'DER', '-out', der)
        candidate = work / 'server.crt'
        if existing_urls:
            shutil.copyfile(cert, candidate)
        else:
            csr, ext = work / 'server.csr', work / 'server.ext'
            openssl('x509', '-x509toreq', '-in', cert, '-signkey', key, '-out', csr)
            ext.write_text(f'subjectAltName={",".join(sans)}\n'
                           'basicConstraints=critical,CA:FALSE\n'
                           'keyUsage=critical,digitalSignature,keyEncipherment\n'
                           'extendedKeyUsage=serverAuth,clientAuth\n'
                           f'crlDistributionPoints=URI:{distribution}\n')
            openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key,
                    '-set_serial', '0x' + secrets.token_hex(16), '-days', '365',
                    '-sha256', '-extfile', ext, '-out', candidate)
        openssl('verify', '-CAfile', ca, '-CRLfile', pem, '-crl_check', candidate)
        if subject_alternatives(candidate) != sans:
            raise ValueError('SAN 보존 실패')
        for path, digest in protected.items():
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('보호 파일이 작업 중 변경되어 적용하지 않았습니다')
        backup_root = state / 'private/enrollment-tls-backups'
        if backup_root.is_symlink():
            raise ValueError('백업 경로가 심볼릭 링크입니다')
        backup_root.mkdir(exist_ok=True, mode=0o700)
        backup = backup_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + secrets.token_hex(6))
        backup.mkdir(mode=0o700)
        for path, original in before.items():
            if original is not None:
                (backup / path.name).write_bytes(original[0])
                (backup / path.name).chmod(0o600)
        changes = {cert: candidate.read_bytes(), paths[ledger_rel]: index.read_bytes(),
                   paths[number_rel]: number.read_bytes(), paths[crl_rel]: der.read_bytes()}
        manifest = {'schema': 1, 'state': str(state), 'protected': {str(p.relative_to(state)): h for p, h in protected.items()},
                    'files': {str(p.relative_to(state)): {
                        'before': ({'sha256': hashlib.sha256(before[p][0]).hexdigest(),
                                    'mode': stat.S_IMODE(before[p][1].st_mode),
                                    'uid': before[p][1].st_uid, 'gid': before[p][1].st_gid}
                                   if before[p] else None),
                        'after_sha256': hashlib.sha256(data).hexdigest()}
                        for p, data in changes.items()}}
        replace_file(backup / 'manifest.json', json.dumps(manifest, indent=2).encode())
        applied = []
        try:
            for path, data in changes.items():
                replace_file(path, data, metadata=before[path][1] if before[path] else None,
                             mode=0o644 if path == paths[crl_rel] else 0o600)
                applied.append(path)
        except BaseException:
            for path in reversed(applied):
                original = before[path]
                if original is None:
                    path.unlink(missing_ok=True)
                else:
                    replace_file(path, original[0], metadata=original[1])
            raise
        receipt = {'ca_replaced': False, 'private_keys_replaced': False,
                   'server_certificate_reissued': not bool(existing_urls),
                   'crl_url': distribution, 'crl_valid_days': days,
                   'backup': str(backup), 'services_reloaded': False}
        return receipt


def restore(state, backup):
    """Explicit rollback only while the installed files still match this change."""
    state, backup = Path(state).absolute(), Path(backup).absolute()
    if state.resolve() != state or backup.resolve() != backup:
        raise ValueError('복원 경로에 심볼릭 링크가 있습니다')
    if backup.parent != state / 'private/enrollment-tls-backups':
        raise ValueError('이 서버의 보호 백업 경로만 복원할 수 있습니다')
    with locked(state):
        manifest = json.loads(safe_path(state, str((backup / 'manifest.json').relative_to(state)), required=True).read_text())
        expected = {'tls/server.crt', 'tls/ca.crl', 'private/enrollment-crl-index', 'private/enrollment-crl-number'}
        if manifest.get('schema') != 1 or manifest.get('state') != str(state) or set(manifest.get('files', {})) != expected:
            raise ValueError('백업 명세가 현재 서버와 일치하지 않습니다')
        for relative in ('tls/ca.crt', 'private/ca.key', 'tls/server.key'):
            path = safe_path(state, relative, required=True)
            if hashlib.sha256(path.read_bytes()).hexdigest() != manifest['protected'].get(relative):
                raise ValueError('CA 또는 개인키가 변경되어 복원하지 않았습니다')
        originals = {}
        for relative, entry in manifest['files'].items():
            path = safe_path(state, relative)
            current = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            before_hash = entry['before']['sha256'] if entry['before'] else None
            if current not in (entry['after_sha256'], before_hash):
                raise ValueError('이후 인증서 또는 CRL이 변경되어 이전 자료로 덮어쓰지 않았습니다')
            if entry['before']:
                original = safe_path(state, str((backup / path.name).relative_to(state)), required=True).read_bytes()
                if hashlib.sha256(original).hexdigest() != before_hash:
                    raise ValueError('백업 내용이 변경되어 복원하지 않았습니다')
                originals[path] = (original, entry['before'])
            else:
                originals[path] = None
        for path, original in originals.items():
            if original is None:
                path.unlink(missing_ok=True)
            else:
                data, attrs = original
                replace_file(path, data, mode=attrs['mode'])
                os.chown(path, attrs['uid'], attrs['gid'])
        return {'restored': True, 'ca_replaced': False, 'private_keys_replaced': False, 'services_reloaded': False}


def install_renewal(state, portal, script, *, days=7):
    """Explicit installer action; daily CRL publication needs no gateway restart."""
    state, script = Path(state).resolve(), Path(script).resolve()
    distribution_url(portal)
    if not 1 <= days <= 30:
        raise ValueError('CRL 유효기간은 1..30일입니다')
    values = (str(script), str(state), portal)
    if any(any(c in value for c in ('"', '\\', '\n', '\r', '%', '$')) for value in values):
        raise ValueError('systemd 인수에 사용할 수 없는 경로 또는 주소입니다')
    name = 'cloud-soc-crl-' + hashlib.sha256(str(state).encode()).hexdigest()[:12]
    folder = Path('/etc/systemd/system')
    service = ('[Unit]\nDescription=Cloud SOC signed CRL renewal\n'
               '[Service]\nType=oneshot\nUMask=0077\n'
               f'ExecStart=/usr/bin/python3 "{script}" --state "{state}" --portal-url "{portal}" --crl-days {days}\n')
    timer = ('[Unit]\nDescription=Daily Cloud SOC CRL publication\n[Timer]\n'
             f'OnCalendar=daily\nPersistent=true\nRandomizedDelaySec=300\nUnit={name}.service\n'
             '[Install]\nWantedBy=timers.target\n')
    definitions = {folder / (name + '.service'): service, folder / (name + '.timer'): timer}
    for path, value in definitions.items():
        if path.is_symlink() or path.exists() and path.read_text() != value:
            raise ValueError('기존 갱신 unit이 달라 덮어쓰지 않았습니다')
    for path, value in definitions.items():
        if not path.exists():
            with path.open('x') as output:
                output.write(value)
            path.chmod(0o644)
    for command in (['systemctl', 'daemon-reload'], ['systemctl', 'enable', '--now', name + '.timer']):
        result = subprocess.run(command, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('CRL 갱신 타이머 등록 실패. 인증서와 기존 서비스는 보존됐습니다')
    return name + '.timer'
