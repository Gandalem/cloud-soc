"""Serve an administrator-pinned, prebuilt native release; never compile on request."""
import hashlib
import json
import os
from pathlib import Path
import stat

from cloud_soc.portal.enrollment import EnrollmentError


INPUTS = ('native/Contracts.cs', 'native/Safe.cs', 'native/Platform.cs', 'native/Installer.cs',
          'native/Program.cs', 'native/TlsChain.cs', 'native/app.manifest', 'enrollment-http.cs', 'tls-probe.cs',
          'discovery-native.cs', 'privacy.js', 'site-privacy.js', 'security-catalog.json')


def source_hash(source):
    digest = hashlib.sha256()
    for name in INPUTS:
        # Git's Windows CRLF conversion must not invalidate a reviewed Linux release mount.
        contents = (Path(source) / name).read_bytes().replace(b'\r\n', b'\n')
        digest.update(name.encode() + b'\0' + hashlib.sha256(contents).digest())
    return digest.hexdigest()


def release(store):
    """Pin is supplied separately from artifact metadata, through server configuration."""
    try:
        root = Path(store.windows_installer_dir).resolve(strict=True)
        pin = store.windows_installer_sha256
        if not isinstance(pin, str) or len(pin) != 64 or any(c not in '0123456789abcdef' for c in pin):
            raise ValueError('pin')
        contents = {}
        for name, limit in (('release.json', 8192), ('cloud-soc-agent-setup.exe', 8388608)):
            path = root / name
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1
                    or not 0 < info.st_size <= limit or os.name != 'nt' and info.st_mode & stat.S_IWOTH):
                raise ValueError('file')
            contents[name] = path.read_bytes()
        metadata = json.loads(contents['release.json'])
        binary = contents['cloud-soc-agent-setup.exe']
        if (metadata.get('schema') != 1 or metadata.get('target') != 'windows-x64-net48'
                or metadata.get('source_sha256') != source_hash(store.source)
                or metadata.get('sha256') != pin or hashlib.sha256(binary).hexdigest() != pin
                or not binary.startswith(b'MZ')
                or metadata.get('mode') not in ('production', 'lab')
                or metadata['mode'] == 'production' and metadata.get('signed') is not True
                or metadata['mode'] == 'lab' and store.windows_installer_allow_lab is not True):
            raise ValueError('release')
        return binary, metadata['mode']
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        raise EnrollmentError('windows_installer_unavailable', 503,
                              'Windows 설치 파일이 준비되지 않았습니다. 관리자가 네이티브 EXE 릴리스와 SHA-256 설정을 확인하세요.') from None


def require_scope(package):
    if package['os'] == 'windows' and package['network']:
        raise EnrollmentError('windows_native_scope', 400,
                              'Windows 네이티브 설치는 시스템·웹 로그를 지원합니다. 네트워크 패킷 수집을 선택 해제하거나 기존 고급 패키지를 사용하세요.')
