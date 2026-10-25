"""Install the common runtime into root-owned storage; consume data-only device settings."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

BASE = Path('/var/lib/cloud-soc-bundles')
DATA = ('package.json', 'ca.crt', 'collection-profile.json', 'SHA256SUMS', 'README.txt', 'registration.json')


def prepare(source):
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('sudo로 실행하세요.')
    spec = json.loads((source / 'package.json').read_text())
    registration = json.loads((source / 'registration.json').read_text())
    device = spec.get('managed_device_id')
    if not isinstance(device, str) or not re.fullmatch(r'[a-f0-9]{32}', device) or registration.get('device_id') != device:
        raise RuntimeError('장치 설정과 등록 정보가 다릅니다.')
    archive = source / 'runtime.zip'
    if archive.stat().st_size > 8 * 1024 * 1024 or hashlib.sha256(archive.read_bytes()).hexdigest() != registration.get('runtime_sha256'):
        raise RuntimeError('설치 프로그램 무결성이 다릅니다.')
    for parent in (BASE, *BASE.parents):
        if parent.exists() and (parent.is_symlink() or parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022):
            raise RuntimeError('설치 저장 위치가 보호되지 않았습니다.')
    BASE.mkdir(mode=0o700, exist_ok=True)
    target = BASE / device
    if target.exists() and (target.is_symlink() or target.stat().st_uid != 0 or target.stat().st_mode & 0o077):
        raise RuntimeError('기존 설치 전달 위치가 보호되지 않았습니다.')
    target.mkdir(mode=0o700, exist_ok=True)
    with zipfile.ZipFile(archive) as stream:
        names = stream.namelist()
        if len(names) != len(set(names)) or len(names) > 100 or sum(i.file_size for i in stream.infolist()) > 16*1024*1024:
            raise RuntimeError('설치 묶음 크기 또는 항목 수가 잘못됐습니다.')
        for info in stream.infolist():
            if (not re.fullmatch(r'[a-zA-Z0-9_.-]+', info.filename) or info.filename in ('.', '..')
                    or info.filename in DATA or info.is_dir()):
                raise RuntimeError('허용되지 않은 설치 파일입니다.')
            path = target / info.filename
            content = stream.read(info)
            if path.is_symlink() or path.exists() and path.read_bytes() != content:
                raise RuntimeError('기존 설치 도구와 버전이 다릅니다. 자동 교체하지 않습니다.')
            if not path.exists():
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(content)
    for name in DATA:
        original = source / name
        if not original.exists():
            if name == 'collection-profile.json':
                continue
            raise RuntimeError('설치 설정이 빠졌습니다.')
        if original.is_symlink() or original.stat().st_size > 256*1024:
            raise RuntimeError('설치 설정 경로 또는 크기가 잘못됐습니다.')
        path = target / name
        if path.is_symlink():
            raise RuntimeError('설치 설정 링크를 허용하지 않습니다.')
        if path.exists() and name != 'registration.json' and path.read_bytes() != original.read_bytes():
            raise RuntimeError('기존 장치 설정과 다릅니다.')
        if name == 'registration.json' or not path.exists():
            temporary = target / ('.' + name + '.new')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as output:
                output.write(original.read_bytes())
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
    return target


def main():
    parser = argparse.ArgumentParser(description='Cloud SOC 장치 설치·상태·삭제 도우미')
    parser.add_argument('action', nargs='?', choices=('install', 'status', 'stop', 'start', 'uninstall', 'help'))
    parser.add_argument('--bundle-directory', type=Path, help='압축을 푼 장치 설정 디렉터리')
    parser.add_argument('--device', help='여러 설치 도구 중 관리할 장치 ID')
    args = parser.parse_args()
    if args.action == 'help':
        parser.print_help()
        return 0
    default = Path(__file__).resolve().parent
    source = args.bundle_directory or (default if (default / 'package.json').is_file() else Path.cwd())
    target = None
    # Status/removal must keep working after the downloaded one-time bundle was deleted.
    if BASE.is_dir() and (args.action != 'install' or not (source / 'package.json').is_file()):
        candidates = [p for p in BASE.iterdir() if re.fullmatch(r'[a-f0-9]{32}', p.name)
                      and (p / 'package.json').is_file() and (p / 'agent-manager.py').is_file()]
        if args.device:
            if not re.fullmatch(r'[a-f0-9]{32}', args.device):
                raise RuntimeError('장치 ID가 올바르지 않습니다.')
            candidates = [p for p in candidates if p.name == args.device]
        if len(candidates) == 1:
            target = candidates[0]
            for path in (target, *target.parents):
                if path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
                    raise RuntimeError('기존 관리 도구 경로가 보호되지 않았습니다.')
        elif candidates:
            raise RuntimeError('--device로 관리할 장치를 선택하세요.')
    if target is None:
        target = prepare(source)
    return subprocess.run([sys.executable, str(target / 'agent-manager.py'), *([args.action] if args.action else [])], check=False).returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit('설치 도구 실행을 완료하지 못했습니다. 장치 설정·권한·등록 만료 상태를 확인하세요. 기존 자료는 초기화하지 않았습니다.')
