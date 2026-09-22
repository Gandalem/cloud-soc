"""Local, explicit collection-policy updates. No network, commands or binary updates."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import tempfile


def checked_path(path):
    path = Path(path).absolute()
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink() or (ancestor.exists() and getattr(ancestor.lstat(), 'st_file_attributes', 0) & 0x400):
            raise ValueError('Symlink/reparse-point paths are forbidden')
    return path


def validate(policy, platform):
    if not isinstance(policy, dict) or set(policy) != {'roots', 'exclusions'}:
        raise ValueError('Policy only accepts roots and exclusions')
    path_type = PureWindowsPath if platform == 'windows' else PurePosixPath
    normalized = {}
    for key in ('roots', 'exclusions'):
        values = policy[key]
        if not isinstance(values, list) or len(values) > 100 or (key == 'roots' and not values):
            raise ValueError('Use 1-100 roots and at most 100 exclusions')
        result = []
        for value in values:
            if (not isinstance(value, str) or len(value) > 500 or not value
                    or re.search(r'[\x00-\x1f\x7f$*?\[\]{}]', value)
                    or value != value.strip() or '..' in path_type(value).parts):
                raise ValueError('Unsafe policy path')
            path = path_type(value)
            if not path.is_absolute() or (platform == 'windows' and not re.match(r'^[A-Za-z]:[\\/]', value)):
                raise ValueError('Only absolute local paths are allowed')
            if platform == 'linux' and not re.fullmatch(r'/[-a-zA-Z0-9_./]+', value):
                raise ValueError('Unsupported Linux path characters')
            canonical = str(path)
            if platform == 'windows':
                lower = canonical.lower()
                suffix = '\\'.join(path.parts[1:]).lower()
                forbidden = ('users', 'windows\\system32\\config', 'program files\\cloud-soc-agent', 'program files\\cloud-soc-network')
                if len(path.parts) < 3 or suffix == 'windows\\system32' or any(suffix == p or suffix.startswith(p + '\\') for p in forbidden):
                    raise ValueError('Broad, personal or collector roots are forbidden')
            else:
                if len(path.parts) < 3 or any(canonical == p or canonical.startswith(p + '/') for p in (
                    '/etc', '/proc', '/sys', '/dev', '/run', '/home', '/root', '/opt/cloud-soc-agent', '/opt/cloud-soc-network')):
                    raise ValueError('Broad, personal or collector roots are forbidden')
            if canonical in result:
                raise ValueError('Repeated path')
            result.append(canonical)
        normalized[key] = result
    for excluded in normalized['exclusions']:
        if not any(path_type(excluded).is_relative_to(path_type(root)) for root in normalized['roots']):
            raise ValueError('Exclusions must be within approved roots')
    return normalized


def encode(policy, version):
    return ('version=' + str(version) + '\n' + ''.join('root=' + p + '\n' for p in policy['roots'])
            + ''.join('exclude=' + p + '\n' for p in policy['exclusions'])).encode('utf-8')


def decode(data, platform):
    lines = data.decode('utf-8').splitlines()
    if not lines or not re.fullmatch(r'version=[0-9]{1,9}', lines[0]):
        raise ValueError('Invalid policy version')
    result = {'roots': [], 'exclusions': []}
    for line in lines[1:]:
        key, separator, value = line.partition('=')
        if not separator or key not in ('root', 'exclude'):
            raise ValueError('Invalid policy record')
        result['roots' if key == 'root' else 'exclusions'].append(value)
    return validate(result, platform), int(lines[0][8:])


@contextmanager
def locked(root):
    path = checked_path(root / 'discovery.lock')
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(path), 0x40000000, 0, None, 4, 0x80, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ValueError('Discovery/policy update is busy or inaccessible; retry later')
        try:
            yield
        finally:
            kernel.CloseHandle(handle)
    else:
        import fcntl
        with path.open('a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield


def current(root, platform):
    path = checked_path(root / 'collection-policy.txt')
    if path.exists():
        if path.stat().st_size > 131072:
            raise ValueError('Policy too large')
        return decode(path.read_bytes(), platform)
    if platform == 'windows':
        settings = json.loads(checked_path(root / 'discovery-settings.json').read_text(encoding='utf-8-sig'))
        roots = settings['log_roots']
    else:
        roots = checked_path(root / 'discovery-roots.txt').read_text().splitlines()
    return validate({'roots': roots, 'exclusions': []}, platform), 0


def update(root, platform, policy=None, *, expected=None, apply=False, rollback=None):
    root = checked_path(root)
    if not root.is_dir() or not (root / 'inputs').is_dir():
        raise ValueError('Existing protected installation required')
    discovery = checked_path(root / ('discover-windows.ps1' if platform == 'windows' else 'discover-linux.sh'))
    if '# cloud-soc-policy-format: 1' not in discovery.read_text(encoding='utf-8-sig'):
        raise ValueError('Installed discovery script does not support policy v1; no changes made')
    with locked(root):
        previous, version = current(root, platform)
        if apply and (type(expected) is not int or expected != version):
            raise ValueError('Policy version changed; review and retry')
        history = checked_path(root / 'policy-history')
        if rollback is not None:
            if type(rollback) is not int or not 0 <= rollback < version:
                raise ValueError('Choose an earlier recorded version')
            saved = checked_path(history / f'{rollback:09d}.policy')
            policy, _ = decode(saved.read_bytes(), platform)
        policy = validate(policy, platform)
        # Host validation is separate from lexical validation, useful for isolated tests.
        for value in policy['roots']:
            if not checked_path(value).is_dir():
                raise ValueError('Approved roots must exist and must not be links')
        for value in policy['exclusions']:
            checked_path(value)
        if version >= 999999999:
            raise ValueError('Policy version exhausted')
        data = encode(policy, version + 1)
        result = {'previous_version': version, 'version': version + 1, 'applied': False,
                  'sha256': hashlib.sha256(data).hexdigest(), 'roots': len(policy['roots']),
                  'exclusions': len(policy['exclusions']), 'binary_update': False}
        if not apply:
            return result
        history.mkdir(mode=0o700, exist_ok=True)
        archive = checked_path(history / f'{version:09d}.policy')
        old = encode(previous, version)
        if archive.exists():
            if archive.read_bytes() != old:
                raise ValueError('Policy history conflict; manual review required')
        else:
            with archive.open('xb') as stream:
                stream.write(old)
            archive.chmod(0o600)
        # One atomic pointer file is authoritative; queues, inputs and keys are untouched.
        fd, candidate = tempfile.mkstemp(prefix='.policy-', dir=root)
        candidate = Path(candidate)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            record = {**result, 'at': datetime.now(timezone.utc).isoformat(), 'rollback_of': rollback, 'state': 'prepared'}
            audit = checked_path(history / f'{version + 1:09d}-{result["sha256"]}.json')
            # Prepared audit + matching current digest proves publication; old digest means not applied.
            if not audit.exists():
                with audit.open('x', encoding='utf-8') as stream:
                    json.dump(record, stream)
                audit.chmod(0o600)
            os.replace(candidate, checked_path(root / 'collection-policy.txt'))
        finally:
            if candidate.exists():
                candidate.unlink()
        return {**result, 'applied': True}


def main():
    parser = argparse.ArgumentParser(description='Local policy only; dry-run unless --apply. Requires Python 3.10+.')
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--policy', type=Path)
    choice.add_argument('--rollback-version', type=int)
    parser.add_argument('--expected-version', type=int)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    platform = 'windows' if os.name == 'nt' else 'linux'
    root = Path(os.environ.get('ProgramFiles', 'C:\\Program Files')) / 'Cloud-SOC-Agent' if os.name == 'nt' else Path('/opt/cloud-soc-agent')
    policy = None
    if args.policy:
        if args.policy.stat().st_size > 131072:
            raise ValueError('Policy too large')
        policy = json.loads(args.policy.read_text(encoding='utf-8-sig'))
    print(json.dumps(update(root, platform, policy, expected=args.expected_version, apply=args.apply, rollback=args.rollback_version)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Do not expose source paths, arbitrary file contents or upstream exceptions.
        raise SystemExit('Policy update failed; validate paths, version, privileges and discovery lock. Existing state retained.') from None
