"""Inventory only operational SQLite, with explicit bounded and verifiable snapshots."""
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3

from cloud_soc.deployment.migrations import atomic_json


def regular(path, state):
    path, state = Path(path), Path(state).resolve()
    if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(state):
        raise ValueError('Unsafe operational database path')
    for parent in path.parents:
        if parent == state:
            break
        if parent.is_symlink():
            raise ValueError('Symlinked operational database parent')
    return path


def inventory(state, contract, adoption):
    """Inactive historical copies are preserved in place, not recursively re-backed up."""
    state = Path(state);paths = set();worker_files = {}
    for name, row in contract['workers'].items():
        path = Path(adoption.get(name, {}).get('state_source', state / 'runtime/state' / name / row['state_file']))
        if not path.exists():
            continue
        path = regular(path, state);key = (path.stat().st_dev, path.stat().st_ino)
        if key in worker_files:
            raise ValueError('Independent workers share the same database inode')
        worker_files[key] = name;paths.add(path)
        early = Path(str(path) + '.early.sqlite')
        if row['options'].get('--early-auth') and early.exists():
            paths.add(regular(early, state))
    for name in ('portal', 'notifications'):
        for path in (state / name).glob('*'):
            if path.suffix in ('.sqlite', '.sqlite3'):
                paths.add(regular(path, state))
    result = []
    for path in sorted(paths):
        wal = Path(str(path) + '-wal')
        if wal.exists():
            regular(wal, state)
        info = path.stat();wal_bytes = wal.stat().st_size if wal.exists() else 0
        result.append({'path': str(path), 'relative': path.relative_to(state).as_posix(),
                       'database_bytes': info.st_size, 'wal_bytes': wal_bytes,
                       'copy_upper_bound_bytes': info.st_size + wal_bytes,
                       'device': str(info.st_dev), 'uid': getattr(info, 'st_uid', None),
                       'gid': getattr(info, 'st_gid', None), 'mode': oct(info.st_mode & 0o777)})
    return result


def sha256(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def allocated_bytes(root):
    """Allocated blocks, once per inode; do not traverse links or other devices."""
    root = Path(root)
    if not root.exists():
        return 0
    device = root.stat().st_dev;seen = set();total = 0
    for directory, folders, files in os.walk(root, followlinks=False):
        folders[:] = [name for name in folders if not (Path(directory)/name).is_symlink()
                      and (Path(directory)/name).stat().st_dev == device]
        for name in files:
            path = Path(directory)/name
            if path.is_symlink():
                continue
            info = path.stat();identity = (info.st_dev, info.st_ino)
            if identity not in seen and info.st_dev == device:
                total += getattr(info, 'st_blocks', (info.st_size + 511)//512) * 512
                seen.add(identity)
    return total


def fsync_directory(path):
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def snapshot_set(rows, directory, backup_database, *, previous=None):
    """Each durable entry is a verified standalone copy; unchanged phases may share a blob.

    A hard-linked stopped/online entry is explicitly one physical recovery object,
    never advertised as two independent backups. No previous upgrade is deleted.
    """
    directory = Path(directory)
    if directory.is_symlink() or directory.exists():
        raise ValueError('Backup set already exists or is unsafe')
    directory.mkdir(mode=0o700, parents=True)
    fsync_directory(directory.parent)
    index = {'complete': False, 'entries': [], 'physical_bytes': 0}
    atomic_json(directory / 'manifest.json', index)
    earlier = {row['relative']: row for row in previous.get('entries', [])} if previous else {}
    for row in rows:
        relative = Path(row['relative'])
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Backup path escapes its set')
        target = directory / relative;target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = target.with_name(target.name + '.partial')
        backup_database(Path(row['path']), temporary)
        fingerprint = sha256(temporary)
        # Verify restoration explicitly; never depend on a source WAL after publication.
        with closing(sqlite3.connect(temporary.as_uri() + '?mode=ro', uri=True)) as copy, closing(sqlite3.connect(':memory:')) as restored:
            if copy.execute('pragma integrity_check').fetchall() != [('ok',)]:
                raise ValueError('Backup integrity failed')
            copy.backup(restored)
            if restored.execute('pragma integrity_check').fetchall() != [('ok',)]:
                raise ValueError('Backup restore verification failed')
        old = earlier.get(row['relative']);shared = False
        if old and old.get('sha256') == fingerprint:
            original = Path(old['path'])
            if (original.is_symlink() or sha256(original) != fingerprint
                    or original.stat().st_dev != temporary.stat().st_dev):
                raise ValueError('Prior verified backup changed or moved')
            os.link(original, target);temporary.unlink();shared = True
        else:
            os.replace(temporary, target)
        fsync_directory(target.parent)
        size = target.stat().st_size
        index['entries'].append({'source': row['path'], 'relative': row['relative'], 'path': str(target),
            'sha256': fingerprint, 'bytes': size, 'integrity': 'ok', 'restore': 'ok',
            'shared_with_online': old['path'] if shared else None})
        if not shared:
            index['physical_bytes'] += size
        atomic_json(directory / 'manifest.json', index)
    index['complete'] = True;atomic_json(directory / 'manifest.json', index)
    return index
