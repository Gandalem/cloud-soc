"""Private configuration/status for the isolated mall service adapters only."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
import time


class CredentialExpired(RuntimeError):
    pass


def stamp():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def private_json(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > 65536 or
                (os.name == 'posix' and (info.st_uid != os.getuid() or info.st_mode & 0o077))):
            raise ValueError('private_configuration_required')
        with os.fdopen(fd, 'r', encoding='utf-8') as source:
            fd = None
            return json.load(source)
    finally:
        if fd is not None:
            os.close(fd)


def status(path, value):
    """Only caller-selected metadata, never exceptions or raw input."""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.status-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(value, output, separators=(',', ':'))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def config(path):
    c = private_json(path)
    root = Path(c['root'])
    if c['schema_version'] != 1 or not root.is_absolute() or root.is_symlink():
        raise ValueError('collection_configuration_invalid')
    if os.name == 'posix' and (root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077):
        raise ValueError('collection_directory_private_required')
    if c['es_url'] != 'https://127.0.0.1:19200':
        raise ValueError('isolated_tls_endpoint_required')
    for name in ('organization_id', 'host_id'):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', c[name]):
            raise ValueError('scope_invalid')
    prefixes = {'app_index': 'soc-host-raw-mall-isolated-continuous-',
                'edge_index': 'soc-host-raw-mall-edge-isolated-continuous-',
                'normalized_index': 'soc-normalized-mall-continuous-',
                'records_index': 'soc-processing-mall-continuous-',
                'status_index': 'soc-pipeline-status-mall-continuous-'}
    for name, prefix in prefixes.items():
        if not isinstance(c[name], str) or not c[name].startswith(prefix) or not re.fullmatch(r'[a-z0-9-]{1,200}', c[name]):
            raise ValueError('exact_isolated_index_required')
    if not 1 <= c['poll_seconds'] <= 60 or not 1 <= c['normalizer_interval_seconds'] <= 60:
        raise ValueError('poll_interval_invalid')
    if not 10 <= c['max_spool_files'] <= 100000 or not 1048576 <= c['max_spool_bytes'] <= 1073741824:
        raise ValueError('spool_limit_invalid')
    for name in ('state', 'spool', 'logs'):
        p = root / name
        if not p.is_dir() or p.is_symlink() or (os.name == 'posix' and p.stat().st_mode & 0o077):
            raise ValueError('private_service_directory_required')
    return c


def disk(root):
    info = shutil.disk_usage(root)
    return {'free_bytes': info.free, 'used_bytes': info.used, 'total_bytes': info.total}


def error_code(error):
    # Exception messages may include credentials or input: never stringify them.
    if isinstance(error, CredentialExpired):
        return 'credential_expired'
    code = getattr(getattr(error, 'meta', None), 'status', None)
    if code == 401:
        return 'authentication_failed_or_key_expired'
    if code == 403:
        return 'authorization_denied'
    return 'collection_processing_failed'


def credential(path):
    value = private_json(path)
    if type(value.get('expires_at')) is not int or value['expires_at'] <= int(time.time()*1000):
        raise CredentialExpired()
    if not isinstance(value.get('encoded'), str) or not value['encoded']:
        raise ValueError('credential_invalid')
    return value
