"""Bounded, read-only Beats interval statistics. No credentials leave the host."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

FIELDS = {
    'queue_bytes': 'libbeat.pipeline.queue.filled.bytes',
    'queue_events': 'libbeat.pipeline.queue.filled.events',
    'queue_pct': 'libbeat.pipeline.queue.filled.pct',
    'queue_max_bytes': 'libbeat.pipeline.queue.max_bytes',
    'pipeline_active': 'libbeat.pipeline.events.active',
    'output_total': 'libbeat.output.events.total',
    'output_acked': 'libbeat.output.events.acked',
    'output_failed': 'libbeat.output.events.failed',
    'output_dropped': 'libbeat.output.events.dropped',
    'output_dead_letter': 'libbeat.output.events.dead_letter',
    'output_failure_store': 'libbeat.output.events.failure_store',
    'read_errors': 'libbeat.output.read.errors',
    'write_errors': 'libbeat.output.write.errors',
}
PROBLEMS = ('output_failed', 'output_dropped', 'output_dead_letter',
            'output_failure_store', 'read_errors', 'write_errors')
MAX_TAIL = 1048576
MAX_LINE = 524288


def stamp(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:?\d{2})', value):
        raise ValueError('timestamp')
    # Ubuntu 22.04's Python 3.10 needs colon offsets and 3/6-digit fractions.
    value = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', value)
    value = re.sub(r'\.(\d{1,9})(?=Z|[+-])', lambda m: '.' + m[1][:6].ljust(6, '0'), value)
    return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)


def at(value, path):
    for key in path.split('.'):
        value = value.get(key) if isinstance(value, dict) else None
    return value


def number(value, fraction=False):
    if type(value) not in (int, float) or not 0 <= value <= (1 if fraction else 9007199254740991):
        return None
    if not math.isfinite(value) or (not fraction and int(value) != value):
        return None
    return value if fraction else int(value)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def parse(line, service):
    if len(line) > MAX_LINE or b'"monitoring"' not in line:
        return None
    try:
        entry = json.loads(line, object_pairs_hook=unique)
        if not isinstance(entry, dict) or entry.get('log.logger') != 'monitoring' or entry.get('service.name') != service:
            return None
        interval = re.fullmatch(r'Non-zero metrics in the last ([1-9][0-9]{0,4})s', entry.get('message', ''))
        metrics = at(entry, 'monitoring.metrics')
        if not interval or int(interval[1]) > 86400 or not isinstance(metrics, dict):
            return None
        sampled = timestamp(entry.get('@timestamp'))
        return {'schema': 1, 'state': 'observed', 'sampled_at': stamp(sampled),
                'interval_seconds': int(interval[1]), 'counter_scope': 'logged_interval_delta',
                **{name: number(at(metrics, path), name == 'queue_pct') for name, path in FIELDS.items()}}
    except (ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        return None


def checked(path, directory=False):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('unsafe_path')
        if os.name == 'posix' and parent != path:
            info = parent.stat()
            # A root-owned sticky temporary directory cannot replace another
            # user's protected child; non-sticky shared writers are unsafe.
            if (info.st_uid not in (0, os.geteuid()) or
                    (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
                raise ValueError('unsafe_path')
    info = path.stat()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('unsafe_path')
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('unsafe_path')
    if os.name == 'posix' and (info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
        raise ValueError('unsafe_path')
    return path, info


def open_checked(path):
    path, before = checked(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not stat.S_ISREG(after.st_mode) or after.st_nlink != 1):
        os.close(fd)
        raise ValueError('unsafe_path')
    return os.fdopen(fd, 'rb')


def bounded(path, maximum=262144):
    with open_checked(path) as stream:
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError('size_limit')
    return value


def missing(reason):
    return {'schema': 1, 'state': 'unavailable', 'reason': reason, 'scan_partial': False,
            'last_problem_at': None}


def read(root, service='filebeat', now=None):
    if service not in ('filebeat', 'packetbeat'):
        raise ValueError('service')
    now = now or datetime.now(timezone.utc)
    result = missing('no_sample')
    partial = False
    latest = problem = None
    try:
        root, _ = checked(root, directory=True)
        logs, _ = checked(root / 'logs', directory=True)
        pattern = re.compile(re.escape(service) + r'-[0-9]{8}(?:-[0-9]+)?\.ndjson')
        candidates = []
        # Stop enumeration as well as limiting bytes; event-data logs never open.
        with os.scandir(logs) as entries:
            for count, entry in enumerate(entries, 1):
                if count > 128:
                    return {**missing('too_many_files'), 'scan_partial': True}
                if pattern.fullmatch(entry.name):
                    try:
                        path, info = checked(Path(entry.path))
                        candidates.append((info.st_mtime_ns, path))
                    except (OSError, ValueError):
                        partial = True
        partial |= len(candidates) > 4
        for _, path in sorted(candidates, reverse=True)[:4]:
            try:
                with open_checked(path) as stream:
                    start = max(0, os.fstat(stream.fileno()).st_size - MAX_TAIL)
                    partial |= start > 0
                    stream.seek(start)
                    lines = stream.read(MAX_TAIL).split(b'\n')
                partial |= bool(lines[-1])
                for line in lines[1 if start else 0:-1]:
                    sample = parse(line, service)
                    if sample is None:
                        partial |= b'"monitoring"' in line or len(line) > MAX_LINE
                        continue
                    sampled = timestamp(sample['sampled_at'])
                    if latest is None or sampled > latest:
                        latest, result = sampled, sample
                    if (now - timedelta(minutes=30) <= sampled <= now + timedelta(seconds=60)
                            and any((sample[name] or 0) > 0 for name in PROBLEMS)
                            and (problem is None or sampled > problem)):
                        problem = sampled
            except (OSError, ValueError):
                partial = True
    except FileNotFoundError:
        result = missing('no_logs')
    except (OSError, ValueError):
        result = missing('read_error')
        partial = True
    result['scan_partial'] = partial
    result['last_problem_at'] = stamp(problem) if problem else None
    return result


def identity(root, service):
    root, _ = checked(root, directory=True)
    config = json.loads(bounded(root / (service + '.yml')), object_pairs_hook=unique)
    if not isinstance(config, dict):
        raise ValueError('identity')
    output = config['output.elasticsearch']
    if not isinstance(output, dict) or not isinstance(config.get('processors'), list):
        raise ValueError('identity')
    hosts = output['hosts']
    if not isinstance(hosts, list) or len(hosts) != 1 or not isinstance(hosts[0], str):
        raise ValueError('identity')
    organization = None
    for processor in config['processors']:
        if not isinstance(processor, dict):
            raise ValueError('identity')
        fields = processor.get('add_fields', {})
        if not isinstance(fields, dict):
            raise ValueError('identity')
        if fields.get('target') == 'organization':
            if organization is not None:
                raise ValueError('identity')
            if not isinstance(fields.get('fields'), dict):
                raise ValueError('identity')
            organization = fields['fields']['id']
    if not isinstance(organization, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', organization):
        raise ValueError('identity')
    if output.get('ssl.verification_mode') != 'full' or output.get('ssl.certificate_authorities') != [str(root / 'ca.crt')]:
        raise ValueError('identity')
    return (hosts[0].rstrip('/'), organization, hashlib.sha256(bounded(root / 'ca.crt')).digest())


def read_network(host_root, network_root, now=None):
    try:
        if identity(host_root, 'filebeat') != identity(network_root, 'packetbeat'):
            return missing('identity_mismatch')
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return missing('identity_unavailable')
    return read(network_root, 'packetbeat', now)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    print(json.dumps({'collector_metrics': read(args.root),
                      'network_collector_metrics': read_network(args.root, '/opt/cloud-soc-network')},
                     allow_nan=False, separators=(',', ':')))


if __name__ == '__main__':
    main()
