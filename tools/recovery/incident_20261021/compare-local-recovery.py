"""Compare retained local records to exported documents; never ingest or replace."""
import bz2
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import json
import lzma
import os
from pathlib import Path
import pwd
import runpy
import sqlite3
import subprocess
import tempfile
from zoneinfo import ZoneInfo

BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')
EXPORT = Path('/var/tmp/cloud-soc-raw-salvage-cy2b5yem')


def field(source, dotted):
    if dotted in source:
        return source[dotted]
    for key in dotted.split('.'):
        if not isinstance(source, dict):
            return None
        source = source.get(key)
    return source


def digest(message):
    return hashlib.sha256(message.encode()).digest()


def main():
    os.umask(0o077)
    helpers = runpy.run_path(str(BASE / 'outputs/inspect-local-log-recovery.py'))
    start, end = helpers['START'], helpers['END']
    local_report = json.loads((BASE / 'work/local-log-recovery-d4ri7dl5.json').read_text())
    zone = ZoneInfo(local_report['host_timezone'])
    original = sqlite3.connect((EXPORT / 'recovered.sqlite').as_uri() + '?mode=ro', uri=True)
    fd, private_db = tempfile.mkstemp(prefix='local-recovery-comparison-', suffix='.sqlite', dir='/var/tmp')
    os.close(fd)
    comparison = sqlite3.connect(private_db)
    comparison.execute('CREATE TABLE signatures (message BLOB, path TEXT, offset TEXT, cursor TEXT)')
    metadata = Counter()
    boundary = {}
    time_range = {}
    for seq, text, origins in original.execute('SELECT seq_no,source,origins FROM documents ORDER BY seq_no'):
        source = json.loads(text)
        message = source.get('message')
        if not isinstance(message, str) or message == '[REDACTED]':
            metadata['no_comparable_message'] += 1
            continue
        path = field(source, 'log.file.path')
        offset = field(source, 'log.offset')
        cursor = field(source, 'journald.cursor')
        if cursor is None and isinstance(offset, str) and offset.startswith('s='):
            cursor = offset
        metadata[str(field(source, 'labels.log_source') or 'unknown')] += 1
        if cursor:
            metadata['with_journal_cursor'] += 1
        if path is not None and offset is not None:
            metadata['with_file_offset'] += 1
        comparison.execute('INSERT INTO signatures VALUES (?,?,?,?)',
            (digest(message), path if isinstance(path, str) else None,
             str(offset) if offset is not None else None, cursor if isinstance(cursor, str) else None))
        if seq in (210452, 230086, 235196):
            boundary[str(seq)] = {'event_time': source.get('@timestamp'),
                'receipt_time': field(source, 'event.ingested'),
                'log_source': field(source, 'labels.log_source'), 'file_path': path}
        for key in ('@timestamp', 'event.ingested'):
            value = field(source, key)
            if isinstance(value, str):
                try:
                    stamp = datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc).isoformat()
                    bounds = time_range.setdefault(key, [stamp, stamp])
                    bounds[0], bounds[1] = min(bounds[0], stamp), max(bounds[1], stamp)
                except ValueError:
                    pass
    original.close()
    for name, columns in [('message', 'message'), ('file', 'path,offset,message'), ('cursor', 'cursor')]:
        comparison.execute('CREATE INDEX idx_' + name + ' ON signatures (' + columns + ')')
    comparison.commit()
    counts = {'journal': Counter(), 'files': []}
    process = subprocess.Popen(['timeout', '180s', 'journalctl', '--utc', '--no-pager', '--all', '-o', 'json',
        '--since', start.strftime('%Y-%m-%d %H:%M:%S UTC'), '--until', end.strftime('%Y-%m-%d %H:%M:%S UTC')],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='replace')
    for line in process.stdout:
        try:
            row = json.loads(line)
            stamp = datetime.fromtimestamp(int(row['__REALTIME_TIMESTAMP']) / 1_000_000, timezone.utc)
            if not start <= stamp < end:
                continue
            counts['journal']['records'] += 1
            message = row.get('MESSAGE')
            if not isinstance(message, str):
                counts['journal']['uncomparable'] += 1
                continue
            cursor = row.get('__CURSOR')
            if cursor and comparison.execute('SELECT 1 FROM signatures WHERE cursor=? AND message=? LIMIT 1',
                                              (cursor, digest(message))).fetchone():
                counts['journal']['cursor_and_message_matched'] += 1
            elif comparison.execute('SELECT 1 FROM signatures WHERE message=? LIMIT 1', (digest(message),)).fetchone():
                counts['journal']['message_only_matched'] += 1
            else:
                counts['journal']['not_found_in_export'] += 1
        except (ValueError, KeyError, TypeError, OverflowError):
            counts['journal']['parse_errors'] += 1
    counts['journal']['command_exit'] = process.wait()
    for record in local_report['files']:
        if not record.get('events', {}).get('count'):
            continue
        path = Path(record['path'])
        out = Counter()
        opener = gzip.open if path.suffix == '.gz' else lzma.open if path.suffix == '.xz' else bz2.open if path.suffix == '.bz2' else open
        offset = 0
        try:
            with opener(path, 'rb') as stream:
                while True:
                    raw = stream.readline(1024 * 1024)
                    if not raw:
                        break
                    current, offset = offset, offset + len(raw)
                    if offset > 256 * 1024 * 1024 or len(raw) >= 1024 * 1024:
                        out['scan_limited'] += 1
                        break
                    line = raw.rstrip(b'\r\n').decode(errors='replace')
                    try:
                        stamp, _ = helpers['timestamp'](line, zone)
                    except (ValueError, TypeError, OverflowError):
                        continue
                    if stamp is None or not start <= stamp < end:
                        continue
                    out['records'] += 1
                    signature = digest(line)
                    if comparison.execute('SELECT 1 FROM signatures WHERE path=? AND offset=? AND message=? LIMIT 1',
                                          (str(path), str(current), signature)).fetchone():
                        out['path_offset_message_matched'] += 1
                    elif comparison.execute('SELECT 1 FROM signatures WHERE message=? LIMIT 1', (signature,)).fetchone():
                        out['message_only_matched'] += 1
                    else:
                        out['not_found_in_export'] += 1
        except (OSError, EOFError, lzma.LZMAError):
            out['read_errors'] += 1
        counts['files'].append({'path': str(path), 'comparison': dict(out)})
    comparison.close()
    report = {'export_directory': str(EXPORT), 'comparison_database': private_db,
        'export_metadata': dict(metadata), 'export_time_ranges': time_range,
        'missing_sequence_range': [210453, 230085], 'neighbor_records': boundary,
        'local_comparison': counts, 'all_19633_documents_verified': False,
        'reason': 'Lost segment document identities are unavailable; local unmatched records are candidates, not proof.',
        'operating_indices_changed': False}
    fd, name = tempfile.mkstemp(prefix='local-vs-export-result-', suffix='.json', dir=BASE / 'work')
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    owner = pwd.getpwnam('lyn')
    os.chown(name, owner.pw_uid, owner.pw_gid)
    print(json.dumps({k: v for k, v in report.items() if k != 'comparison_database'}, ensure_ascii=False))
    print(json.dumps({'private_report': name}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'comparison_stopped': type(error).__name__}))
        raise SystemExit(1)
