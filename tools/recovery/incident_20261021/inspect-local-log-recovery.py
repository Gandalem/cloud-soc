"""Count retained local records without exporting messages, users or addresses."""
import bz2
from collections import Counter
from datetime import datetime, timezone
import glob
import gzip
import json
import lzma
import os
from pathlib import Path
import pwd
import re
import subprocess
import tempfile
from zoneinfo import ZoneInfo

START = datetime(2026, 10, 20, 15, tzinfo=timezone.utc)
END = datetime(2026, 10, 21, 8, 20, tzinfo=timezone.utc)
BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')


def aggregate():
    return {'count': 0, 'first_utc': None, 'last_utc': None, 'hourly_utc': Counter(),
            'ssh_failed_password': 0, 'ssh_invalid_user': 0, 'ssh_accepted': 0}


def add(out, stamp, message):
    if not START <= stamp < END:
        return
    text = stamp.isoformat()
    out['count'] += 1
    out['first_utc'] = min(out['first_utc'] or text, text)
    out['last_utc'] = max(out['last_utc'] or text, text)
    out['hourly_utc'][stamp.strftime('%Y-%m-%dT%H:00Z')] += 1
    if 'Failed password for ' in message:
        out['ssh_failed_password'] += 1
    if re.search(r'\bInvalid user ', message):
        out['ssh_invalid_user'] += 1
    if re.search(r'\bAccepted (?:password|publickey) for ', message):
        out['ssh_accepted'] += 1


def timestamp(line, local):
    match = re.match(r'^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d))', line)
    if match:
        return datetime.fromisoformat(match[1].replace('Z', '+00:00')).astimezone(timezone.utc), 'explicit_offset'
    match = re.match(r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d:\d\d:\d\d)', line)
    if match:
        month = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'].index(match[1]) + 1
        h, m, s = map(int, match[3].split(':'))
        return datetime(2026, month, int(match[2]), h, m, s, tzinfo=local).astimezone(timezone.utc), 'year_inferred_2026_host_timezone'
    match = re.search(r'\bmsg=audit\((\d{10}(?:\.\d+)?):', line)
    if match:
        return datetime.fromtimestamp(float(match[1]), timezone.utc), 'audit_epoch'
    if line.startswith('{'):
        data = json.loads(line)
        for key in ('@timestamp', 'timestamp', 'time', 'ts'):
            value = data.get(key)
            if isinstance(value, str):
                try:
                    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    if parsed.tzinfo is not None:
                        return parsed.astimezone(timezone.utc), 'json_explicit_offset'
                except ValueError:
                    pass
    return None, 'unparsed'


def main():
    if os.geteuid() != 0:
        raise ValueError('Root required')
    os.umask(0o077)
    zone = subprocess.run(['timedatectl', 'show', '-p', 'Timezone', '--value'],
                          capture_output=True, text=True, timeout=5).stdout.strip()
    local = ZoneInfo(zone)
    report = {'window_start_utc': START.isoformat(), 'window_end_utc': END.isoformat(),
              'host_timezone': zone, 'journal': aggregate(), 'files': []}
    err = tempfile.TemporaryFile()
    command = ['timeout', '180s', 'journalctl', '--utc', '--no-pager', '--all', '-o', 'json',
               '--since', START.strftime('%Y-%m-%d %H:%M:%S UTC'),
               '--until', END.strftime('%Y-%m-%d %H:%M:%S UTC')]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=err, text=True, errors='replace')
    malformed = 0
    for line in process.stdout:
        try:
            data = json.loads(line)
            stamp = datetime.fromtimestamp(int(data['__REALTIME_TIMESTAMP']) / 1_000_000, timezone.utc)
            message = data.get('MESSAGE', '')
            add(report['journal'], stamp, message if isinstance(message, str) else '')
        except (ValueError, KeyError, TypeError, OverflowError):
            malformed += 1
    report['journal'].update(command_exit=process.wait(), malformed_records=malformed)
    err.close()
    candidates = set()
    patterns = ['/var/log/auth.log*', '/var/log/secure*', '/var/log/syslog*',
                '/var/log/kern.log*', '/var/log/ufw.log*', '/var/log/fail2ban.log*',
                '/var/log/audit/audit.log*', '/home/lyn/security-mall/audit/security-audit.jsonl*']
    for config in Path('/opt/cloud-soc-agent/inputs').glob('*'):
        if config.is_file() and config.stat().st_size < 2 * 1024 * 1024:
            try:
                inputs = json.loads(config.read_text())
                if isinstance(inputs, list):
                    for entry in inputs:
                        for pattern in entry.get('paths', []):
                            if isinstance(pattern, str) and pattern.startswith('/var/log/'):
                                patterns.append(pattern)
            except (ValueError, OSError, AttributeError):
                pass
    for pattern in patterns:
        candidates.update(Path(p) for p in glob.glob(pattern))
    for path in sorted(candidates):
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix in ('.journal', '.journal~', '.db', '.sqlite'):
            continue
        record = {'path': str(path), 'file_bytes': path.stat().st_size, 'events': aggregate(),
                  'time_basis_counts': Counter(), 'lines_unparsed': 0, 'scan_complete': True}
        opener = gzip.open if path.suffix == '.gz' else lzma.open if path.suffix == '.xz' else bz2.open if path.suffix == '.bz2' else open
        scanned = 0
        try:
            with opener(path, 'rt', encoding='utf-8', errors='replace') as stream:
                while True:
                    line = stream.readline(1024 * 1024)
                    if not line:
                        break
                    scanned += len(line)
                    if scanned > 256 * 1024 * 1024 or len(line) >= 1024 * 1024:
                        record['scan_complete'] = False
                        break
                    try:
                        stamp, basis = timestamp(line, local)
                        record['time_basis_counts'][basis] += 1
                        if stamp is not None:
                            add(record['events'], stamp, line)
                        else:
                            record['lines_unparsed'] += 1
                    except (ValueError, TypeError, OverflowError):
                        record['lines_unparsed'] += 1
        except (OSError, EOFError, lzma.LZMAError) as error:
            record.update(scan_complete=False, read_error=type(error).__name__)
        report['files'].append(record)
    boots = subprocess.run(['journalctl', '--list-boots', '--no-pager'], capture_output=True, text=True, timeout=10)
    report['journal_boots'] = boots.stdout
    fd, name = tempfile.mkstemp(prefix='local-log-recovery-', suffix='.json', dir=BASE / 'work')
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    owner = pwd.getpwnam('lyn')
    os.chown(name, owner.pw_uid, owner.pw_gid)
    print(json.dumps({'window_start_utc': report['window_start_utc'], 'window_end_utc': report['window_end_utc'],
                      'host_timezone': zone, 'journal': report['journal']}, ensure_ascii=False))
    for record in report['files']:
        print(json.dumps({k: v for k, v in record.items() if k != 'time_basis_counts'}, ensure_ascii=False))
    print(json.dumps({'private_report': name, 'raw_messages_exported': False,
                      'missing_document_identity_match': 'not_yet_possible', 'live_state_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'local_log_diagnosis_stopped': type(error).__name__}))
        raise SystemExit(1)
