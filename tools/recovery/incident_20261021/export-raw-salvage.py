"""Private offline export and sequence reconciliation; never write to Elasticsearch."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import sqlite3
import subprocess
import tempfile

BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')
ARCHIVE = Path('/var/tmp/cloud-soc-raw21-check-2tq8dgn7')


def main():
    if os.geteuid() != 0:
        raise ValueError('Root required')
    os.umask(0o077)
    shard = ARCHIVE / 'archive-shard'
    manifest = json.loads((ARCHIVE / 'manifest.json').read_text())
    if not all(hashlib.sha256((shard / name).read_bytes()).hexdigest() == digest for name, digest in manifest.items()):
        raise ValueError('Archived hash mismatch')
    if shutil.disk_usage('/var/tmp').free < 2 * 1024**3:
        raise ValueError('Insufficient disk space')
    root = Path(tempfile.mkdtemp(prefix='cloud-soc-raw-salvage-', dir='/var/tmp'))
    shutil.copy2(BASE / 'outputs/RawSalvage.java', root / 'RawSalvage.java')
    image = subprocess.run(['docker', 'inspect', '--format', '{{.Image}}', 'cloud-soc-central-elasticsearch-1'],
        capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('Unexpected image')
    common = ['docker', 'run', '--rm', '--pull=never', '--network', 'none', '--read-only', '--user', '0',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '1g', '--cpus', '2',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m', '--mount', 'type=bind,src=' + str(root) + ',dst=/work',
        '--mount', 'type=bind,src=' + str(shard) + ',dst=/archive,readonly']
    container_name = root.name
    steps = [common + ['--name', container_name, '--entrypoint', '/usr/share/elasticsearch/jdk/bin/javac', image,
        '-cp', '/usr/share/elasticsearch/lib/*', '-d', '/work/classes', '/work/RawSalvage.java'],
        common + ['--name', container_name, '--entrypoint', '/usr/share/elasticsearch/jdk/bin/java', image,
        '-Xmx512m', '-cp', '/work/classes:/usr/share/elasticsearch/lib/*',
        'org.elasticsearch.index.translog.RawSalvage', '/archive', '/work']]
    for number, command in enumerate(steps):
        with (root / ('step-' + str(number) + '-private.log')).open('w') as stream:
            try:
                result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
            except subprocess.TimeoutExpired:
                subprocess.run(['docker', 'stop', '--time', '5', container_name], capture_output=True, timeout=15)
                print(json.dumps({'export_directory': str(root), 'step': number, 'timeout': True}))
                return
        if result.returncode:
            # Share compiler/type diagnostics only through a private owner-readable copy.
            diagnostic = (root / ('step-' + str(number) + '-private.log')).read_text(errors='replace')
            save_report({'export_directory': str(root), 'step': number, 'exit_code': result.returncode,
                         'private_diagnostic': diagnostic})
            return
    summary = json.loads((root / 'java-summary.json').read_text())
    database = root / 'recovered.sqlite'
    db = sqlite3.connect(database)
    db.execute('CREATE TABLE documents (id TEXT PRIMARY KEY, seq_no INTEGER, source TEXT, origins INTEGER)')
    db.execute('CREATE TABLE deletions (id TEXT, seq_no INTEGER)')
    source_conflicts = 0
    invalid_sources = 0
    for filename, flag in (('segments.ndjson', 1), ('translog.ndjson', 2)):
        with (root / filename).open() as stream:
            for line in stream:
                row = json.loads(line)
                if 'delete_id_b64' in row:
                    db.execute('INSERT INTO deletions VALUES (?,?)', (base64.b64decode(row['delete_id_b64']).decode(), row['seq_no']))
                    continue
                identity = base64.b64decode(row['id_b64']).decode()
                try:
                    source = json.loads(base64.b64decode(row['source_b64']))
                    if not isinstance(source, dict):
                        raise ValueError()
                except (ValueError, UnicodeDecodeError):
                    invalid_sources += 1
                    continue
                canonical = json.dumps(source, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
                old = db.execute('SELECT seq_no,source,origins FROM documents WHERE id=?', (identity,)).fetchone()
                if old:
                    if old[0] == row['seq_no'] and old[1] != canonical:
                        source_conflicts += 1
                    if old[0] > row['seq_no']:
                        canonical, sequence = old[1], old[0]
                    else:
                        sequence = row['seq_no']
                    db.execute('UPDATE documents SET seq_no=?,source=?,origins=? WHERE id=?',
                               (sequence, canonical, old[2] | flag, identity))
                else:
                    db.execute('INSERT INTO documents VALUES (?,?,?,?)', (identity, row['seq_no'], canonical, flag))
    db.commit()
    sequences = {row[0] for row in db.execute('SELECT seq_no FROM documents WHERE seq_no BETWEEN 0 AND 235196')}
    missing = sorted(set(range(235197)) - sequences)
    spans = []
    for n in missing:
        if spans and n == spans[-1][1] + 1:
            spans[-1][1] = n
        else:
            spans.append([n, n])
    summary.update(export_directory=str(root), invalid_sources=invalid_sources, same_sequence_source_conflicts=source_conflicts,
        recovered_unique_ids=db.execute('SELECT COUNT(*) FROM documents').fetchone()[0],
        translog_only_ids=db.execute('SELECT COUNT(*) FROM documents WHERE origins=2').fetchone()[0],
        known_contiguous_checkpoint=235196, missing_sequence_count=len(missing),
        missing_sequence_ranges=spans, sequence_coverage_proves_document_identity=False,
        local_source_comparison_complete=False, operating_indices_changed=False)
    db.close()
    save_report(summary)


def save_report(report):
    fd, name = tempfile.mkstemp(prefix='raw-salvage-result-', suffix='.json', dir=BASE / 'work')
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    owner = pwd.getpwnam('lyn')
    os.chown(name, owner.pw_uid, owner.pw_gid)
    print(json.dumps({k: v for k, v in report.items() if k not in ('private_diagnostic', 'missing_sequence_ranges')}, ensure_ascii=False))
    print(json.dumps({'private_report': name}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'export_stopped': type(error).__name__}))
        raise SystemExit(1)
