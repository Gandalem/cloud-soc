"""Archive the unavailable shard and check a disposable copy; no live shard edits."""
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import ssl
import subprocess
import tempfile
import urllib.request

BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')
STATE = Path('/home/lyn/cloud-soc/state/server')
INDEX = 'soc-host-raw-linux-9.5.2-2026.10.21'


def main():
    if os.geteuid() != 0:
        raise ValueError('Root required')
    os.umask(0o077)
    auth = base64.b64encode(('elastic:' + (STATE / 'secrets/elastic_password').read_text().strip()).encode()).decode()
    context = ssl.create_default_context(cafile=str(STATE / 'tls/ca.crt'))

    def get(path, body=None):
        request = urllib.request.Request('https://192.168.1.156:9200' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'}, method='GET')
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            return json.load(response)

    allocation = get('/_cluster/allocation/explain', {'index': INDEX, 'shard': 0, 'primary': True})
    if allocation.get('current_state') != 'unassigned':
        raise ValueError('Shard is no longer unassigned')
    rows = get('/_cat/indices/' + INDEX + '?format=json&h=index,uuid')
    uuid = next(row['uuid'] for row in rows if row['index'] == INDEX)
    if '/' in uuid or uuid.startswith('.'):
        raise ValueError('Unsafe UUID')
    source = Path('/var/lib/docker/volumes/cloud-soc-central_es-data/_data/indices') / uuid / '0'
    if source.is_symlink() or not (source / 'index').is_dir():
        raise ValueError('Shard directory missing')
    total = sum(p.stat().st_size for p in source.rglob('*') if p.is_file())
    if shutil.disk_usage('/var/tmp').free < total * 3 + 1024**3:
        raise ValueError('Insufficient free space')

    def manifest(root):
        result = {}
        for p in sorted(root.rglob('*')):
            if p.is_symlink():
                raise ValueError('Symlink in shard')
            if p.is_file():
                result[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
        return result

    backup = Path(tempfile.mkdtemp(prefix='cloud-soc-raw21-check-', dir='/var/tmp'))
    before = manifest(source)
    shutil.copytree(source, backup / 'archive-shard')
    if before != manifest(source) or before != manifest(backup / 'archive-shard'):
        raise ValueError('Shard changed during copy; archive not verified')
    (backup / 'manifest.json').write_text(json.dumps(before, indent=2))
    shutil.copytree(backup / 'archive-shard/index', backup / 'check-index')
    image = subprocess.run(['docker', 'inspect', '--format', '{{.Image}}',
        'cloud-soc-central-elasticsearch-1'], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('Unexpected Elasticsearch image identifier')
    container = backup.name
    command = ['docker', 'run', '--rm', '--pull=never', '--name', container,
        '--network', 'none', '--read-only', '--user', '0', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges:true', '--memory', '1g', '--cpus', '2',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m',
        '--mount', 'type=bind,src=' + str(backup / 'check-index') + ',dst=/check',
        '--entrypoint', '/usr/share/elasticsearch/jdk/bin/java', image,
        '-Xmx512m', '-ea:org.apache.lucene...', '-cp', '/usr/share/elasticsearch/lib/*',
        'org.apache.lucene.index.CheckIndex', '/check']
    with (backup / 'checkindex-private.log').open('w') as log:
        try:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=180)
            code = result.returncode
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'stop', '--time', '5', container], capture_output=True, timeout=15)
            code = 124
    text = (backup / 'checkindex-private.log').read_text(errors='replace')
    report = {'index': INDEX, 'backup_directory': str(backup), 'archive_hashes_verified': True,
        'check_exit_code': code,
        'segments_check_passed': code == 0 and 'No problems were detected with this index' in text,
        'segment_doc_counts': re.findall(r'numDocs=(\d+)', text),
        'exception_types': sorted(set(re.findall(r'(?:[a-zA-Z_$][\w$]*\.)+[A-Za-z_$]*Exception', text))),
        'checkindex_output': text, 'live_shard_modified': False,
        'snapshot_replay_initial_utc': '2026-10-16T03:54:50.950880Z'}
    fd, name = tempfile.mkstemp(prefix='raw21-segment-check-', suffix='.json', dir=BASE / 'work')
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    owner = pwd.getpwnam('lyn')
    os.chown(name, owner.pw_uid, owner.pw_gid)
    summary = {k: v for k, v in report.items() if k != 'checkindex_output'}
    summary['private_report'] = name
    print(json.dumps(summary, ensure_ascii=False))
    print('Only archive and disposable copy were created. No translog was truncated and no live shard was changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'check_stopped': type(error).__name__}))
        raise SystemExit(1)
