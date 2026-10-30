"""Read-only raw index disk inventory, source ranges and checkpoint assessment."""
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import sqlite3
import ssl
import subprocess
import traceback
import urllib.error
import urllib.parse
import urllib.request

BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')
STATE = Path('/home/lyn/cloud-soc/state/server')
RAW = 'soc-host-raw-linux-9.5.2-2026.10.21'


def main():
    os.umask(0o077)
    auth = base64.b64encode(('elastic:' + (STATE / 'secrets/elastic_password').read_text().strip()).encode()).decode()
    context = ssl.create_default_context(cafile=str(STATE / 'tls/ca.crt'))

    def get(path, body=None):
        req = urllib.request.Request('https://192.168.1.156:9200' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'}, method='GET')
        try:
            with urllib.request.urlopen(req, context=context, timeout=20) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            return {'query_error': 'HTTP_' + str(e.code)}
        except Exception as e:
            return {'query_error': type(e).__name__}

    report = {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    settings = get('/_cat/indices/' + RAW + '?format=json&h=index,uuid&expand_wildcards=all')
    if isinstance(settings, dict) and settings.get('query_error'):
        print(json.dumps({'uuid_query_error': settings['query_error']}))
    uuid = next((row.get('uuid') for row in settings if row.get('index') == RAW), None) if isinstance(settings, list) else None
    if not uuid or '/' in uuid or uuid.startswith('.'):
        raise ValueError('Could not resolve raw index UUID')
    shard = Path('/var/lib/docker/volumes/cloud-soc-central_es-data/_data/indices') / uuid / '0'
    files = []
    for folder in ('index', 'translog', '_state'):
        for p in sorted((shard / folder).glob('*')):
            if not p.is_file():
                continue
            st = p.stat()
            record = {'file': folder + '/' + p.name, 'bytes': st.st_size,
                      'mtime_utc': datetime.datetime.fromtimestamp(st.st_mtime, datetime.timezone.utc).isoformat()}
            if p.name.startswith('segments_') and st.st_size < 10 * 1024 * 1024:
                record['sha256'] = hashlib.sha256(p.read_bytes()).hexdigest()
            files.append(record)
    report['raw_files'] = {'index_uuid': uuid, 'shard_path': str(shard), 'files': files,
                           'total_bytes': sum(f['bytes'] for f in files)}
    explanation = get('/_cluster/allocation/explain', {'index': RAW, 'shard': 0, 'primary': True})
    report['raw_allocation'] = explanation
    text = json.dumps(explanation)
    import re
    missing = sorted(set(re.findall(r'translog-\d+\.tlog', text)))
    print(json.dumps({'raw_index': RAW, 'index_uuid': uuid,
                      'shard_total_bytes': report['raw_files']['total_bytes'],
                      'segment_commit_files': [f['file'] for f in files if f['file'].startswith('index/segments_')],
                      'translog_files': [f for f in files if f['file'].startswith('translog/')],
                      'translogs_mentioned_in_error': missing,
                      'mentioned_translogs_present': {n: (shard / 'translog' / n).is_file() for n in missing}}, ensure_ascii=False))
    indices = get('/_cat/indices/soc-host-raw-*,soc-network-*?format=json&h=index,health,status,docs.count&expand_wildcards=open&allow_no_indices=true')
    report['raw_ranges'] = []
    if isinstance(indices, list):
        for row in indices:
            if row.get('health') not in ('green', 'yellow'):
                report['raw_ranges'].append(row)
                continue
            result = get('/' + urllib.parse.quote(row['index'], safe='') + '/_search?allow_partial_search_results=false', {
                'size': 0, 'track_total_hits': True,
                'aggs': {'first_receipt': {'min': {'field': 'event.ingested'}},
                         'last_receipt': {'max': {'field': 'event.ingested'}},
                         'after_snapshot': {'filter': {'range': {'event.ingested': {'gte': '2026-10-16T07:28:06.324Z'}}}}}})
            report['raw_ranges'].append({'index': row['index'], 'health': row.get('health'),
                'documents': result.get('hits', {}).get('total'), 'ranges': result.get('aggregations'),
                'query_error': result.get('query_error'), 'failed_shards': result.get('_shards', {}).get('failed')})
    print(json.dumps({'raw_ranges': report['raw_ranges']}, ensure_ascii=False))
    report['normalizer_checkpoints'] = {}
    for service in ('normalizer', 'normalizer-priority'):
        db = STATE / 'runtime/state' / service / 'checkpoint.sqlite'
        if db.is_file():
            try:
                connection = sqlite3.connect(db.as_uri() + '?mode=ro', uri=True, timeout=2)
                try:
                    report['normalizer_checkpoints'][service] = {
                        'state': connection.execute('SELECT checkpoint,last_success FROM state WHERE id=1').fetchall(),
                        'initial': connection.execute('SELECT initial_start FROM config WHERE id=1').fetchall()}
                finally:
                    connection.close()
            except sqlite3.Error as e:
                report['normalizer_checkpoints'][service] = {'read_error': type(e).__name__}
    print(json.dumps({'normalizer_checkpoints': report['normalizer_checkpoints']}))
    help_result = subprocess.run(['docker', 'exec', 'cloud-soc-central-elasticsearch-1',
        '/usr/share/elasticsearch/jdk/bin/java', '-cp', '/usr/share/elasticsearch/lib/*',
        'org.apache.lucene.index.CheckIndex', '-help'], capture_output=True, text=True, timeout=20)
    report['checkindex_help'] = {'exit_code': help_result.returncode, 'text': help_result.stdout + help_result.stderr}
    journal = subprocess.run(['journalctl', '--list-boots', '--no-pager'], capture_output=True, text=True, timeout=10)
    report['journal_boots'] = journal.stdout
    fd, name = __import__('tempfile').mkstemp(prefix='raw-recovery-report-', suffix='.json', dir=BASE / 'work')
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    owner = pwd.getpwnam('lyn')
    os.chown(name, owner.pw_uid, owner.pw_gid)
    print(json.dumps({'private_report': name, 'checkindex_help_exit': help_result.returncode,
                      'live_files_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'diagnosis_stopped': type(e).__name__,
                          'frames': [{'function': f.name, 'line': f.lineno}
                                     for f in traceback.extract_tb(e.__traceback__)]}))
        raise SystemExit(1)
