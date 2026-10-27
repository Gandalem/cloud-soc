"""Read-only Elasticsearch allocation and snapshot diagnostics; no recovery writes."""
import base64
import json
import os
from pathlib import Path
import shutil
import ssl
import urllib.error
import urllib.request


def main():
    os.umask(0o077)
    state = Path('/home/lyn/cloud-soc/state/server')
    password = (state / 'secrets/elastic_password').read_text().strip()
    auth = base64.b64encode(('elastic:' + password).encode()).decode()
    context = ssl.create_default_context(cafile=str(state / 'tls/ca.crt'))

    def get(path, body=None):
        request = urllib.request.Request('https://192.168.1.156:9200' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'}, method='GET')
        try:
            with urllib.request.urlopen(request, context=context, timeout=15) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            return {'query_error': 'HTTP_' + str(error.code)}
        except Exception as error:
            return {'query_error': type(error).__name__}

    snapshot = get('/_snapshot/cloud-soc-backup/manual-20261016-01?filter_path=snapshots.snapshot,snapshots.state,snapshots.version,snapshots.indices,snapshots.feature_states,snapshots.failures')
    sizes = get('/_snapshot/cloud-soc-backup/manual-20261016-01/_status?filter_path=snapshots.state,snapshots.stats.total,snapshots.shards_stats')
    shards = get('/_cat/shards?format=json&h=index,shard,prirep,state')
    if not isinstance(shards, list):
        print(json.dumps(shards))
        return
    explanations = []
    for shard in shards:
        if shard.get('prirep') != 'p' or shard.get('state') != 'UNASSIGNED':
            continue
        result = get('/_cluster/allocation/explain', {
            'index': shard['index'], 'shard': int(shard['shard']), 'primary': True})
        explanations.append(result)
        print(json.dumps({
            'index': shard['index'], 'can_allocate': result.get('can_allocate'),
            'query_error': result.get('query_error'),
            'allocation_reason': result.get('unassigned_info', {}).get('reason'),
            'store_errors': [n.get('store', {}).get('store_exception')
                             for n in result.get('node_allocation_decisions', [])
                             if n.get('store', {}).get('store_exception')],
            'deciders': [d for n in result.get('node_allocation_decisions', [])
                         for d in n.get('deciders', []) if d.get('decision') == 'NO'],
        }, ensure_ascii=False))
    report = {'snapshot': snapshot, 'snapshot_size': sizes,
              'disk_free_bytes': shutil.disk_usage('/var/lib/docker/volumes/cloud-soc-central_es-data/_data').free,
              'allocation': explanations}
    path = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/work/shard-recovery-report-private.json')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
    import pwd
    owner = pwd.getpwnam('lyn')
    os.chown(path, owner.pw_uid, owner.pw_gid)
    print(json.dumps({'snapshot': snapshot, 'snapshot_size': sizes,
                      'disk_free_bytes': report['disk_free_bytes'], 'report': str(path)}, ensure_ascii=False))
    print('Read-only diagnosis completed. No indices, settings or checkpoints were changed.')


if __name__ == '__main__':
    main()
