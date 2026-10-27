"""Restore five indices under isolated names. Never replace original indices."""
import base64
import json
import ssl
from pathlib import Path
import urllib.error
import urllib.request

INDICES = ['soc-normalized-v1', 'soc-pipeline-status', 'soc-processing-v1',
           'soc-detection-exclusions-v1', 'soc-detection-runs-v1']
PREFIX = 'recovery-20261016-'


def main():
    state = Path('/home/lyn/cloud-soc/state/server')
    password = (state / 'secrets/elastic_password').read_text().strip()
    auth = base64.b64encode(('elastic:' + password).encode()).decode()
    context = ssl.create_default_context(cafile=str(state / 'tls/ca.crt'))

    def request(method, path, body=None):
        req = urllib.request.Request('https://192.168.1.156:9200' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + auth, 'Content-Type': 'application/json'}, method=method)
        with urllib.request.urlopen(req, context=context, timeout=30) as response:
            return json.load(response)

    names = ','.join(PREFIX + name for name in INDICES)
    existing = request('GET', '/_cat/indices/' + names + '?format=json&h=index,health,status,docs.count&allow_no_indices=true&ignore_unavailable=true')
    if not existing:
        snapshot = request('GET', '/_snapshot/cloud-soc-backup/manual-20261016-01')['snapshots'][0]
        if snapshot['state'] != 'SUCCESS' or not set(INDICES) <= set(snapshot['indices']):
            raise ValueError('Snapshot precondition failed')
        result = request('POST', '/_snapshot/cloud-soc-backup/manual-20261016-01/_restore', {
            'indices': ','.join(INDICES), 'ignore_unavailable': False,
            'include_global_state': False, 'feature_states': ['none'],
            'include_aliases': False, 'partial': False,
            'rename_pattern': '(.+)', 'rename_replacement': PREFIX + '$1',
            'index_settings': {'index.number_of_replicas': 0}})
        print(json.dumps({'restore_request': result, 'original_indices_replaced': False}))
    else:
        if {row['index'] for row in existing} != {PREFIX + name for name in INDICES}:
            raise ValueError('Partial existing sidecopy; no overwrite attempted')
        print('Existing sidecopy found; checking only.')
    health = request('GET', '/_cluster/health/' + names + '?wait_for_status=yellow&timeout=10s')
    print(json.dumps({'sidecopy_health': health}))
    rows = request('GET', '/_cat/indices/' + names + '?format=json&h=index,health,status,docs.count,store.size')
    print(json.dumps({'sidecopy_indices': rows}))
    ready = (health.get('status') in ('green', 'yellow')
             and not health.get('timed_out')
             and health.get('active_primary_shards') == len(INDICES)
             and health.get('unassigned_primary_shards', 0) == 0
             and health.get('initializing_shards', 0) == 0)
    print(json.dumps({'sidecopy_ready': ready}))
    if ready:
        for name in INDICES:
            count = request('GET', '/' + PREFIX + name + '/_count')
            print(json.dumps({'index': PREFIX + name, 'count': count.get('count'),
                              'failed_shards': count.get('_shards', {}).get('failed')}))
    else:
        shards = request('GET', '/_cat/shards/' + names + '?format=json&h=index,shard,prirep,state,unassigned.reason')
        print(json.dumps({'sidecopy_shards': shards}))
        pending = request('GET', '/_cluster/pending_tasks?filter_path=tasks.priority,tasks.source,tasks.time_in_queue')
        print(json.dumps({'pending_tasks': pending}))
        unassigned = next((s for s in shards if s.get('prirep') == 'p' and s.get('state') == 'UNASSIGNED'), None)
        if unassigned:
            explanation = request('GET', '/_cluster/allocation/explain', {
                'index': unassigned['index'], 'shard': int(unassigned['shard']), 'primary': True})
            print(json.dumps({'sidecopy_allocation': explanation}))
    print('Original indices, aliases, security settings, worker checkpoints and Kibana were not replaced.')


if __name__ == '__main__':
    try:
        main()
    except urllib.error.HTTPError as error:
        print(json.dumps({'request_failed_http': error.code}))
        raise SystemExit(1)
    except Exception as error:
        print(json.dumps({'operation_stopped': type(error).__name__}))
        raise SystemExit(1)
