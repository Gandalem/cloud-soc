"""Read-only immutable alert/notice guard across an upgrade."""
import json
import sys

from cloud_soc.deployment.contract import digest
from cloud_soc.deployment.verify import checked


def capture(client):
    from elasticsearch.helpers import scan
    result = {}
    for index in ('security-alerts', 'soc-alert-notices-v1'):
        if not client.indices.exists(index=index):
            continue
        rows = {}
        for hit in scan(client, index=index, query={'query': {'match_all': {}}},
                        allow_partial_search_results=False, raise_on_error=True):
            rows[hit['_id']] = digest(hit['_source'])
            if len(rows) > 100000:
                raise ValueError('Immutable document guard exceeds the reviewed budget')
        result[index] = rows
    return result


def check(client, before):
    count = 0
    for index, rows in before.items():
        ids = list(rows)
        for offset in range(0, len(ids), 100):
            batch = ids[offset:offset+100]
            response = checked(client.mget(index=index, ids=batch))
            if len(response['docs']) != len(batch) or {hit['_id'] for hit in response['docs']} != set(batch):
                raise ValueError('Incomplete immutable document verification')
            for hit in response['docs']:
                if not hit.get('found') or hit.get('error') or digest(hit['_source']) != rows[hit['_id']]:
                    raise ValueError('Existing alert/notice was removed or changed')
                count += 1
    return {'existing_immutable_documents_preserved': count}


def main():
    from elasticsearch import Elasticsearch
    payload = json.load(sys.stdin)
    with Elasticsearch('https://elasticsearch:9200', basic_auth=('elastic', payload['password']),
                       ca_certs='/run/certs/ca.crt', request_timeout=30, max_retries=0) as client:
        print(json.dumps(check(client, payload['before']) if 'before' in payload else capture(client)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('runtime_preservation_guard_failed; protected payloads omitted') from None
