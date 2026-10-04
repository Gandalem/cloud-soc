"""Read-only live ES deployment preflight. Never print credentials or event bodies."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from elasticsearch import Elasticsearch
from cloud_soc.aws.__main__ import endpoint, protected_key
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS


def complete(result):
    if result.get('timed_out') or result.get('_shards', {}).get('failed', 0):
        raise RuntimeError('incomplete_preflight')
    return result


def inspect(client):
    info = client.info()
    health = client.cluster.health()
    result = {'read_only': True, 'version': info['version']['number'], 'cluster_uuid': info['cluster_uuid'],
              'health': health['status'], 'unassigned_shards': health['unassigned_shards'], 'indices': {}}
    for name in (NORMALIZED, RECORDS, STATUS, 'security-alerts'):
        if not client.indices.exists(index=name):
            result['indices'][name] = {'exists': False}
            continue
        resolved = client.indices.resolve_index(name=name)
        if resolved.get('aliases') or resolved.get('data_streams') or [r['name'] for r in resolved.get('indices', [])] != [name]:
            raise RuntimeError('unexpected_index_identity')
        row = {'exists': True, 'documents': complete(client.count(index=name))['count']}
        if name == NORMALIZED:
            query = {'bool': {'must_not': [{'exists': {'field': 'cloud_soc.normalized_at'}}]}}
            row['missing_normalized_at'] = complete(client.count(index=name, query=query))['count']
            times = complete(client.search(index=name, size=0, allow_partial_search_results=False,
                aggs={'first_event': {'min': {'field': '@timestamp'}},
                      'last_event': {'max': {'field': '@timestamp'}},
                      'last_ingested': {'max': {'field': 'event.ingested'}}}))
            row['time_range'] = {key: value.get('value_as_string') for key, value in times['aggregations'].items()}
        result['indices'][name] = row
    repositories = client.snapshot.get_repository()
    result['snapshot_repositories'] = list(repositories)
    result['snapshot_ready'] = bool(repositories)
    result['requires_legacy_conversion'] = result['indices'].get(NORMALIZED, {}).get('missing_normalized_at', 0) > 0
    result['blocking'] = ['cluster_red'] if health['status'] == 'red' else []
    if not repositories:
        result['blocking'].append('verified_es_snapshot_required_before_conversion')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--es-url', required=True)
    parser.add_argument('--ca-file', required=True)
    parser.add_argument('--password-file', required=True)
    parser.add_argument('--username', default='elastic')
    parser.add_argument('--report', required=True)
    args = parser.parse_args(argv)
    try:
        with Elasticsearch(endpoint(args.es_url), basic_auth=(args.username, protected_key(args.password_file)),
                           ca_certs=args.ca_file, request_timeout=30, max_retries=0) as client:
            report = inspect(client)
        output = Path(args.report)
        # Preserve an earlier report, never overwrite it implicitly.
        with output.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
        print(json.dumps({'read_only': True, 'report_written': True, 'blocking': report['blocking'],
                          'requires_legacy_conversion': report['requires_legacy_conversion']}))
        return 0 if not report['blocking'] else 2
    except Exception:
        print('preflight_failed; verify connection, CA and privileges; credentials and payloads omitted')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
