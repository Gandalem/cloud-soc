"""Replay retained intake into isolated, create-only indices for the unified log view."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

from elasticsearch import Elasticsearch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from cloud_soc.portal.agent_status import iso, parse_time  # noqa: E402
from cloud_soc.portal.log_contract import INDICES, project_hit  # noqa: E402
from cloud_soc.portal.log_normalization import processing_candidates  # noqa: E402
from cloud_soc.processing.contract import (  # noqa: E402
    BACKFILL_NORMALIZED, BACKFILL_RECORDS, RECORDS, normalize,
)
from cloud_soc.processing.worker import READ_FIELDS, checked, create_batch, resolve  # noqa: E402
from cloud_soc.web.scope import NORMALIZER_VERSION  # noqa: E402

SOURCE = ['labels.log_source', 'log.file.path', 'input.type', 'log_source', 'agent.type']


def mget(client, index, ids, fields):
    result = client.mget(index=index, docs=[{'_id': key, '_source': fields} for key in ids])['docs']
    if len(result) != len(ids):
        raise ValueError('incomplete_mget')
    found = {}
    for key, doc in zip(ids, result, strict=True):
        if doc.get('_index') != index or doc.get('_id') != key or 'error' in doc:
            raise ValueError('invalid_mget_result')
        if doc.get('found') is True:
            found[key] = doc
        elif doc.get('found') is not False:
            raise ValueError('invalid_mget_status')
    return found


def pages(client, index, before, *, unsupported=False):
    pit = None
    after = None
    try:
        pit = checked(client.open_point_in_time(index=index, keep_alive='2m',
                                               allow_partial_search_results=False))['id']
        while True:
            result = client.search(body={
                'pit': {'id': pit, 'keep_alive': '2m'}, 'size': 500, 'sort': ['_shard_doc'],
                'track_total_hits': False, '_source': ['raw'] if unsupported else SOURCE, 'timeout': '15s',
                'query': {'bool': {'filter': [{'range': {'event.ingested': {'lt': before}}},
                          *([{'term': {'status': 'unsupported'}}] if unsupported else [])]}},
                **({'search_after': after} if after is not None else {}),
            }, allow_partial_search_results=False)
            pit = result.get('pit_id', pit)
            batch = checked(result)['hits']['hits']
            if not batch:
                return
            next_after = batch[-1]['sort']
            if after == next_after or any(hit.get('_index') != index for hit in batch):
                raise ValueError('unexpected_scan_result')
            after = next_after
            yield batch
    finally:
        if pit:
            client.close_point_in_time(id=pit)


def replay(client, index, before, apply):
    counts = Counter()
    for hits in pages(client, index, before):
        candidates = {}
        for hit in hits:
            counts['scanned'] += 1
            try:
                row = project_hit(hit)
            except ValueError:
                counts['invalid_reference'] += 1
                continue
            _, keys = processing_candidates(hit['_source'], row['reference'], row['source_kind'])
            candidates[hit['_id']] = keys
        ids = list(dict.fromkeys(key for keys in candidates.values() for key in keys))
        live = {}
        for offset in range(0, len(ids), 500):
            live.update(mget(client, RECORDS, ids[offset:offset + 500], ['status', 'version', 'raw.index', 'raw.id']))
        todo = []
        for identifier, keys in candidates.items():
            ref = {'index': index, 'id': identifier}
            if any(live[key]['_source'].get('status') == 'normalized'
                   and live[key]['_source'].get('raw') == ref
                   and live[key]['_source'].get('version') == version
                   for key, version in keys.items() if key in live):
                counts['existing_normalized'] += 1
            else:
                todo.append(identifier)
        if not todo:
            continue
        raw = mget(client, index, todo, list(dict.fromkeys(READ_FIELDS)))
        counts['source_expired'] += len(todo) - len(raw)
        operations = []
        for hit in raw.values():
            key, record, event = normalize(hit, before, web_version=NORMALIZER_VERSION)
            counts[record['status']] += 1
            if event is not None:
                record['normalized']['index'] = BACKFILL_NORMALIZED
                operations.append((BACKFILL_NORMALIZED, key, event))
            operations.append((BACKFILL_RECORDS, key, record))
        if apply:
            for offset in range(0, len(operations), 200):
                create_batch(client, operations[offset:offset + 200])
        time.sleep(0.05)
    return counts


def replay_unsupported(client, names, before, apply):
    counts = Counter()
    for hits in pages(client, BACKFILL_RECORDS, before, unsupported=True):
        grouped = {}
        for hit in hits:
            counts['scanned'] += 1
            ref = hit['_source']['raw']
            if ref['index'] not in names:
                counts['source_expired'] += 1
                continue
            grouped.setdefault(ref['index'], []).append(ref['id'])
        for index, ids in grouped.items():
            raw = mget(client, index, list(dict.fromkeys(ids)), list(dict.fromkeys(READ_FIELDS)))
            counts['source_expired'] += len(ids) - len(raw)
            operations = []
            for hit in raw.values():
                key, record, event = normalize(hit, before, web_version=NORMALIZER_VERSION)
                counts[record['status']] += 1
                if event is None:
                    continue
                counts['candidates'] += 1
                record['normalized']['index'] = BACKFILL_NORMALIZED
                operations.extend([(BACKFILL_NORMALIZED, key, event), (BACKFILL_RECORDS, key, record)])
            new_keys = [key for index_name, key, _ in operations if index_name == BACKFILL_NORMALIZED]
            existing = mget(client, BACKFILL_RECORDS, new_keys, ['status']) if new_keys else {}
            existing = {key for key, row in existing.items() if row['_source'].get('status') == 'normalized'}
            counts['already_reprocessed'] += len(existing)
            operations = [(index_name, key, record) for index_name, key, record in operations if key not in existing]
            if apply:
                for offset in range(0, len(operations), 200):
                    create_batch(client, operations[offset:offset + 200])
        time.sleep(0.05)
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--before', required=True)
    parser.add_argument('--ca', required=True, type=Path)
    parser.add_argument('--password-file', required=True, type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--unsupported-only', action='store_true')
    args = parser.parse_args()
    stamp = parse_time(args.before)
    if stamp is None or stamp > datetime.now(timezone.utc):
        parser.error('a fixed past receipt-time cutoff is required')
    client = Elasticsearch('https://elasticsearch:9200',
                           basic_auth=('elastic', args.password_file.read_text().strip()),
                           ca_certs=str(args.ca), request_timeout=35, max_retries=3)
    for index in (BACKFILL_NORMALIZED, BACKFILL_RECORDS):
        mapping = client.indices.get_mapping(index=index)
        if set(mapping) != {index} or mapping[index]['mappings'].get('_meta', {}).get('contract') != index:
            raise ValueError('backfill_index_contract_mismatch')
    total = Counter()
    names = set(resolve(client, INDICES))
    if args.unsupported_only:
        total = replay_unsupported(client, names, iso(stamp), args.apply)
    for name in sorted(names if not args.unsupported_only else (), reverse=True):
        counts = replay(client, name, iso(stamp), args.apply)
        total.update(counts)
        print(json.dumps({'index': name, 'counts': counts}), flush=True)
    print(json.dumps({'complete': True, 'apply': args.apply, 'before': iso(stamp), 'counts': total}), flush=True)


if __name__ == '__main__':
    main()
