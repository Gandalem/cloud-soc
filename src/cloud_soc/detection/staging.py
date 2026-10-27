"""Durable input spool: receipt windows finalize only after a complete PIT scan."""
import json

from elasticsearch import NotFoundError

from cloud_soc.elastic.pagination import IncompleteSearchError
from cloud_soc.processing.contract import NORMALIZED
from cloud_soc.processing import receipt

MAX_STAGED = 1_000_000


def prepare(db, identity, checkpoint, lower, end):
    db.execute('CREATE TABLE IF NOT EXISTS input_scan (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS input_hits (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
    row = db.execute('SELECT body FROM input_scan WHERE id=1').fetchone()
    if row:
        meta = json.loads(row[0])
        if meta['identity'] != identity or meta['checkpoint'] != checkpoint:
            raise ValueError('input_scan_scope_changed')
        return meta
    return {'identity': identity, 'checkpoint': checkpoint, 'lower': lower, 'end': end,
            'pit': None, 'after': None, 'complete': False}


def remember(db, meta):
    db.execute('INSERT OR REPLACE INTO input_scan VALUES(1,?)', (json.dumps(meta),))


def add(db, hit, meta, seen):
    if hit.get('_index') != NORMALIZED or not isinstance(hit.get('_id'), str) or not hit['_id']:
        raise ValueError('invalid_reference')
    if not receipt.contains(hit['_source']['cloud_soc']['normalized_at'], meta['lower'], meta['end']):
        # A date mapping may return another source timestamp in the same
        # millisecond. It belongs to an adjacent exact window, not this spool.
        return False
    if hit['_id'] in seen or db.execute('SELECT 1 FROM input_hits WHERE id=?', (hit['_id'],)).fetchone():
        return False
    body = json.dumps({k: hit[k] for k in ('_index', '_id', '_source')})
    if len(body.encode()) > 262144:
        raise ValueError('input_document_size_limit')
    db.execute('INSERT INTO input_hits VALUES(?,?)', (hit['_id'], body))
    return True


def checked(response):
    if response.get('timed_out') or response.get('terminated_early') or response.get('_shards', {}).get('failed', 0):
        raise IncompleteSearchError('partial_input_scan')
    return response


def read_window(client, db, meta, *, budget, seen, scanner=None):
    if meta.get('receipt_query_version') != 2:
        # Old cursors used narrower date buckets. Replay the same fixed window
        # once so records earlier in shard order are not missed after upgrade.
        if meta.get('pit'):
            try:
                client.close_point_in_time(id=meta['pit'])
            except Exception:
                pass  # The old PIT expires; the replacement does not use it.
        meta.update(pit=None, after=None, complete=False, receipt_query_version=2)
    if meta['complete']:
        return True
    query = receipt.query('cloud_soc.normalized_at', meta['lower'], meta['end'])
    total = db.execute('SELECT count(*) FROM input_hits').fetchone()[0]
    added = 0

    def store(hit):
        nonlocal total, added
        if add(db, hit, meta, seen):
            total += 1
            added += 1
            if total > MAX_STAGED:
                raise ValueError('input_spool_limit')

    if scanner is not None:
        # Test/replay adapters provide a complete snapshot; production uses PIT.
        for hit in scanner(client, index=NORMALIZED, page_size=500, max_documents=None, query=query):
            store(hit)
            if added >= budget:
                remember(db, meta)
                return False
        meta['complete'] = True
    else:
        reopened = False
        for _ in range(10000):
            if not meta['pit']:
                opened = client.open_point_in_time(index=NORMALIZED, keep_alive='10m',
                    allow_partial_search_results=False)
                meta['pit'] = opened['id']
                checked(opened)
                meta['after'] = None
            try:
                response = client.search(pit={'id': meta['pit'], 'keep_alive': '10m'},
                    size=min(500, budget - added), sort=['_shard_doc'], search_after=meta['after'],
                    query=query, track_total_hits=False, allow_partial_search_results=False, timeout='10s')
            except NotFoundError:
                if reopened:
                    raise
                # An expired PIT restarts the same receipt range. Staged/seen IDs
                # do not consume the new-input budget, even for identical times.
                meta['pit'], meta['after'], reopened = None, None, True
                continue
            meta['pit'] = response.get('pit_id', meta['pit'])
            checked(response)
            hits = response['hits']['hits']
            if not hits:
                client.close_point_in_time(id=meta['pit'])
                meta['pit'], meta['after'], meta['complete'] = None, None, True
                break
            after = hits[-1].get('sort')
            if not after or after == meta['after'] or len(hits) > min(500, budget - added):
                raise IncompleteSearchError('input_cursor_or_page_invalid')
            for hit in hits:
                store(hit)
            meta['after'] = after
            if added >= budget:
                remember(db, meta)
                return False
        else:
            raise IncompleteSearchError('input_page_limit')
    remember(db, meta)
    return True


def staged_hits(db):
    for row in db.execute('SELECT body FROM input_hits ORDER BY id'):
        yield json.loads(row[0])


def clear(db):
    db.execute('DELETE FROM input_hits')
    db.execute('DELETE FROM input_scan')
