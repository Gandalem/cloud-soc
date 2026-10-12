"""Resume bounded raw reads without persisting event bodies or advancing coverage early."""
import hashlib
import json

from elasticsearch import NotFoundError

from cloud_soc.portal.log_contract import document_reference


def prepare(db, client, checkpoint, start, end, *, resolve, batches, checked):
    db.execute('CREATE TABLE IF NOT EXISTS scan_progress (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS scan_seen (id TEXT PRIMARY KEY)')
    row = db.execute('SELECT body FROM scan_progress WHERE id=1').fetchone()
    if row:
        meta = json.loads(row[0])
        if meta.get('version') != 1 or meta['checkpoint'] != checkpoint:
            raise RuntimeError('scan_scope_changed')
        return meta
    names = resolve(client)
    scopes = list(batches(names))
    # All mappings must pass before any create-only write.
    for scope in scopes:
        fields = client.field_caps(index=scope, fields=['event.ingested'], include_unmapped=True)
        caps = fields['fields'].get('event.ingested', {})
        if not caps or set(caps) - {'date', 'date_nanos'}:
            raise RuntimeError('receipt_mapping_missing')
    return {'version': 1, 'checkpoint': checkpoint, 'start': start, 'end': end,
            'batches': scopes, 'batch': 0, 'pit': None, 'after': None,
            'counts': {'normalized': 0, 'unsupported': 0, 'invalid': 0}}


def seen_id(hit):
    reference = document_reference(hit.get('_index'), hit.get('_id'))
    return hashlib.sha256(json.dumps(reference, sort_keys=True).encode()).hexdigest()


def read(client, db, meta, *, budget, fields, checked, consume):
    reopened = False
    for _ in range(budget):
        if meta['batch'] == len(meta['batches']):
            return True
        scope = meta['batches'][meta['batch']]
        if not meta['pit']:
            opened = client.open_point_in_time(index=scope, keep_alive='10m', allow_partial_search_results=False)
            meta['pit'] = opened['id']
            checked(opened)
            meta['after'] = None
        try:
            result = client.search(pit={'id': meta['pit'], 'keep_alive': '10m'},
                size=200, sort=['_shard_doc'], search_after=meta['after'], source=fields,
                track_total_hits=False, allow_partial_search_results=False, timeout='10s',
                query={'range': {'event.ingested': {'gte': meta['start'], 'lt': meta['end']}}})
        except NotFoundError:
            if reopened:
                raise
            # Replay only this fixed receipt range; committed reference hashes
            # skip already delivered events without keeping their contents.
            meta['pit'], meta['after'], reopened = None, None, True
            continue
        meta['pit'] = result.get('pit_id', meta['pit'])
        checked(result)
        hits = result['hits']['hits']
        if not hits:
            client.close_point_in_time(id=meta['pit'])
            meta['pit'], meta['after'] = None, None
            meta['batch'] += 1
            continue
        after = hits[-1].get('sort')
        if (not isinstance(after, list) or not after or after == meta['after'] or len(hits) > 200
                or any(hit.get('_index') not in scope for hit in hits)):
            raise RuntimeError('cursor_not_advancing')
        unseen = [hit for hit in hits if not db.execute('SELECT 1 FROM scan_seen WHERE id=?', (seen_id(hit),)).fetchone()]
        consume(unseen, meta['counts'])
        for hit in unseen:
            db.execute('INSERT OR IGNORE INTO scan_seen VALUES(?)', (seen_id(hit),))
        meta['after'] = after
    return meta['batch'] == len(meta['batches'])


def remember(db, meta):
    db.execute('INSERT OR REPLACE INTO scan_progress VALUES(1,?)', (json.dumps(meta),))


def clear(db):
    db.execute('DELETE FROM scan_progress')
    db.execute('DELETE FROM scan_seen')
