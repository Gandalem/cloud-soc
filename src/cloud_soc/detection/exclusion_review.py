"""Evidence-backed exclusion reviews stored separately from immutable telemetry."""
import argparse
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import tempfile

from cloud_soc.detection.engine import SERVICE_LOGON_SCOPE_RULES, event_fingerprint, get_field_value as field, rule_revision
from cloud_soc.detection.profiles import catalog
from cloud_soc.detection.telemetry import EXCLUSIONS, evaluate
from cloud_soc.portal.log_contract import document_reference
from cloud_soc.processing.contract import NORMALIZED

DATABASE = 'exclusion-reviews.sqlite'
REVIEWED_DECISIONS = ('resolved_scope', 'confirmed_input_gap', 'confirmed_late', 'confirmed_reprocessing_needed')


def checked(result):
    if result.get('timed_out') or result.get('terminated_early') or result.get('_shards', {}).get('failed', 0):
        raise ValueError('Incomplete exclusion search')
    return result


def classify(record, normalized, raw, rule):
    """Reassess exact evidence with the current rule, keeping actual gaps unresolved."""
    if not normalized or not raw or not rule:
        return 'needs_review'
    reference = record.get('normalized', {})
    hashed = dict(normalized)
    hashed['_cloud_soc_meta'] = {'index': reference.get('index'), 'document_id': reference.get('id')}
    if (event_fingerprint(hashed) != record.get('event_hash')
            or field(normalized, 'cloud_soc.provenance.raw') != record.get('raw')
            or field(normalized, 'organization.id') != field(raw, 'organization.id')):
        return 'needs_review'
    outcome, missing = evaluate(normalized, rule)
    if outcome == 'not_matched':
        if (rule['id'] in SERVICE_LOGON_SCOPE_RULES
                and field(normalized, 'cloud_soc.detail.adapter') == 'windows_security_v1'
                and field(normalized, 'event.outcome') == 'success'
                and field(normalized, 'cloud_soc.detail.fields.logon_type') == 5
                and (str(field(raw, 'winlog.event_id')) != '4624'
                     or str(field(raw, 'winlog.event_data.LogonType')) != '5')):
            return 'needs_review'
        return 'resolved_scope'
    if (outcome == 'unknown' and missing
            and field(normalized, 'cloud_soc.detail.adapter') == 'packetbeat_metadata_v1'
            and field(raw, 'event.dataset') == 'flow'
            and all(field(raw, name) in (None, '', '-') for name in missing)
            and set(missing) <= {'source.ip', 'destination.ip', 'network.transport'}):
        return 'confirmed_input_gap'
    if outcome == 'matched' and record.get('reason') == 'late_event':
        return 'confirmed_late'
    if outcome == 'matched' and record.get('reason') in ('missing_condition_fields', 'missing_group_fields'):
        return 'confirmed_reprocessing_needed'
    if outcome == 'unknown':
        from cloud_soc.processing.contract import normalize
        _, processed, event = normalize({'_index': record['raw']['index'], '_id': record['raw']['id'],
                                         '_source': raw}, datetime.now(timezone.utc).isoformat())
        if processed['status'] == 'normalized' and event is not None:
            fresh_outcome, fresh_missing = evaluate(event, rule)
            if fresh_outcome == 'unknown' and set(fresh_missing) == set(missing):
                return 'confirmed_input_gap'
            return 'confirmed_reprocessing_needed'
    return 'needs_review'


def fetched(client, requests):
    if not requests:
        return {}
    docs = client.mget(docs=list(requests.values()))['docs']
    if len(docs) != len(requests):
        raise ValueError('Incomplete review evidence')
    result = {}
    for request, doc in zip(requests.values(), docs):
        if (doc.get('error') or doc.get('_index') != request['_index']
                or doc.get('_id') != request['_id']):
            raise ValueError('Unexpected review evidence')
        result[doc['_index'], doc['_id']] = doc.get('_source') if doc.get('found') else None
    return result


def review(client, path, *, actor, apply=False, max_records=500000):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink() or not actor or len(actor) > 80:
        raise ValueError('Invalid review path or actor')
    rules = {rule['id']: rule for rule in catalog()}
    stamp = datetime.now(timezone.utc).isoformat()
    # Stage the complete PIT before changing the durable review database.
    with tempfile.TemporaryDirectory(prefix='exclusion-review-', dir=path.parent) as directory:
        with closing(sqlite3.connect(Path(directory) / 'stage.sqlite')) as stage:
            stage.execute('CREATE TABLE staged (id TEXT PRIMARY KEY, rule TEXT, decision TEXT, '
                          'version TEXT, source_hash TEXT, reviewed_at TEXT, actor TEXT)')
            pit = client.open_point_in_time(index=EXCLUSIONS, keep_alive='2m')['id']
            after = None
            count = 0
            counts = Counter()
            census = {}
            try:
                while True:
                    response = checked(client.search(
                        pit={'id': pit, 'keep_alive': '2m'}, size=250,
                        sort=['_shard_doc'], search_after=after,
                        query={'match_all': {}}, track_total_hits=False))
                    pit = response.get('pit_id', pit)
                    hits = response['hits']['hits']
                    if not hits:
                        break
                    count += len(hits)
                    if count > max_records:
                        raise ValueError('Review budget exceeded; no review applied')
                    requests = {}
                    for hit in hits:
                        record = hit['_source']
                        for name in ('raw', 'normalized'):
                            ref = record.get(name, {})
                            if name == 'raw':
                                if document_reference(ref.get('index'), ref.get('id')) != ref:
                                    continue
                            elif ref.get('index') != NORMALIZED or not isinstance(ref.get('id'), str):
                                continue
                            requests[ref['index'], ref['id']] = {'_index': ref['index'], '_id': ref['id']}
                    documents = fetched(client, requests)
                    for hit in hits:
                        record = hit['_source']
                        if record.get('record_id') != hit['_id']:
                            raise ValueError('Exclusion identity mismatch')
                        rule = rules.get(record['rule']['id'])
                        row = census.setdefault(record['rule']['id'], {'total': 0, 'latest': ''})
                        row['total'] += 1
                        row['latest'] = max(row['latest'], record['@timestamp'])
                        norm_ref, raw_ref = record.get('normalized', {}), record.get('raw', {})
                        decision = classify(record,
                            documents.get((norm_ref.get('index'), norm_ref.get('id'))),
                            documents.get((raw_ref.get('index'), raw_ref.get('id'))), rule)
                        version = rule_revision(rule) if rule else 'unknown'
                        stage.execute('INSERT INTO staged VALUES(?,?,?,?,?,?,?)', (
                            hit['_id'], record['rule']['id'], decision, version,
                            event_fingerprint(record), stamp, actor))
                        counts[decision] += 1
                    seek = hits[-1]['sort']
                    if seek == after:
                        raise ValueError('Review cursor did not advance')
                    after = seek
                    stage.commit()
            finally:
                client.close_point_in_time(id=pit)
            if apply:
                with closing(sqlite3.connect(path, timeout=10)) as db:
                    db.execute('PRAGMA journal_mode=WAL')
                    db.execute('PRAGMA synchronous=FULL')
                    db.execute('CREATE TABLE IF NOT EXISTS reviews '
                               '(id TEXT PRIMARY KEY, rule TEXT, decision TEXT, version TEXT, '
                               'source_hash TEXT, reviewed_at TEXT, actor TEXT)')
                    db.execute('CREATE TABLE IF NOT EXISTS review_history '
                               '(id TEXT, rule TEXT, decision TEXT, version TEXT, source_hash TEXT, '
                               'reviewed_at TEXT, actor TEXT, PRIMARY KEY(id,decision,version,source_hash))')
                    db.execute('CREATE TABLE IF NOT EXISTS review_census '
                               '(rule TEXT PRIMARY KEY, total INTEGER, latest TEXT)')
                    db.execute('BEGIN IMMEDIATE')
                    db.execute('DELETE FROM reviews')
                    for row in stage.execute('SELECT * FROM staged'):
                        db.execute('INSERT OR IGNORE INTO review_history VALUES(?,?,?,?,?,?,?)', row)
                        db.execute('INSERT OR REPLACE INTO reviews VALUES(?,?,?,?,?,?,?)', row)
                    db.execute('DELETE FROM review_census')
                    db.executemany('INSERT INTO review_census VALUES(?,?,?)', [
                        (rule, row['total'], row['latest']) for rule, row in census.items()])
                    db.commit()
                path.chmod(0o600)
    return {'applied': apply, 'reviewed_at': stamp, 'records_scanned': count,
            'decisions': dict(counts), 'unresolved': count - counts['resolved_scope']}


def summary(client, path):
    """Count reviewed IDs still present, so new records do not invalidate old decisions."""
    rules = {rule['id']: rule_revision(rule) for rule in catalog()}
    result = checked(client.search(index=EXCLUSIONS, size=0, track_total_hits=True,
        aggs={'rules': {'terms': {'field': 'rule.id', 'size': 1000},
                        'aggs': {'latest': {'max': {'field': '@timestamp'}}}}}))
    buckets = result['aggregations']['rules']
    if buckets.get('sum_other_doc_count', 0) or buckets.get('doc_count_error_upper_bound', 0):
        raise ValueError('Incomplete review totals')
    totals = {row['key']: row['doc_count'] for row in buckets['buckets']}
    reviewed = Counter()
    snapshot = Counter()
    path = Path(path)
    last = None
    if path.exists():
        if path.is_symlink():
            raise ValueError('Unsafe review database')
        with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
            db.execute('BEGIN')
            cursor = db.execute('SELECT id,rule,decision,version,reviewed_at FROM reviews '
                                "WHERE decision != 'needs_review' ORDER BY id")
            while batch := cursor.fetchmany(20000):
                groups = {}
                for identifier, rule, decision, version, at in batch:
                    if rules.get(rule) != version or decision not in REVIEWED_DECISIONS:
                        continue
                    snapshot[rule] += 1
                    last = max(last or at, at)
                    groups.setdefault((rule, decision), []).append(identifier)
                if not groups:
                    continue
                filters = {rule + '|' + decision: {'bool': {'filter': [
                    {'terms': {'record_id': identifiers}}, {'term': {'rule.id': rule}},
                ]}} for (rule, decision), identifiers in groups.items()}
                matched = checked(client.search(index=EXCLUSIONS, size=0, track_total_hits=False,
                    allow_partial_search_results=False,
                    query={'terms': {'record_id': [identifier for ids in groups.values() for identifier in ids]}},
                    aggs={'reviews': {'filters': {'filters': filters}}}))
                buckets = matched['aggregations']['reviews']['buckets']
                if set(buckets) != set(filters):
                    raise ValueError('Incomplete reviewed record counts')
                for (rule, decision), identifiers in groups.items():
                    count = buckets[rule + '|' + decision]['doc_count']
                    if type(count) is not int or not 0 <= count <= len(identifiers):
                        raise ValueError('Invalid reviewed record counts')
                    reviewed[rule, decision] += count
    rows = {}
    for rule, total in totals.items():
        resolved = reviewed[rule, 'resolved_scope']
        gaps = reviewed[rule, 'confirmed_input_gap']
        late = reviewed[rule, 'confirmed_late']
        reprocessing = reviewed[rule, 'confirmed_reprocessing_needed']
        reviewed_count = resolved + gaps + late + reprocessing
        if reviewed_count > total:
            raise ValueError('Review counts changed during search; retry')
        unreviewed = total - reviewed_count
        rows[rule] = {'total': total, 'resolved': resolved, 'confirmed_input_gap': gaps,
                      'confirmed_late': late, 'reprocessing_needed': reprocessing,
                      'reviewed': reviewed_count, 'unresolved': total - resolved,
                      'unreviewed': unreviewed, 'snapshot_reviewed': snapshot[rule],
                      'review_state': 'current' if unreviewed == 0 else 'review_required'}
    return {'state': 'ok', 'last_reviewed': last, 'rules': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--actor', required=True)
    parser.add_argument('--max-records', type=int, default=500000)
    args = parser.parse_args()
    from elasticsearch import Elasticsearch
    from cloud_soc.portal.app import settings_from_environment
    settings = settings_from_environment()
    auth = ({'api_key': settings['PORTAL_READ_API_KEY']} if settings.get('PORTAL_READ_API_KEY')
            else {'basic_auth': ('cloud_soc_agent_monitor', settings['MONITOR_PASSWORD'])})
    client = Elasticsearch(settings['ES_URL'], ca_certs=settings['CA_FILE'],
                           request_timeout=30, max_retries=0, **auth)
    with client:
        result = review(client, Path(settings['STATE_DIR']) / DATABASE,
                        actor=args.actor, apply=args.apply, max_records=args.max_records)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
