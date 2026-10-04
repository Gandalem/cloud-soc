"""Append-only runs and idempotent exclusions, containing references rather than payloads."""
from copy import deepcopy
import json
from elasticsearch import ConflictError
from cloud_soc.detection.engine import condition_matches, event_fingerprint, get_field_value, parse_event_timestamp, rule_revision, rule_engine_version

RUNS = 'soc-detection-runs-v1'
EXCLUSIONS = 'soc-detection-exclusions-v1'


def evaluate(event, rule):
    missing = []
    mismatch = False
    for condition in rule['conditions']:
        actual = get_field_value(event, condition['field'])
        if actual is None and condition['operator'] != 'exists':
            missing.append(condition['field'])
        elif not condition_matches(event, condition):
            mismatch = True
    if mismatch:
        return 'not_matched', []
    return ('unknown', missing) if missing else ('matched', [])


def create_record(client, index, identifier, document):
    try:
        response = client.create(index=index, id=identifier, document=document, refresh=False)
        if response['result'] != 'created':
            raise RuntimeError('unexpected_telemetry_write')
    except ConflictError:
        # Exclusion identities are deterministic across checkpoint retries.
        return


def exclusion(client, event, rule, reason, missing, stamp, run_id):
    meta = event.get('_cloud_soc_meta', {})
    raw = get_field_value(event, 'cloud_soc.provenance.raw')
    normalized = {'index': meta.get('index'), 'id': meta.get('document_id')}
    version = rule_revision(rule)
    identifier = event_fingerprint({'rule': version, 'normalized': normalized, 'reason': reason, 'missing': missing})
    try:
        occurred = parse_event_timestamp(event).isoformat()
    except (ValueError, TypeError):
        occurred = None
    document = {'@timestamp': stamp, 'record_id': identifier, 'run_id': run_id, 'rule': {'id': rule['id'], 'version': version},
                'reason': reason, 'missing_fields': missing, 'normalized': normalized, 'raw': deepcopy(raw),
                'event_time': occurred, 'event_hash': event_fingerprint(event)}
    create_record(client, EXCLUSIONS, identifier, document)


def stats_for(rules):
    return {rule['id']: {'input_events': 0, 'matched': 0, 'not_matched': 0, 'unknown': 0,
                         'excluded': 0, 'late': 0, 'alerts_created': 0, 'alerts_existing': 0}
            for rule in rules}


def run_records(rules, stats, *, run_id, stamp, start, end, state, error=None):
    for rule in rules:
        identifier = run_id + ':' + rule['id'] + ':' + state
        document = {'@timestamp': stamp, 'record_id': identifier, 'run_id': run_id, 'rule': {'id': rule['id'], 'version': rule_revision(rule)},
                    'engine_version': rule_engine_version(rule), 'rule_snapshot': deepcopy(rule),
                    'state': state, 'range_start': start, 'range_end': end,
                    'counts': deepcopy(stats[rule['id']]), 'error': error}
        yield identifier, document


def runs(client, rules, stats, **options):
    for identifier, document in run_records(rules, stats, **options):
        create_record(client, RUNS, identifier, document)


def queue_committed_runs(db, rules, stats, **options):
    for identifier, document in run_records(rules, stats, state='committed', **options):
        db.execute('INSERT OR IGNORE INTO telemetry_outbox VALUES(?,?)', (identifier, json.dumps(document)))


def flush_outbox(client, db):
    for identifier, body in db.execute('SELECT id,body FROM telemetry_outbox').fetchall():
        create_record(client, RUNS, identifier, json.loads(body))
        db.execute('DELETE FROM telemetry_outbox WHERE id=?', (identifier,))
