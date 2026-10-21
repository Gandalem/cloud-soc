"""Bounded historical-context review of late normalized events in independent state."""
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import math
import os
from pathlib import Path
import sqlite3
import stat

from cloud_soc.detection import staging
from cloud_soc.detection.engine import (build_group_key, detect_rule, event_evidence,
    event_fingerprint, get_field_value, parse_event_timestamp, rule_revision)
from cloud_soc.detection.incremental import utc
from cloud_soc.detection.telemetry import evaluate, runtime_manifest
from cloud_soc.detection.worker import approved_rules, ALERTS
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping, save_security_alert
from cloud_soc.main import build_security_alert, make_alert_id
from cloud_soc.processing.contract import NORMALIZED, STATUS

INDEXED_GROUP_FIELDS = frozenset(('organization.id', 'source.ip', 'destination.ip',
    'host.id', 'user.name', 'user.id', 'cloud.account.id'))


def context(client, rule, job, *, limit):
    filters = [{'range': {'@timestamp': {'gte': job['lower'], 'lt': job['upper']}}}]
    filters += [{'term': {field: value}} for field, value in job['fields'].items()
                if field in INDEXED_GROUP_FIELDS]
    return fetch_all_hits(client, index=NORMALIZED, page_size=500, max_documents=limit,
                          query={'bool': {'filter': filters}})


def run_retrospective(client, *, state_path, start, now=None, source_id='local',
                      lateness_seconds=900, max_documents=20000, max_context_documents=10000,
                      max_context_windows=20, scanner=None, context_scanner=None, **selection):
    """Receipt discovery commits only with durable pending review jobs.

    Each complete context includes neighbouring event-time buckets. Late arrival
    order does not rewind a live frontier or reuse a live cooldown/database.
    Create-only IDs are identical to the ordinary engine for identical evidence.
    """
    now, initial = utc(now or datetime.now(timezone.utc)), utc(start)
    if (initial > now or type(lateness_seconds) is not int or not 60 <= lateness_seconds <= 86400
            or type(max_documents) is not int or not 1 <= max_documents <= 100000
            or type(max_context_documents) is not int or not 1 <= max_context_documents <= 100000
            or type(max_context_windows) is not int or not 1 <= max_context_windows <= 100):
        raise ValueError('invalid_retrospective_options')
    rules = approved_rules(**selection)
    by_id = {r['id']: r for r in rules}
    identity = event_fingerprint({'contract': 'retrospective-v1', 'rules': rules,
        'versions': [rule_revision(r) for r in rules], 'start': initial.isoformat(),
        'source': source_id, 'lateness': lateness_seconds, 'index': NORMALIZED})
    path = Path(state_path)
    if path.is_symlink():
        raise ValueError('unsafe_state_path')
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError:
        if not path.is_file() or os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError('state_file_must_be_private_and_regular')
    client = client.options(request_timeout=15, max_retries=0)
    with closing(sqlite3.connect(path, timeout=0)) as db:
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name IN ('runtime','state','early_identity')").fetchone():
            raise ValueError('retrospective_requires_independent_state')
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS review_state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS review_jobs (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS review_seen (id TEXT PRIMARY KEY, received TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS review_alerts (id TEXT PRIMARY KEY, rule TEXT NOT NULL, '
                   'group_key TEXT NOT NULL, occurred REAL NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS review_alert_group ON review_alerts(rule, group_key, occurred)')
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT body FROM review_state WHERE id=1').fetchone()
        saved = json.loads(row[0]) if row else {'identity': identity, 'checkpoint': initial.isoformat(),
            'last_success': None, 'reviewed_total': 0, 'excluded_total': 0}
        if saved['identity'] != identity:
            raise ValueError('retrospective_scope_changed_requires_new_state')
        current = deepcopy(saved)
        checkpoint = utc(saved['checkpoint'])
        if checkpoint > now:
            raise ValueError('clock_regression')
        lower = max(initial, checkpoint - timedelta(minutes=15))
        end = min(now - timedelta(seconds=30), checkpoint + timedelta(minutes=5))
        counts = {'events': 0, 'late_events': 0, 'excluded': 0, 'contexts_reviewed': 0,
                  'created': 0, 'existing': 0, 'cooldown_suppressed': 0}
        meta = None

        def publish(state, error=None):
            pending = db.execute('SELECT count(*) FROM review_jobs').fetchone()[0]
            client.index(index=STATUS, id='detector-retrospective', document={
                'runtime': runtime_manifest(rules, 'retrospective'),
                '@timestamp': now.isoformat(), 'state': state, 'mode': 'retrospective',
                'detection': ','.join(by_id), 'checkpoint': current['checkpoint'],
                'last_success': current['last_success'], 'counts': counts, 'pending_contexts': pending,
                'excluded_total': current['excluded_total'],
                'health': 'failed' if state == 'failed' else 'warning' if pending or current['excluded_total'] else 'healthy',
                'error': error, 'assessment': {'state': 'evaluated' if counts['contexts_reviewed'] else 'unverified',
                                             'reason': 'historical_context' if counts['contexts_reviewed'] else 'no_late_context_reviewed'}})
        try:
            if set(client.indices.get_mapping(index=ALERTS)) != {ALERTS}:
                raise ValueError('unexpected_alert_scope')
            ensure_provenance_mapping(client, ALERTS)
            resolved = client.indices.resolve_index(name=NORMALIZED)
            if resolved.get('aliases') or resolved.get('data_streams') or [r['name'] for r in resolved.get('indices', [])] != [NORMALIZED]:
                raise ValueError('unexpected_normalized_scope')
            caps = client.field_caps(index=NORMALIZED, fields=['cloud_soc.normalized_at'])['fields'].get('cloud_soc.normalized_at', {})
            if set(caps) != {'date'}:
                raise ValueError('normalization_time_mapping_required')
            publish('running')
            if end > checkpoint:
                seen = {r[0]: r[1] for r in db.execute('SELECT id,received FROM review_seen')}
                meta = staging.prepare(db, identity, checkpoint.isoformat(), lower.isoformat(), end.isoformat())
                if not staging.read_window(client, db, meta, budget=max_documents, seen=seen, scanner=scanner):
                    publish('running', 'input_scan_pending')
                    db.commit()
                    return counts
                for hit in staging.staged_hits(db):
                    event = deepcopy(hit['_source'])
                    event['_cloud_soc_meta'] = {'index': hit['_index'], 'document_id': hit['_id']}
                    if not event_evidence(event)['complete']:
                        raise ValueError('incomplete_provenance')
                    if hit['_id'] in seen:
                        continue
                    received = utc(event['cloud_soc']['normalized_at'])
                    db.execute('INSERT OR IGNORE INTO review_seen VALUES(?,?)', (hit['_id'], received.isoformat()))
                    counts['events'] += 1
                    try:
                        occurred = parse_event_timestamp(event)
                    except (ValueError, TypeError):
                        counts['excluded'] += 1
                        continue
                    if (received - occurred).total_seconds() <= lateness_seconds:
                        continue
                    counts['late_events'] += 1
                    for rule in rules:
                        outcome, missing = evaluate(event, rule)
                        if outcome in ('unknown', 'excluded'):
                            counts['excluded'] += 1
                            continue
                        fields = list(dict.fromkeys(['organization.id', *rule['group_by']]))
                        group = build_group_key(event, fields)
                        if outcome != 'matched':
                            continue
                        if group is None or any(get_field_value(event, f) in (None, '') for f in fields):
                            counts['excluded'] += 1
                            continue
                        width = rule['time_window']['seconds']
                        bucket = math.floor(occurred.timestamp() / width) * width
                        key = event_fingerprint([rule['id'], group, bucket])
                        previous = db.execute('SELECT body FROM review_jobs WHERE id=?', (key,)).fetchone()
                        job = json.loads(previous[0]) if previous else {
                            'rule': rule['id'], 'group': event_fingerprint(group),
                            'fields': {f: get_field_value(event, f) for f in fields},
                            'lower': datetime.fromtimestamp(bucket-width, timezone.utc).isoformat(),
                            'upper': datetime.fromtimestamp(bucket+2*width, timezone.utc).isoformat(),
                            'triggers': {}}
                        job['triggers'][event_fingerprint(event_evidence(event)['raw'])] = hit['_id']
                        db.execute('INSERT OR REPLACE INTO review_jobs VALUES(?,?)', (key, json.dumps(job)))
                current['checkpoint'] = meta['end']
                current['last_success'] = now.isoformat()
                staging.clear(db)
            if db.execute('SELECT count(*) FROM review_jobs').fetchone()[0] > 100000:
                raise ValueError('retrospective_job_capacity')
            for key, body in db.execute('SELECT id,body FROM review_jobs ORDER BY id LIMIT ?', (max_context_windows,)).fetchall():
                job = json.loads(body)
                rule = by_id[job['rule']]
                hits = (context_scanner(client, rule, job, limit=max_context_documents) if context_scanner else
                        context(client, rule, job, limit=max_context_documents))
                if not isinstance(hits, list) or len(hits) > max_context_documents:
                    raise ValueError('incomplete_historical_context')
                events = []
                present = set()
                for hit in hits:
                    if hit.get('_index') != NORMALIZED or not hit.get('_id'):
                        raise ValueError('invalid_context_reference')
                    event = deepcopy(hit['_source'])
                    event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': hit['_id']}
                    if not event_evidence(event)['complete']:
                        raise ValueError('incomplete_context_provenance')
                    stamp = parse_event_timestamp(event)
                    if not utc(job['lower']) <= stamp < utc(job['upper']):
                        raise ValueError('outside_historical_context')
                    if event_fingerprint(build_group_key(event, list(job['fields']))) != job['group']:
                        continue
                    events.append(event)
                    present.add(hit['_id'])
                if not set(job['triggers'].values()) <= present:
                    raise ValueError('historical_trigger_missing')
                for detection in detect_rule(events, rule):
                    if not any(event_fingerprint(e['raw']) in job['triggers'] for e in detection['evidence']):
                        continue
                    identifier = make_alert_id(detection)
                    occurred = utc(detection['window_end']).timestamp()
                    cooldown = rule.get('cooldown', {}).get('seconds', 0)
                    if cooldown and db.execute(
                            'SELECT 1 FROM review_alerts WHERE rule=? AND group_key=? AND id<>? '
                            'AND occurred>? AND occurred<? LIMIT 1',
                            (rule['id'], job['group'], identifier, occurred-cooldown, occurred+cooldown)).fetchone():
                        counts['cooldown_suppressed'] += 1
                        continue
                    alert = build_security_alert(detection)
                    alert['cloud_soc']['provenance']['review'] = {'mode': 'retrospective', 'reviewed_at': now.isoformat(),
                        'reason': 'late_normalization', 'context_start': job['lower'], 'context_end': job['upper']}
                    result = save_security_alert(client, alert, index_name=ALERTS, document_id=identifier,
                                                 refresh=False, index_prepared=True)
                    if result['result'] not in ('created', 'existing'):
                        raise RuntimeError('unexpected_immutable_result')
                    counts[result['result']] += 1
                    db.execute('INSERT OR IGNORE INTO review_alerts VALUES(?,?,?,?)',
                               (identifier, rule['id'], job['group'], occurred))
                db.execute('DELETE FROM review_jobs WHERE id=?', (key,))
                counts['contexts_reviewed'] += 1
            current['reviewed_total'] += counts['contexts_reviewed']
            current['excluded_total'] += counts['excluded']
            db.execute('DELETE FROM review_seen WHERE received<?', ((utc(current['checkpoint'])-timedelta(minutes=15)).isoformat(),))
            db.execute('INSERT OR REPLACE INTO review_state VALUES(1,?)', (json.dumps(current),))
            publish('success')
            db.commit()
            return counts
        except Exception:
            db.rollback()
            current = saved
            if meta and meta.get('pit'):
                try: client.close_point_in_time(id=meta['pit'])
                except Exception: pass
            try: publish('failed', 'retrospective_cycle_failed')
            except Exception: pass
            raise RuntimeError('retrospective_cycle_failed; checkpoint and pending review retained') from None
