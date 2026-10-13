"""Optional AUTH-001 notices: independent receipt scan, durable intent, immutable revisions.

Final alerts and their 900-second frontier remain owned by incremental.py.
This sidecar never advances that checkpoint or writes an original/normalized event.
"""
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat

from elasticsearch import ConflictError
from cloud_soc.detection import staging
from cloud_soc.detection.engine import (detect_rule, event_evidence, event_fingerprint,
    parse_event_timestamp, rule_revision)
from cloud_soc.detection.telemetry import evaluate
from cloud_soc.processing.contract import NORMALIZED

NOTICES = 'soc-alert-notices-v1'
MAPPING = {'dynamic': 'strict', '_meta': {'contract': NOTICES}, 'properties': {
    '@timestamp': {'type': 'date'}, 'organization': {'properties': {'id': {'type': 'keyword'}}},
    'notice': {'properties': {'id': {'type': 'keyword'}, 'revision': {'type': 'long'}, 'state': {'type': 'keyword'}, 'initial_at': {'type': 'date'}}},
    'body': {'type': 'object', 'enabled': False}}}
OPEN = {'initial', 'verifying', 'delayed'}
STATES = OPEN | {'confirmed', 'corrected'}


def utc(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else value
    if not isinstance(stamp, datetime) or stamp.tzinfo is None:
        raise ValueError('early_time_requires_timezone')
    return stamp.astimezone(timezone.utc)


def location(path):
    return Path(str(path) + '.early.sqlite')


def connection(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('unsafe_early_state')
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except FileExistsError:
        info = path.stat()
        if (not path.is_file() or info.st_nlink != 1 or getattr(info, 'st_file_attributes', 0) & 0x400
                or os.name != 'nt' and stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError('early_state_must_be_private_regular_file')
    db = sqlite3.connect(path, timeout=0)
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        for name in ('early_runtime', 'early_events', 'early_notices', 'early_outbox'):
            # Identifiers are code-owned constants, never configuration or telemetry.
            db.execute(f'CREATE TABLE IF NOT EXISTS {name} (id TEXT PRIMARY KEY, body TEXT NOT NULL)')  # nosec B608
        return db
    except Exception:
        db.close()
        raise


def prepared(client):
    found = client.indices.get_mapping(index=NOTICES)
    if set(found) != {NOTICES} or found[NOTICES]['mappings'] != MAPPING:
        raise ValueError('early_notice_mapping_requires_explicit_setup')


def emit(db, body, state, *, final_id=None, reason=None):
    if state not in STATES:
        raise ValueError('invalid_notice_state')
    if body.get('state') == state and body.get('final_alert_id') == final_id:
        return
    stamp = datetime.now(timezone.utc).isoformat()
    body.update(state=state, revision=body.get('revision', 0) + 1, updated_at=stamp,
                final_alert_id=final_id, reason=reason)
    if state == 'confirmed':
        body['final_at'] = stamp
    document = {'@timestamp': stamp, 'organization': {'id': body['organization']},
                'notice': {'id': body['id'], 'revision': body['revision'], 'state': state, 'initial_at': body['initial_at']}, 'body': deepcopy(body)}
    key = body['id'] + ':' + str(body['revision'])
    db.execute('INSERT OR REPLACE INTO early_notices VALUES(?,?)', (body['id'], json.dumps(body)))
    db.execute('INSERT INTO early_outbox VALUES(?,?)', (key, json.dumps(document)))


def flush(client, path):
    delivered = 0
    with closing(connection(path)) as db:
        db.execute('BEGIN IMMEDIATE')
        for key, encoded in db.execute('SELECT id,body FROM early_outbox ORDER BY rowid LIMIT 100').fetchall():
            document = json.loads(encoded)
            try:
                result = client.create(index=NOTICES, id=key, document=document, refresh='wait_for')
                if result.get('result') != 'created':
                    raise RuntimeError('unexpected_notice_write')
            except ConflictError:
                existing = client.get(index=NOTICES, id=key)['_source']
                if event_fingerprint(existing) != event_fingerprint(document):
                    raise ValueError('immutable_notice_conflict')
            db.execute('DELETE FROM early_outbox WHERE id=?', (key,))
            delivered += 1
        pending = db.execute('SELECT count(*) FROM early_outbox').fetchone()[0]
        db.commit()
    return {'early_delivered': delivered, 'early_delivery_pending': pending}


def related(body, match):
    # This is a rule/cooldown episode, never a claim of same SSH session or attacker.
    return (body['group'] == match['group'] and body['rule_version'] == match['rule_version']
            and abs((utc(body['window_end']) - utc(match['window_end'])).total_seconds()) < 300
            and utc(body['window_start']) <= utc(match['window_end'])
            and utc(match['window_start']) <= utc(body['window_end']))


def proposals(events, rule):
    # Reuse the AUTH engine and mirror contract, but bound provisional windows.
    # A positive notice needs ten valid observations, not an exhaustive final count.
    runtime = {}
    ordered = sorted(events, key=lambda event: (parse_event_timestamp(event), event_fingerprint(event)))
    unique, sources = [], set()
    for event in ordered:
        source = event_fingerprint({'organization': event['organization']['id'],
                                    'raw': event['cloud_soc']['provenance']['raw']})
        if source not in sources:
            sources.add(source)
            unique.append(event)
    ordered = unique
    for offset in range(0, len(ordered), 24):
        yield from detect_rule(ordered[offset:offset + 24], rule, runtime=runtime)
        for group in runtime.values():
            group['window'] = group['window'][-24:]


def run(client, *, path, rule, identity, start, now, frontier, budget=20000, capacity=20000, scanner=None):
    """Current receipt tail has no 30-second final-scan grace or lateness wait."""
    prepared(client)
    path, start, now, frontier = Path(path), utc(start), utc(now), utc(frontier)
    with closing(connection(path)) as db:
        db.execute('BEGIN IMMEDIATE')
        saved = db.execute("SELECT body FROM early_runtime WHERE id='state'").fetchone()
        state = json.loads(saved[0]) if saved else {'identity': identity,
            'begin': max(start, now - timedelta(minutes=5)).isoformat(),
            'checkpoint': max(start, now - timedelta(minutes=5)).isoformat(), 'cursor': 0}
        if state['identity'] != identity or utc(state['checkpoint']) > now:
            raise ValueError('early_scope_changed_or_clock_regression')
        lower = max(utc(state['begin']), utc(state['checkpoint']) - timedelta(minutes=15))
        scan = staging.prepare(db, identity, state['checkpoint'], lower.isoformat(), now.isoformat())
        if utc(scan['end']) > utc(scan['lower']):
            complete = staging.read_window(client, db, scan, budget=budget, seen={}, scanner=scanner)
        else:
            complete = True
        # Process only newly staged rows, including partial scans, without advancing final time.
        for rowid, encoded in db.execute('SELECT rowid,body FROM input_hits WHERE rowid>? ORDER BY rowid', (state['cursor'],)):
            state['cursor'] = rowid
            hit = json.loads(encoded)
            event = deepcopy(hit['_source'])
            event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': hit['_id']}
            if not event_evidence(event)['complete']:
                raise ValueError('early_incomplete_evidence')
            if evaluate(event, rule)[0] != 'matched':
                continue
            stamp = parse_event_timestamp(event)
            if stamp < frontier or stamp > now:
                continue
            old = db.execute('SELECT body FROM early_events WHERE id=?', (hit['_id'],)).fetchone()
            if old and event_fingerprint(json.loads(old[0])) != event_fingerprint(event):
                raise ValueError('early_normalized_document_changed')
            db.execute('INSERT OR IGNORE INTO early_events VALUES(?,?)', (hit['_id'], json.dumps(event)))
        events = []
        cutoff = max(frontier - timedelta(seconds=300), now - timedelta(seconds=1800))
        for key, encoded in db.execute('SELECT id,body FROM early_events').fetchall():
            event = json.loads(encoded)
            if parse_event_timestamp(event) < cutoff:
                db.execute('DELETE FROM early_events WHERE id=?', (key,))
            else:
                events.append(event)
        if len(events) > capacity:
            raise ValueError('early_active_capacity')
        notices = [json.loads(row[0]) for row in db.execute('SELECT body FROM early_notices')]
        initial = 0
        for match in proposals(events, rule):
            if utc(match['window_end']) < frontier or any(related(body, match) for body in notices):
                continue
            if len(notices) >= 10000:
                raise ValueError('early_notice_capacity_requires_review')
            identifier = event_fingerprint({'source': identity, 'rule': rule_revision(rule),
                                           'group': match['group'], 'anchor': match['window_end']})
            proof = match['evidence'][:10]
            proof_ids = {item['normalized']['id'] for item in proof}
            selected = [event for event in events if event['_cloud_soc_meta']['document_id'] in proof_ids]
            generated = datetime.now(timezone.utc)
            normalized = max(utc(event['cloud_soc']['normalized_at']) for event in selected)
            elapsed = (generated - normalized).total_seconds()
            body = {'id': identifier, 'state': None, 'revision': 0, 'organization': match['organization_id'],
                'rule_id': 'AUTH-001', 'rule_version': match['rule_version'], 'severity': 'high',
                'title': 'SSH 무차별 대입 공격 의심', 'group': match['group'],
                'source_ip': match['group']['source.ip'], 'window_start': match['window_start'],
                'window_end': match['window_end'], 'observed_count': len(proof), 'threshold': 10,
                'window_seconds': 300, 'evidence': proof, 'initial_at': generated.isoformat(),
                'first_received_at': min(utc(event['event']['ingested']) for event in selected).isoformat(),
                'normalized_at': normalized.isoformat(), 'search_observed_at': now.isoformat(),
                'normalization_to_initial_seconds': elapsed if elapsed >= 0 else None,
                'final_at': None, 'final_alert_id': None, 'attack_success': 'not_established'}
            emit(db, body, 'initial')
            emit(db, body, 'verifying')
            notices.append(body)
            initial += 1
        if complete:
            state.update(checkpoint=scan['end'], cursor=0)
            staging.clear(db)
        db.execute('INSERT OR REPLACE INTO early_runtime VALUES(?,?)', ('state', json.dumps(state)))
        db.commit()
    result = {'early_initials': initial, 'early_scan_pending': int(not complete)}
    try:
        result.update(flush(client, path))
    except Exception:
        result['early_delivery_pending'] = 1
    return result


def queue_final(db, detections, frontier):
    db.execute('CREATE TABLE IF NOT EXISTS early_final_outbox (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
    count = db.execute("SELECT count(*) FROM early_final_outbox WHERE id NOT IN ('frontier','overflow')").fetchone()[0]
    complete = True
    for match, identifier in detections:
        if match['rule_id'] == 'AUTH-001':
            if db.execute('SELECT 1 FROM early_final_outbox WHERE id=?', (identifier,)).fetchone():
                continue
            if count >= 1000:
                complete = False
                # Preserve a durable gap marker, never silently correct a notice
                # when its final link could have been omitted. Final detection continues.
                db.execute('INSERT OR REPLACE INTO early_final_outbox VALUES(?,?)', ('overflow', json.dumps('final_link_intent_capacity_requires_review')))
                continue
            summary = {key: match[key] for key in ('group', 'rule_version', 'window_start', 'window_end', 'event_count')}
            db.execute('INSERT OR IGNORE INTO early_final_outbox VALUES(?,?)', (identifier, json.dumps(summary)))
            count += 1
    db.execute('INSERT OR REPLACE INTO early_final_outbox VALUES(?,?)', ('frontier', json.dumps(frontier)))
    return complete


def finalize(client, *, final_db, path, commit_final=True):
    queued = final_db.execute('SELECT id,body FROM early_final_outbox').fetchall()
    matches = [(identifier, json.loads(encoded)) for identifier, encoded in queued if identifier not in ('frontier', 'overflow')]
    overflow = any(identifier == 'overflow' for identifier, _ in queued)
    frontier = next((utc(json.loads(encoded)) for identifier, encoded in queued if identifier == 'frontier'), None)
    with closing(connection(path)) as db:
        db.execute('BEGIN IMMEDIATE')
        for encoded, in db.execute('SELECT body FROM early_notices').fetchall():
            body = json.loads(encoded)
            if body['state'] not in OPEN:
                continue
            found = next(((key, match) for key, match in matches if related(body, match)), None)
            if found:
                body['final_observed_count'] = found[1]['event_count']
                emit(db, body, 'confirmed', final_id=found[0], reason='immutable_final_alert_linked')
            elif overflow:
                emit(db, body, 'delayed', reason='final_link_intent_capacity_requires_manual_reconciliation')
            elif frontier and frontier > utc(body['window_end']) + timedelta(milliseconds=5):
                emit(db, body, 'corrected', reason='no_final_match_or_final_suppression; not_a_benign_verdict')
        db.commit()
    # Only remove durable final intents after the sidecar transition commits.
    final_db.execute("DELETE FROM early_final_outbox WHERE id!='overflow'")
    if commit_final:
        final_db.commit()
    return {**flush(client, path), 'early_final_reconcile_required': int(overflow)}


def delayed(client, path):
    if not Path(path).exists():
        return
    with closing(connection(path)) as db:
        db.execute('BEGIN IMMEDIATE')
        for encoded, in db.execute('SELECT body FROM early_notices').fetchall():
            body = json.loads(encoded)
            if body['state'] in OPEN:
                emit(db, body, 'delayed', reason='final_processing_or_notice_delivery_unavailable')
        db.commit()
    flush(client, path)
