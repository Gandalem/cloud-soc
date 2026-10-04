"""Transactional incremental threshold detection; ES writes precede local commit."""
from copy import deepcopy
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3

from cloud_soc.detection.engine import detect_rule, event_matches_rule, event_fingerprint, parse_event_timestamp, event_evidence, build_group_key
from cloud_soc.detection.worker import approved_rules, ALERTS
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping, save_security_alert
from cloud_soc.main import make_alert_id, build_security_alert
from cloud_soc.processing.contract import NORMALIZED, STATUS


def utc(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else value
    if not isinstance(stamp, datetime) or stamp.tzinfo is None:
        raise ValueError('timezone_required')
    return stamp.astimezone(timezone.utc)


def run_incremental(client, *, state_path, start, now=None, max_documents=20000,
                    lateness_seconds=900, scanner=None, source_id='local', accept_legacy_exclusion=False, include_cloud=False):
    """Late events beyond the finalized frontier are counted, never silently replayed.

    A 15-minute normalization receipt overlap handles bounded refresh/write delays.
    Rule/source identity is pinned; changing it requires a new explicit state file.
    """
    now, start = utc(now or datetime.now(timezone.utc)), utc(start)
    if not 1 <= max_documents <= 100000 or not 60 <= lateness_seconds <= 86400 or start > now:
        raise ValueError('invalid_incremental_options')
    path = Path(state_path)
    if path.is_symlink():
        raise ValueError('unsafe_state_path')
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(descriptor)
    except FileExistsError:
        pass
    rules = approved_rules(include_cloud=include_cloud)
    identity = event_fingerprint({'rules': rules, 'start': start.isoformat(), 'lateness': lateness_seconds,
                                  'index': NORMALIZED, 'source': source_id, 'legacy_exclusion': accept_legacy_exclusion})
    with closing(sqlite3.connect(path, timeout=0)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS runtime (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT body FROM runtime WHERE id=1').fetchone()
        saved = json.loads(row[0]) if row else {'identity': identity, 'checkpoint': start.isoformat(),
            'frontier': (start - timedelta(seconds=lateness_seconds)).isoformat(),
            'pending': {}, 'seen': {}, 'groups': {}, 'last_success': None, 'late_total': 0}
        if saved['identity'] != identity:
            raise ValueError('rule_or_scope_changed_requires_new_state')
        state = deepcopy(saved)
        checkpoint = utc(state['checkpoint'])
        if checkpoint > now:
            raise ValueError('clock_regression')
        end = min(now - timedelta(seconds=30), checkpoint + timedelta(minutes=5))
        lower = max(start, checkpoint - timedelta(minutes=15))
        counts = {'events': 0, 'created': 0, 'existing': 0, 'late': 0}

        def publish(kind, error=None):
            health = 'failed' if kind == 'failed' else 'delayed' if (now - utc(state['checkpoint'])).total_seconds() > 1200 else 'warning' if state['late_total'] or state.get('legacy_excluded') else 'healthy'
            client.index(index=STATUS, id='detector', document={'@timestamp': now.isoformat(),
                'state': kind, 'detection': ','.join(rule['id'] for rule in rules), 'checkpoint': state['checkpoint'],
                'last_success': state['last_success'], 'error': error,
                'health': health, 'legacy_excluded': state.get('legacy_excluded', 0),
                'lag_seconds': max(0, int((now - utc(state['checkpoint'])).total_seconds())),
                'late_total': state['late_total'], 'counts': counts}, refresh=False)

        try:
            publish('running')
            if end <= checkpoint:
                publish('waiting')
                db.rollback()
                return counts
            resolved = client.indices.resolve_index(name=NORMALIZED)
            if resolved.get('aliases') or resolved.get('data_streams') or [r['name'] for r in resolved.get('indices', [])] != [NORMALIZED]:
                raise ValueError('unexpected_normalized_index')
            caps = client.field_caps(index=NORMALIZED, fields=['cloud_soc.normalized_at'])['fields'].get('cloud_soc.normalized_at', {})
            if set(caps) != {'date'}:
                raise ValueError('normalization_time_mapping_required')
            if not row:
                legacy = client.count(index=NORMALIZED, query={'bool': {'must_not': [{'exists': {'field': 'cloud_soc.normalized_at'}}]}})
                if legacy.get('_shards', {}).get('failed', 0) or type(legacy.get('count')) is not int:
                    raise ValueError('legacy_scope_check_failed')
                if legacy['count'] and not accept_legacy_exclusion:
                    raise ValueError('legacy_missing_normalization_time_requires_explicit_exclusion')
                state['legacy_excluded'] = legacy['count']
            ensure_provenance_mapping(client, ALERTS)
            query = {'range': {'cloud_soc.normalized_at': {'gte': lower.isoformat(), 'lt': end.isoformat()}}}
            hits = (scanner or fetch_all_hits)(client, index=NORMALIZED, page_size=500,
                                               max_documents=max_documents, query=query)
            if len(hits) > max_documents:
                raise ValueError('batch_limit')
            frontier = utc(state['frontier'])
            for hit in hits:
                if hit.get('_index') != NORMALIZED or not hit.get('_id'):
                    raise ValueError('invalid_reference')
                event = deepcopy(hit['_source'])
                received = utc(event['cloud_soc']['normalized_at'])
                if not lower <= received < end:
                    raise ValueError('outside_receipt_range')
                key = hit['_id']
                if key in state['seen']:
                    continue
                stamp = parse_event_timestamp(event)
                event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
                if not event_evidence(event)['complete']:
                    raise ValueError('incomplete_evidence')
                state['seen'][key] = received.isoformat()
                counts['events'] += 1
                matched_rules = [rule for rule in rules if event_matches_rule(event, rule)]
                if not matched_rules:
                    continue
                organization = event.get('organization', {}).get('id')
                if not isinstance(organization, str) or not organization.strip():
                    raise ValueError('missing_organization')
                for rule in matched_rules:
                    if build_group_key(event, list(dict.fromkeys(['organization.id', *rule['group_by']]))) is None:
                        raise ValueError('missing_detection_group')
                if stamp < frontier:
                    counts['late'] += 1
                    state['late_total'] += 1
                    continue
                if stamp > now + timedelta(minutes=5):
                    raise ValueError('future_event_clock')
                state['pending'][key] = event
            final = max(frontier, end - timedelta(seconds=lateness_seconds))
            ready = [e for e in state['pending'].values() if parse_event_timestamp(e) < final]
            # Stateful engine preserves the same event ordering and cooldown as batch detection.
            extra_groups = state.setdefault('rule_groups', {})
            runtimes = {rule['id']: state['groups'] if i == 0 else extra_groups.setdefault(rule['id'], {})
                        for i, rule in enumerate(rules) if rule.get('type', 'threshold') == 'threshold'}
            detections = [detection for rule in rules for detection in
                          detect_rule(ready, rule, runtime=runtimes.get(rule['id']))]
            for detection in detections:
                result = save_security_alert(client, build_security_alert(detection), index_name=ALERTS,
                    document_id=make_alert_id(detection), refresh=False, index_prepared=True)
                if result['result'] not in ('created', 'existing'):
                    raise RuntimeError('unexpected_alert_write')
                counts[result['result']] += 1
            state['pending'] = {k: e for k, e in state['pending'].items() if parse_event_timestamp(e) >= final}
            for rule in rules:
                groups = runtimes.get(rule['id'], {})
                window = timedelta(seconds=rule['time_window']['seconds'])
                cooldown = timedelta(seconds=rule.get('cooldown', {}).get('seconds', 0))
                for key, group in list(groups.items()):
                    group['window'] = [e for e in group['window'] if parse_event_timestamp(e) >= final - window]
                    if not group['window'] and (not group['last_alert'] or utc(group['last_alert']) < final - cooldown):
                        del groups[key]
            state['seen'] = {k: t for k, t in state['seen'].items() if utc(t) >= end - timedelta(minutes=15)}
            if len(state['pending']) + sum(len(g['window']) for groups in runtimes.values() for g in groups.values()) > max_documents:
                raise ValueError('active_state_limit')
            state.update(checkpoint=end.isoformat(), frontier=final.isoformat(), last_success=now.isoformat())
            # Publish before commit: a status/write failure must not advance the checkpoint.
            publish('success')
            db.execute('INSERT OR REPLACE INTO runtime VALUES(1,?)', (json.dumps(state),))
            db.commit()
            return counts
        except Exception:
            db.rollback()
            state = saved
            try:
                publish('failed', 'incremental_cycle_failed')
            except Exception:
                pass
            raise RuntimeError('incremental_cycle_failed; checkpoint retained') from None
