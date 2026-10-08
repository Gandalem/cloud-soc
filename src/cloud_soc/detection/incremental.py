"""Transactional incremental threshold detection; ES writes precede local commit."""
from copy import deepcopy
from contextlib import closing
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
from uuid import uuid4

from cloud_soc.detection.engine import detect_rule, event_fingerprint, parse_event_timestamp, event_evidence, build_group_key, get_field_value, rule_revision
from cloud_soc.detection.worker import approved_rules, ALERTS
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping, save_security_alert
from cloud_soc.main import make_alert_id, build_security_alert
from cloud_soc.processing.contract import NORMALIZED, STATUS
from cloud_soc.detection.telemetry import evaluate, exclusion, stats_for, runs, queue_committed_runs, flush_outbox


def utc(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00')) if isinstance(value, str) else value
    if not isinstance(stamp, datetime) or stamp.tzinfo is None:
        raise ValueError('timezone_required')
    return stamp.astimezone(timezone.utc)


def run_incremental(client, *, state_path, start, now=None, max_documents=20000,
                    lateness_seconds=900, scanner=None, source_id='local', accept_legacy_exclusion=False, include_cloud=False, include_sequence=False):
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
    rules = approved_rules(include_cloud=include_cloud, include_sequence=include_sequence)
    identity = event_fingerprint({'rules': rules, 'start': start.isoformat(), 'lateness': lateness_seconds,
                                  'index': NORMALIZED, 'source': source_id, 'legacy_exclusion': accept_legacy_exclusion,
                                  'runtime_contract': 2, 'rule_versions': [rule_revision(rule) for rule in rules]})
    with closing(sqlite3.connect(path, timeout=0)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS runtime (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS telemetry_outbox (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
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
        rule_stats = stats_for(rules)
        run_id = str(uuid4())

        def publish(kind, error=None):
            history_pending = db.execute('SELECT count(*) FROM telemetry_outbox').fetchone()[0]
            health = 'failed' if kind == 'failed' else 'delayed' if (now - utc(state['checkpoint'])).total_seconds() > 1200 else 'warning' if history_pending or state.get('excluded_total') or state['late_total'] or state.get('legacy_excluded') else 'healthy'
            client.index(index=STATUS, id='detector', document={'@timestamp': now.isoformat(),
                'state': kind, 'detection': ','.join(rule['id'] for rule in rules), 'checkpoint': state['checkpoint'],
                'last_success': state['last_success'], 'error': error,
                'health': health, 'legacy_excluded': state.get('legacy_excluded', 0),
                'lag_seconds': max(0, int((now - utc(state['checkpoint'])).total_seconds())),
                'late_total': state['late_total'], 'excluded_total': state.get('excluded_total', 0),
                'history_pending': history_pending, 'counts': counts}, refresh=False)

        try:
            publish('running')
            flush_outbox(client, db)
            if end <= checkpoint:
                runs(client, rules, rule_stats, run_id=run_id, stamp=now.isoformat(), start=lower.isoformat(),
                     end=checkpoint.isoformat(), state='waiting')
                publish('waiting')
                db.commit()
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
                event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
                if not event_evidence(event)['complete']:
                    raise ValueError('incomplete_evidence')
                state['seen'][key] = received.isoformat()
                counts['events'] += 1
                try:
                    stamp = parse_event_timestamp(event)
                    time_reason = ('late_event' if stamp < frontier else
                                   'future_event_clock' if stamp > now + timedelta(minutes=5) else None)
                except (ValueError, TypeError):
                    time_reason = 'invalid_event_time'
                eligible = False
                late = False
                for rule in rules:
                    metrics = rule_stats[rule['id']]
                    metrics['input_events'] += 1
                    outcome, missing = evaluate(event, rule)
                    metrics[outcome] += 1
                    if outcome == 'not_matched':
                        continue
                    group_fields = list(dict.fromkeys(['organization.id', *rule['group_by']]))
                    group_missing = [f for f in group_fields if get_field_value(event, f) in (None, '')]
                    organization = event.get('organization', {}).get('id')
                    reason = ('missing_condition_fields' if outcome == 'unknown' else
                              'missing_group_fields' if group_missing or not isinstance(organization, str) or not organization.strip() or build_group_key(event, group_fields) is None else time_reason)
                    if reason:
                        metrics['excluded'] += 1
                        if reason == 'late_event':
                            metrics['late'] += 1
                            late = True
                        exclusion(client, event, rule, reason, missing or group_missing, now.isoformat(), run_id)
                    else:
                        eligible = True
                if late:
                    counts['late'] += 1
                    state['late_total'] += 1
                if eligible:
                    state['pending'][key] = event
            final = max(frontier, end - timedelta(seconds=lateness_seconds))
            ready = [e for e in state['pending'].values() if parse_event_timestamp(e) < final]
            # Stateful engine preserves the same event ordering and cooldown as batch detection.
            extra_groups = state.setdefault('rule_groups', {})
            runtimes = {rule['id']: state['groups'] if i == 0 else extra_groups.setdefault(rule['id'], {})
                        for i, rule in enumerate(rules) if rule.get('type', 'threshold') in ('threshold', 'sequence')}
            detections = []
            for rule in rules:
                eligible_ready = [e for e in ready if evaluate(e, rule)[0] == 'matched' and
                                  build_group_key(e, list(dict.fromkeys(['organization.id', *rule['group_by']]))) is not None and
                                  all(get_field_value(e, f) not in (None, '') for f in ['organization.id', *rule['group_by']]) and
                                  isinstance(get_field_value(e, 'organization.id'), str) and get_field_value(e, 'organization.id').strip()]
                rule_stats[rule['id']]['evaluated_events'] = len(eligible_ready)
                found = detect_rule(eligible_ready, rule, runtime=runtimes.get(rule['id']))
                rule_stats[rule['id']]['detection_matches'] = len(found)
                detections.extend(found)
            for detection in detections:
                result = save_security_alert(client, build_security_alert(detection), index_name=ALERTS,
                    document_id=make_alert_id(detection), refresh=False, index_prepared=True)
                if result['result'] not in ('created', 'existing'):
                    raise RuntimeError('unexpected_alert_write')
                counts[result['result']] += 1
                rule_stats[detection['rule_id']]['alerts_' + result['result']] += 1
            state['pending'] = {k: e for k, e in state['pending'].items() if parse_event_timestamp(e) >= final}
            for rule in rules:
                groups = runtimes.get(rule['id'], {})
                window = timedelta(seconds=rule['time_window']['seconds'])
                cooldown = timedelta(seconds=rule.get('cooldown', {}).get('seconds', 0))
                for key, group in list(groups.items()):
                    slot = 'failures' if rule.get('type') == 'sequence' else 'window'
                    group[slot] = [e for e in group[slot] if parse_event_timestamp(e) >= final - window]
                    if not group[slot] and (not group.get('last_alert') or utc(group['last_alert']) < final - cooldown):
                        del groups[key]
            state['seen'] = {k: t for k, t in state['seen'].items() if utc(t) >= end - timedelta(minutes=15)}
            if len(state['pending']) + sum(len(g.get('window', g.get('failures', []))) for groups in runtimes.values() for g in groups.values()) > max_documents:
                raise ValueError('active_state_limit')
            state.update(checkpoint=end.isoformat(), frontier=final.isoformat(), last_success=now.isoformat())
            state['excluded_total'] = state.get('excluded_total', 0) + sum(c['excluded'] for c in rule_stats.values())
            runs(client, rules, rule_stats, run_id=run_id, stamp=now.isoformat(), start=lower.isoformat(),
                 end=end.isoformat(), state='evaluated')
            # Publish before commit: a status/write failure must not advance the checkpoint.
            publish('success')
            db.execute('INSERT OR REPLACE INTO runtime VALUES(1,?)', (json.dumps(state),))
            queue_committed_runs(db, rules, rule_stats, run_id=run_id, stamp=now.isoformat(),
                                 start=lower.isoformat(), end=end.isoformat())
            db.commit()
            # Checkpoint and delivery intent are now committed together. A later ES
            # failure must not rewind them or label this completed run as failed.
            try:
                db.execute('BEGIN IMMEDIATE')
                flush_outbox(client, db)
                db.commit()
            except Exception:
                db.rollback()
                try:
                    publish('success', 'history_delivery_pending')
                except Exception:
                    pass
            return counts
        except Exception:
            db.rollback()
            state = saved
            try:
                runs(client, rules, rule_stats, run_id=run_id, stamp=now.isoformat(), start=lower.isoformat(),
                     end=end.isoformat(), state='failed', error='incremental_cycle_failed')
            except Exception:
                pass
            try:
                publish('failed', 'incremental_cycle_failed')
            except Exception:
                pass
            raise RuntimeError('incremental_cycle_failed; checkpoint retained') from None
