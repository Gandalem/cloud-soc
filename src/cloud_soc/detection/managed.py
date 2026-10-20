"""Explicitly configured fast rule worker; existing detector state is never opened.

A bounded event-time replay buffer tolerates reordering without waiting for a
watermark. Logical alerts are immutable; changed evidence is a linked revision.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re

from elasticsearch import ConflictError

from cloud_soc.detection.engine import (build_group_key, detect_rule, event_evidence, event_fingerprint,
    get_field_value, observation_identity, parse_event_timestamp, rule_revision)
from cloud_soc.detection.telemetry import evaluate
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping
from cloud_soc.pipeline.alerts import build_security_alert
from cloud_soc.portal.rule_library import RuleLibrary, aware, digest, encoded


def configuration(value):
    required = {'organizations', 'normalized_indices', 'raw_indices', 'alerts_index', 'revisions_index',
                'max_events', 'max_alerts', 'late_seconds', 'future_seconds'}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError('managed_config_invalid')
    c = deepcopy(value)
    for key in ('normalized_indices', 'raw_indices'):
        names = c[key]
        if (not isinstance(names, list) or not 1 <= len(names) <= 8 or
                any(not isinstance(n, str) or not re.fullmatch('[a-z0-9][a-z0-9_.-]{0,199}', n) for n in names)
                or len(set(names)) != len(names)):
            raise ValueError('concrete_indices_required')
    for key in ('alerts_index', 'revisions_index'):
        if not isinstance(c[key], str) or not re.fullmatch('[a-z0-9][a-z0-9_.-]{0,199}', c[key]):
            raise ValueError('concrete_indices_required')
    names = [*c['normalized_indices'], *c['raw_indices'], c['alerts_index'], c['revisions_index']]
    if len(set(names)) != len(names):
        raise ValueError('index_roles_overlap')
    if (not isinstance(c['organizations'], list) or not 1 <= len(c['organizations']) <= 20 or
            any(not isinstance(o, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', o) for o in c['organizations'])):
        raise ValueError('organizations_required')
    for key, low, high in (('max_events', 10, 20000), ('max_alerts', 10, 200000),
                           ('late_seconds', 0, 3600), ('future_seconds', 0, 300)):
        if type(c[key]) is not int or not low <= c[key] <= high:
            raise ValueError('managed_bound_invalid')
    return c


def checked_indices(client, names):
    response = client.indices.resolve_index(name=','.join(names), expand_wildcards='none')
    if (response.get('aliases') or response.get('data_streams') or
            sorted(r['name'] for r in response.get('indices', [])) != sorted(names)):
        raise ValueError('concrete_indices_required')


def immutable_create(client, index, identifier, document):
    try:
        result = client.create(index=index, id=identifier, document=document, refresh=False)
        if result.get('result') != 'created':
            raise RuntimeError('unexpected_create_result')
        return True
    except ConflictError:
        existing = client.get(index=index, id=identifier)['_source']
        if digest(existing) != digest(document):
            raise ValueError('immutable_document_conflict') from None
        return False


class ManagedWorker:
    def __init__(self, library_path, config, *, source_id='local'):
        self.config = configuration(config)
        self.source_id = source_id
        self.path = Path(library_path)
        if not self.path.is_file() or self.path.is_symlink():
            raise ValueError('existing_rule_library_required')
        self.library = RuleLibrary(self.path, self.config['organizations'])
        with self.library.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS managed_worker_state (
                    rule_id TEXT NOT NULL, generation INTEGER NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(rule_id,generation));
                CREATE TABLE IF NOT EXISTS managed_alerts (
                    id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, original TEXT NOT NULL,
                    content_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS managed_alert_revisions (
                    id TEXT PRIMARY KEY, logical_id TEXT NOT NULL, content_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS managed_input_issues (
                    rule_id TEXT NOT NULL, reference TEXT NOT NULL, reason TEXT NOT NULL,
                    PRIMARY KEY(rule_id,reference,reason));
                CREATE TABLE IF NOT EXISTS managed_heartbeat (
                    scope TEXT PRIMARY KEY, at TEXT NOT NULL, failed INTEGER NOT NULL);
            ''')

    def run(self, client, *, now=None, scanner=fetch_all_hits):
        now = aware(now) if isinstance(now, str) else now or datetime.now(timezone.utc)
        if now.utcoffset() is None:
            raise ValueError('time_zone_required')
        totals = {'rules': 0, 'created': 0, 'existing': 0, 'revisions': 0, 'issues': 0, 'failed': 0}
        for release in self.library.desired_releases(self.config['organizations']):
            try:
                counts = self.cycle(client, release, now=now, scanner=scanner)
                for key, value in counts.items():
                    totals[key] += value
                totals['rules'] += 1
            except Exception:
                # A changed generation is never acknowledged as the old execution.
                try:
                    self.library.acknowledge(release['id'], release['generation'], 'failed')
                except Exception:
                    pass
                totals['failed'] += 1
        with self.library.connect() as db:
            db.execute('INSERT OR REPLACE INTO managed_heartbeat VALUES(?,?,?)',
                       (digest(self.config),now.isoformat(),totals['failed']))
        return totals

    def cycle(self, client, release, *, now, scanner):
        c = self.config
        # One DB write lock fences deletion/replacement and concurrent workers.
        # Remote side effects precede this transaction's durable checkpoint.
        with self.library.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT * FROM managed_rules WHERE id=?', (release['id'],)).fetchone()
            if current is None or current['generation'] != release['generation']:
                raise ValueError('release_changed')
            if release['action'] != 'running':
                db.execute('UPDATE managed_rules SET observed=?,observed_state=?,observed_at=?,status=? WHERE id=?',
                           (release['generation'], release['action'], now.isoformat(),
                            'deleted' if release['action'] == 'deleted' else current['status'], release['id']))
                return {}
            rule = json.loads(release['engine_rule'])
            start = aware(release['effective_from'])
            if start > now:
                raise ValueError('start_in_future')
            horizon = rule['time_window']['seconds'] + rule.get('success_window', {}).get('seconds', 0)
            # Retain cooldown context too, otherwise bounded replay could repeat suppressed alerts.
            horizon += rule.get('cooldown', {}).get('seconds', 0) + c['late_seconds']
            identity = digest({'rule': rule, 'config': c, 'start': start.isoformat(), 'source': self.source_id})
            saved = db.execute('SELECT body FROM managed_worker_state WHERE rule_id=? AND generation=?',
                               (release['id'], release['generation'])).fetchone()
            state = json.loads(saved['body']) if saved else {
                'identity': identity, 'checkpoint': (start - timedelta(seconds=horizon)).isoformat(),
                'events': {}, 'seen': {}, 'last_now': now.isoformat()}
            if state['identity'] != identity or aware(state['last_now']) > now:
                raise ValueError('worker_scope_or_clock_changed')
            checkpoint = aware(state['checkpoint'])
            lower = checkpoint - timedelta(seconds=max(60, c['late_seconds']))
            # Read through now, including bootstrap context, in this cycle.
            # A complete PIT and max_events bound work without an artificial delay.
            end = now
            checked_indices(client, [*c['normalized_indices'], *c['raw_indices'], c['alerts_index'], c['revisions_index']])
            ensure_provenance_mapping(client, c['alerts_index'], apply=False)
            ensure_provenance_mapping(client, c['revisions_index'], apply=False)
            counts = {'created': 0, 'existing': 0, 'revisions': 0, 'issues': 0}
            issues = db.execute('SELECT count(*) FROM managed_input_issues WHERE rule_id=?', (release['id'],)).fetchone()[0]
            floor = min(checkpoint, now) - timedelta(seconds=horizon)
            pool = {k: e for k, e in state['events'].items() if parse_event_timestamp(e) >= floor}

            def issue(reference, reason):
                nonlocal issues
                if db.execute('INSERT OR IGNORE INTO managed_input_issues VALUES(?,?,?)',
                              (release['id'], reference, reason)).rowcount:
                    counts['issues'] += 1
                    issues += 1
                if issues > c['max_events']:
                    raise ValueError('issue_capacity')

            query = {'bool': {'filter': [
                {'range': {'cloud_soc.normalized_at': {'gte': lower.isoformat(), 'lte': end.isoformat()}}},
                {'term': {'organization.id': release['organization']}}]}}
            read_count = 0
            for index in c['normalized_indices']:
                for hit in scanner(client, index=index, query=query, max_documents=c['max_events']):
                    read_count += 1
                    if read_count > c['max_events'] or hit.get('_index') != index or not isinstance(hit.get('_id'), str):
                        raise ValueError('input_scope_or_capacity')
                    e = deepcopy(hit['_source'])
                    e['_cloud_soc_meta'] = {'index': index, 'document_id': hit['_id']}
                    ref = encoded([index, hit['_id']])
                    received = aware(get_field_value(e, 'cloud_soc.normalized_at'))
                    if get_field_value(e, 'organization.id') != release['organization'] or not lower <= received <= end:
                        raise ValueError('input_scope_mismatch')
                    content_hash = event_fingerprint(e)
                    prior = state['seen'].get(ref)
                    if prior and prior['hash'] != content_hash:
                        raise ValueError('normalized_document_changed')
                    if prior:
                        continue
                    state['seen'][ref] = {'hash': content_hash, 'received': received.isoformat()}
                    evidence = event_evidence(e)
                    if not evidence['complete'] or evidence['raw']['index'] not in c['raw_indices']:
                        raise ValueError('input_provenance_invalid')
                    outcome, _ = evaluate(e, rule)
                    if outcome == 'not_matched':
                        continue
                    if outcome != 'matched':
                        issue(ref, 'required_fields_missing')
                        continue
                    if build_group_key(e, rule['group_by']) is None:
                        issue(ref, 'group_values_invalid')
                        continue
                    try:
                        event_time = parse_event_timestamp(e)
                    except (ValueError, TypeError):
                        issue(ref, 'event_time_invalid')
                        continue
                    if event_time > now + timedelta(seconds=c['future_seconds']):
                        issue(ref, 'future_event_time')
                    elif event_time > now:
                        pool[ref] = e
                    elif event_time < floor:
                        issue(ref, 'late_input_reprocessing_required')
                    else:
                        pool[ref] = e
            if len(pool) > c['max_events']:
                raise ValueError('event_capacity')
            # Re-evaluate the bounded buffer in event order; original events are immutable.
            replay_rule = deepcopy(rule)
            replay_rule['cooldown'] = {'seconds': 0}
            detections = detect_rule([e for e in pool.values() if parse_event_timestamp(e) <= now], replay_rule, runtime={})
            originals = [json.loads(r['original']) for r in db.execute(
                'SELECT original FROM managed_alerts WHERE rule_id=?', (release['id'],))]
            for detection in detections:
                if aware(detection['window_end']) < start:
                    continue
                refs = detection['evidence']
                by_reference = {encoded(event_evidence(e)['normalized']): e for e in pool.values()}
                trigger = by_reference[encoded(refs[-1]['normalized'])]
                logical_id = digest({'rule_id': release['id'], 'revision': rule_revision(rule),
                                     'trigger': observation_identity(trigger)})
                group_key = digest(detection['group'])
                cooldown = rule.get('cooldown', {}).get('seconds', 0)
                prior_logical = db.execute('SELECT * FROM managed_alerts WHERE id=?', (logical_id,)).fetchone()
                if prior_logical is None and any(
                        get_field_value(old, 'cloud_soc.provenance.managed.group') == group_key and
                        get_field_value(old, 'cloud_soc.provenance.rule_version') == rule_revision(rule) and
                        abs((aware(old['@timestamp']) - aware(detection['window_end'])).total_seconds()) < cooldown
                        for old in originals):
                    continue
                detection['rule_snapshot'] = deepcopy(rule)
                detection['rule_version'] = rule_revision(rule)
                detection['identity_anchor'] = logical_id
                document = build_security_alert(detection)
                document['cloud_soc']['provenance']['managed'] = {
                    'id': release['id'], 'logical_alert_id': logical_id, 'group': group_key,
                    'evidence_hash': digest(refs)}
                previous = prior_logical
                if previous is None:
                    existing = None
                    try:
                        existing = client.get(index=c['alerts_index'], id=logical_id)['_source']
                    except Exception as error:
                        if getattr(getattr(error, 'meta', None), 'status', None) != 404:
                            raise
                    if existing is not None:
                        if (get_field_value(existing, 'cloud_soc.provenance.managed.id') != release['id'] or
                                get_field_value(existing, 'organization.id') != release['organization'] or
                                get_field_value(existing, 'cloud_soc.provenance.rule_version') != rule_revision(rule)):
                            raise ValueError('remote_alert_identity_conflict')
                        # Remote success followed by local failure: recover the immutable original first.
                        original = existing
                        counts['existing'] += 1
                    else:
                        immutable_create(client, c['alerts_index'], logical_id, document)
                        original = document
                        counts['created'] += 1
                    db.execute('INSERT INTO managed_alerts VALUES(?,?,?,?)',
                               (logical_id, release['id'], encoded(original), digest(original)))
                    originals.append(original)
                    previous = {'content_hash': digest(original), 'original': encoded(original)}
                if previous['content_hash'] != digest(document):
                    original = json.loads(previous['original'])
                    old_refs = {encoded(r) for r in original['cloud_soc']['provenance']['evidence']}
                    new_refs = {encoded(r) for r in refs}
                    if not old_refs <= new_refs:
                        issue(logical_id, 'analysis_context_changed')
                        continue
                    revision_id = digest([logical_id, digest(document)])
                    if not db.execute('SELECT 1 FROM managed_alert_revisions WHERE id=?', (revision_id,)).fetchone():
                        revision_document = deepcopy(document)
                        revision_document['cloud_soc']['provenance']['managed']['original'] = {
                            'index': c['alerts_index'], 'id': logical_id}
                        immutable_create(client, c['revisions_index'], revision_id, revision_document)
                        db.execute('INSERT INTO managed_alert_revisions VALUES(?,?,?)',
                                   (revision_id, logical_id, digest(document)))
                        counts['revisions'] += 1
            stored = db.execute('SELECT count(*) FROM managed_alerts').fetchone()[0]
            revisions = db.execute('SELECT count(*) FROM managed_alert_revisions').fetchone()[0]
            if stored + revisions > c['max_alerts']:
                raise ValueError('alert_state_capacity')
            state.update(events=pool, checkpoint=end.isoformat(), last_now=now.isoformat())
            state['seen'] = {k: v for k, v in state['seen'].items() if aware(v['received']) >= lower}
            if len(state['seen']) > c['max_events'] * 2:
                raise ValueError('receipt_state_capacity')
            db.execute('INSERT OR REPLACE INTO managed_worker_state VALUES(?,?,?)',
                       (release['id'], release['generation'], encoded(state)))
            db.execute("UPDATE managed_rules SET observed=?,observed_state='running',observed_at=? WHERE id=?",
                       (release['generation'], now.isoformat(), release['id']))
            # On failure, rollback keeps the old checkpoint; remote creates are reconciled on retry.
            return counts
