from copy import deepcopy
import json
import sqlite3
from unittest.mock import Mock

import pytest

from cloud_soc.detection.engine import event_fingerprint, rule_revision
from cloud_soc.detection.exclusion_review import classify, review, summary
from cloud_soc.detection.profiles import catalog
from cloud_soc.detection.scope_migration import migrate, previous_identity
from cloud_soc.detection.telemetry import evaluate
from cloud_soc.processing.contract import NORMALIZED

RULES = {rule['id']: rule for rule in catalog()}


def service_logon():
    return {
        'organization': {'id': 'fixture'}, 'host': {'id': 'fixture'},
        'event': {'category': ['authentication'], 'action': 'login', 'outcome': 'success'},
        'cloud_soc': {'detail': {'adapter': 'windows_security_v1', 'fields': {'logon_type': 5}},
                      'provenance': {'raw': {'index': 'soc-host-raw-fixture', 'id': 'raw'}}},
    }


@pytest.mark.parametrize('rule_id', [
    'UNIFIED-SERVER-MIN3-001', 'UNIFIED-THREE-SOURCE-001',
    'UNIFIED-HOST-NET-001', 'UNIFIED-WEB-HOST-001',
])
def test_service_scope_keeps_network_logon_missing_ip_visible(rule_id):
    event = service_logon()
    assert evaluate(event, RULES[rule_id]) == ('not_matched', [])
    event['cloud_soc']['detail']['fields']['logon_type'] = 3
    outcome, missing = evaluate(event, RULES[rule_id])
    assert outcome == 'unknown' and 'source.ip' in missing


def evidence():
    event = service_logon()
    ref = {'index': NORMALIZED, 'id': 'normalized'}
    hashed = {**event, '_cloud_soc_meta': {'index': NORMALIZED, 'document_id': 'normalized'}}
    raw = {'organization': {'id': 'fixture'}, 'winlog': {
        'event_id': 4624, 'event_data': {'LogonType': '5'}}}
    record = {'@timestamp': '2026-11-17T12:00:00.123456Z', 'record_id': 'excluded',
              'normalized': ref, 'raw': event['cloud_soc']['provenance']['raw'],
              'event_hash': event_fingerprint(hashed), 'rule': {'id': 'UNIFIED-SERVER-MIN3-001'}}
    return record, event, raw


def test_review_requires_matching_raw_scope_and_hash():
    record, event, raw = evidence()
    rule = RULES[record['rule']['id']]
    assert classify(record, event, raw, rule) == 'resolved_scope'
    changed = deepcopy(event)
    changed['host']['id'] = 'tampered'
    assert classify(record, changed, raw, rule) == 'needs_review'
    raw['winlog']['event_data']['LogonType'] = '3'
    assert classify(record, event, raw, rule) == 'needs_review'
    assert classify(record, event, None, rule) == 'needs_review'


def test_packetbeat_input_gap_stays_unresolved():
    event = {
        'organization': {'id': 'fixture'}, 'host': {'id': 'fixture'},
        'event': {'category': ['network'], 'dataset': 'flow'},
        'cloud_soc': {'detail': {'adapter': 'packetbeat_metadata_v1',
                                 'fields': {'flow_final': True, 'flow_id': 'fixture'}},
                      'provenance': {'raw': {'index': 'soc-network-fixture', 'id': 'raw'}}},
    }
    record = {'normalized': {'index': NORMALIZED, 'id': 'normalized'},
              'raw': event['cloud_soc']['provenance']['raw']}
    record['event_hash'] = event_fingerprint({
        **event, '_cloud_soc_meta': {'index': NORMALIZED, 'document_id': 'normalized'}})
    raw = {'organization': {'id': 'fixture'}, 'event': {'dataset': 'flow'}}
    assert classify(record, event, raw, RULES['UNIFIED-NET-MIN3-001']) == 'confirmed_input_gap'


def test_scope_migration_preserves_checkpoint_cooldown_and_scan():
    rule = RULES['UNIFIED-SERVER-MIN3-001']
    payload = {'rules': [rule], 'rule_versions': [rule_revision(rule)], 'start': 'fixed'}
    old_identity = previous_identity(payload)
    event = service_logon()
    network = deepcopy(event)
    network['cloud_soc']['detail']['fields']['logon_type'] = 3
    saved = {'identity': old_identity, 'checkpoint': 'checkpoint', 'excluded_total': 100,
             'pending': {'n': network}, 'groups': {'g': {
                 'window': [event, network], 'last_alert': 'cooldown'}}}
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE runtime (id INTEGER PRIMARY KEY, body TEXT)')
        db.execute('INSERT INTO runtime VALUES(1,?)', (json.dumps(saved),))
        db.execute('CREATE TABLE input_scan (id INTEGER PRIMARY KEY, body TEXT)')
        db.execute('INSERT INTO input_scan VALUES(1,?)', (json.dumps({
            'identity': old_identity, 'checkpoint': 'checkpoint', 'after': [42]}),))
        current = migrate(db, saved, payload, 'now')
        assert current['checkpoint'] == saved['checkpoint']
        assert current['identity'] == old_identity
        assert current['scope_identity'] == event_fingerprint(payload)
        assert current['excluded_total'] == 100
        assert current['pending'] == saved['pending']
        assert current['groups']['g'] == {'window': [network], 'last_alert': 'cooldown'}
        assert json.loads(db.execute('SELECT body FROM input_scan').fetchone()[0])['after'] == [42]
        assert migrate(db, current, payload, 'later') == current
        assert db.execute('SELECT count(*) FROM scope_migrations').fetchone()[0] == 1
        with pytest.raises(ValueError):
            migrate(db, {**saved, 'identity': 'foreign'}, payload, 'now')


def test_preflight_accepts_exact_previous_identity_without_modifying_database(tmp_path):
    from cloud_soc.deployment.migrations import state_compatible
    rule = RULES['UNIFIED-SERVER-MIN3-001']
    start = '2026-11-17T00:00:00+00:00'
    payload = {'rules': [rule], 'start': start, 'lateness': 900,
               'index': NORMALIZED, 'source': 'https://elasticsearch:9200',
               'legacy_exclusion': False, 'runtime_contract': 2,
               'rule_versions': [rule_revision(rule)]}
    path = tmp_path / 'runtime.sqlite'
    body = json.dumps({'identity': previous_identity(payload), 'checkpoint': start})
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE runtime (id INTEGER PRIMARY KEY, body TEXT)')
        db.execute('INSERT INTO runtime VALUES(1,?)', (body,))
    row = {'module': 'cloud_soc.detection', 'options': {
        '--additional-rules': rule['id'], '--start': start,
        '--es-url': 'https://elasticsearch:9200', '--lateness-seconds': '900',
    }}
    state_compatible(row, path)
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT body FROM runtime').fetchone()[0] == body
    row['options']['--start'] = '2026-11-17T01:00:00+00:00'
    with pytest.raises(ValueError):
        state_compatible(row, path)


def test_retrospective_identity_transition_preserves_existing_review_jobs():
    rule = RULES['UNIFIED-SERVER-MIN3-001']
    payload = {'contract': 'retrospective-v1', 'rules': [rule],
               'versions': [rule_revision(rule)], 'start': 'fixed'}
    saved = {'identity': previous_identity(payload), 'checkpoint': 'fixed', 'excluded_total': 12}
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE review_state (id INTEGER PRIMARY KEY, body TEXT)')
        db.execute('INSERT INTO review_state VALUES(1,?)', (json.dumps(saved),))
        current = migrate(db, saved, payload, 'now', table='review_state')
        assert current['checkpoint'] == 'fixed' and current['excluded_total'] == 12
        assert current['identity'] == saved['identity']
        assert current['scope_identity'] == event_fingerprint(payload)


def test_policy_transition_pins_original_policy_and_preserves_worker_floors(tmp_path):
    from cloud_soc.deployment.contract import build_contract, digest, policy
    from cloud_soc.detection.rule_loader import PROJECT_ROOT
    value = policy(PROJECT_ROOT)
    current, _ = build_contract(value, {}, tmp_path)
    old = deepcopy(current)
    old['policy_sha256'] = '27e7c586d6185ba4b52991cec2244e2c450c163fc3d01d1b09dfef92a6bf0a58'
    updated, adoption = build_contract(value, {}, tmp_path, existing=old)
    assert updated['policy_sha256'] == digest(value) and not adoption
    assert updated['workers'] == old['workers']
    assert updated['catalog_detection_start'] == old['catalog_detection_start']
    assert updated['scope_migration'] == 'windows-service-logon-v1'
    changed = deepcopy(value)
    changed['resources']['min_cpus'] += 1
    with pytest.raises(ValueError):
        build_contract(changed, {}, tmp_path, existing=old)


def client_for_review():
    record, event, raw = evidence()
    client = Mock()
    client.open_point_in_time.return_value = {'id': 'pit'}
    client.search.side_effect = [
        {'hits': {'hits': [{'_id': 'excluded', '_source': record, 'sort': [1]}]}},
        {'hits': {'hits': []}},
    ]
    client.mget.return_value = {'docs': [
        {'_index': record['raw']['index'], '_id': 'raw', 'found': True, '_source': raw},
        {'_index': NORMALIZED, '_id': 'normalized', 'found': True, '_source': event},
    ]}
    return client


def test_review_apply_is_idempotent_and_new_records_require_review(tmp_path):
    path = tmp_path / 'review.sqlite'
    assert review(client_for_review(), path, actor='fixture')['applied'] is False
    assert not path.exists()
    for _ in range(2):
        result = review(client_for_review(), path, actor='fixture', apply=True)
        assert result['decisions'] == {'resolved_scope': 1}
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT count(*) FROM review_history').fetchone()[0] == 1
    client = Mock()
    def totals(count):
        return {'aggregations': {'rules': {'buckets': [{
            'key': 'UNIFIED-SERVER-MIN3-001', 'doc_count': count,
            'latest': {'value_as_string': '2026-11-17T12:00:00.123Z'},
        }]}}}
    client.search.return_value = totals(1)
    row = summary(client, path)['rules']['UNIFIED-SERVER-MIN3-001']
    assert row['resolved'] == 1 and row['unresolved'] == 0
    client.search.return_value = totals(2)
    row = summary(client, path)['rules']['UNIFIED-SERVER-MIN3-001']
    assert row['resolved'] == 0 and row['unresolved'] == 2
    assert row['snapshot_reviewed'] == 1


def test_incomplete_review_never_changes_database(tmp_path):
    path = tmp_path / 'review.sqlite'
    client = client_for_review()
    client.search.side_effect = [{'timed_out': True}]
    with pytest.raises(ValueError):
        review(client, path, actor='fixture', apply=True)
    assert not path.exists()
    client.close_point_in_time.assert_called_once()


@pytest.mark.parametrize(('excluded', 'unresolved', 'late', 'expected'), [
    (100, 0, 0, 'healthy'),
    (100, 20, 0, 'warning'),
    (100, 0, 1, 'warning'),
    (200, 0, 0, 'warning'),
])
def test_reviewed_counts_do_not_hide_unresolved_or_late_events(excluded, unresolved, late, expected):
    from datetime import datetime, timezone
    from cloud_soc.portal.operations import Operations
    stamp = datetime.now(timezone.utc).isoformat()
    operations = Operations(Mock(), exclusion_reviews='fixture')
    operations.get = lambda *args: {
        '@timestamp': stamp, 'checkpoint': stamp, 'last_success': stamp, 'state': 'success',
        'excluded_total': excluded, 'late_total': late,
        'runtime': {'rules': [{'id': 'UNIFIED-SERVER-MIN3-001'}]},
    }
    operations._review_summary = {'last_reviewed': stamp, 'rules': {
        'UNIFIED-SERVER-MIN3-001': {
            'total': 100, 'reviewed': 100, 'resolved': 100 - unresolved,
            'confirmed_input_gap': unresolved, 'unresolved': unresolved,
            'unreviewed': 0, 'review_state': 'current',
        }}}
    result = operations.worker_status('detector-catalog')
    assert result['health'] == expected
    assert result['excluded_total'] == excluded
