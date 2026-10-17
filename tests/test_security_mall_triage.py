"""7-B real local ledger/detector and SQLite transactions; no ES/VM or services."""
from copy import deepcopy
from dataclasses import replace
import json
import sqlite3

import pytest

from cloud_soc.correlation.store import CorrelationStore
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.triage.engine import evaluate
from cloud_soc.triage.policy import Policy
from cloud_soc.triage.store import TriageStore
from test_security_mall_correlation import SCOPE, VIEWER, app, edge, detected, stamp, NORM, RAW
from test_security_mall_detection import sequence

START, END = stamp(0), stamp(1200)


@pytest.fixture
def ledger(tmp_path):
    return CorrelationStore(tmp_path / 'correlation.sqlite', SCOPE)


@pytest.fixture
def queue(tmp_path):
    return TriageStore(tmp_path / 'triage.sqlite', SCOPE)


def run(ledger, events, alerts=None, policy=None):
    ledger.ingest(events, detected(events) if alerts is None else alerts)
    return evaluate(ledger.snapshot(VIEWER), SCOPE, START, END, policy)


def alert_items(result):
    return [item for item in result['items'] if item['linked_alert_ids']]


def auth_hits():
    hits = []
    for i, event in enumerate(sequence()):
        event.pop('_cloud_soc_meta')
        event['http'] = {'request': {'id': chr(65 + i) * 27}}
        event['event']['ingested'] = stamp(100)
        event['cloud_soc']['provenance']['raw'] = {'index': RAW, 'id': 'auth-' + str(i)}
        hits.append({'_index': NORM, '_id': 'norm-auth-' + str(i), '_source': event})
    return hits


def repeated_hits(count=3):
    hits = []
    for i in range(count):
        rid = chr(65 + i) * 27;seconds = i * 40 + 1
        hits.extend([app(i + 1, seconds, rid), edge('web', seconds, rid), edge('waf', seconds, rid)])
    return hits


def test_access_risk_20_low_unchanged_and_one_request_not_three_attacks(ledger):
    events = [app(), edge('web'), edge('waf')];before = deepcopy(events)
    rows = alert_items(run(ledger, events));assert len(rows) == 1
    item = rows[0]
    assert (item['base_risk_score'], item['original_severity'], item['triage_score'], item['triage_priority']) == (20, 'low', 20, 'low')
    assert item['independent_request_count'] == 1
    assert item['evidence_confidence'] == 'corroborated_metadata'
    assert len(item['evidence_references']) == 3 and events == before


def test_auth_risk_60_medium_severity_and_six_requests_not_one(ledger):
    hits = auth_hits();alerts = detected(hits);before = deepcopy(alerts)
    rows = alert_items(run(ledger, hits, alerts));assert len(rows) == 1
    item = rows[0]
    assert (item['base_risk_score'], item['original_severity'], item['original_risk_level'], item['triage_score']) == (60, 'medium', 'high', 60)
    assert item['triage_priority'] == 'high' and len(item['linked_request_ids']) == 6
    assert item['behavior']['login_failures'] == 5 and item['behavior']['login_successes'] == 1
    assert item['independent_request_count'] == 0  # No web anchors: not proof of zero real requests.
    assert item['evidence_confidence'] == 'limited' and not item['behavior']['compromise_confirmed']
    assert alerts == before


def test_independent_repeated_denials_get_bounded_priority_bonus_without_risk_sum(ledger):
    items = alert_items(run(ledger, repeated_hits(5)))
    assert len(items) == 5
    assert sorted(item['triage_score'] for item in items) == [20, 20, 30, 35, 35]
    assert all(item['base_risk_score'] == 20 for item in items)
    assert max(item['repeated_independent_request_count'] for item in items) == 5
    assert items[0]['triage_priority'] == 'medium'


def test_more_streams_change_confidence_not_score(ledger):
    hit = app();initial = alert_items(run(ledger, [hit]))[0]
    ledger.ingest([edge('web'), edge('waf')])
    updated = alert_items(evaluate(ledger.snapshot(VIEWER), SCOPE, START, END))[0]
    assert updated['triage_score'] == initial['triage_score'] == 20
    assert initial['evidence_confidence'] == 'limited' and updated['evidence_confidence'] == 'corroborated_metadata'
    assert updated['id'] == initial['id']


@pytest.mark.parametrize('damage', ['missing', 'hash', 'missing_hash'])
def test_high_risk_missing_or_bad_hash_evidence_stays_high_and_visible(ledger, damage):
    hits = auth_hits();alerts = detected(hits)
    if damage != 'missing':
        ref = alerts[0]['_source']['cloud_soc']['provenance']['evidence'][0]
        if damage == 'hash':ref['event_hash'] = '0' * 64
        else:ref.pop('event_hash')
    result = run(ledger, [] if damage == 'missing' else hits, alerts)
    item = alert_items(result)[0]
    assert item['triage_score'] == 60 and item['triage_priority'] == 'high'
    assert item['evidence_confidence'] == 'unverified'
    assert item['evidence_completeness']['unresolved_alert_references'] > 0
    assert 'evidence_missing_or_integrity_unverified' in item['uncertainty_factors']


def test_waf_detection_only_and_app_403_are_separate(ledger):
    item = alert_items(run(ledger, [app(), edge('web'), edge('waf')]))[0]
    behavior = item['behavior']
    assert behavior['application_denials'] == 1 and behavior['http_403_responses'] == 1
    assert behavior['application_denial_reasons'] == ['not_owner']
    assert behavior['http_403_causes'] == ['consistent_with_application_denial']
    assert behavior['waf_rule_matches'] == 1 and behavior['waf_detection_only_observed']
    assert behavior['waf_block_observed'] is False and not behavior['origin_authenticated']
    assert 'DetectionOnly는 차단이 아니며' in item['explanation']


def test_generic_403_and_waf_observations_do_not_create_risk_or_alert(ledger):
    result = run(ledger, [edge('web'), edge('waf')], [])
    assert len(result['items']) == 1
    item = result['items'][0]
    assert item['triage_score'] == 0 and not item['linked_alert_ids']
    assert item['base_risk_score'] is None and item['review_kind'] == 'unalerted_observation'
    assert not item['behavior']['application_denials'] and item['behavior']['waf_block_observed'] is False


def test_app_only_login_failure_and_success_are_not_attack_confirmation(ledger):
    result = run(ledger, [app(1, 1, action='login'), app(2, 2, 'B' * 27, action='login', outcome='success')], [])
    assert len(result['items']) == 2
    assert all(item['triage_score'] == 0 and not item['behavior']['compromise_confirmed'] for item in result['items'])
    assert all(item['evidence_completeness']['state'] == 'partial' for item in result['items'])


def test_one_request_referenced_by_multiple_alerts_never_counts_as_repetition(ledger):
    hit = app();alerts = detected([hit]);second = deepcopy(alerts[0]);second['_id'] = 'another-stored-alert'
    result = run(ledger, [hit, edge('web'), edge('waf')], alerts + [second])
    assert len(result['items']) == 2
    assert all(item['triage_score'] == 20 and item['repeated_independent_request_count'] == 1 for item in result['items'])


@pytest.mark.parametrize('change', ['account', 'key', 'ip'])
def test_repetition_does_not_mix_pseudonym_key_or_observed_ip(ledger, change):
    hits = repeated_hits()
    meta = hits[-3]['_source']['cloud_soc']['security_mall']
    if change == 'account':meta['account_id'] = 'b' * 64
    if change == 'key':meta['account_key_id'] = 'v2'
    if change == 'ip':hits[-3]['_source']['source']['ip'] = '192.0.2.99'
    result = run(ledger, hits)
    assert all(item['triage_score'] == 20 for item in alert_items(result))


def test_ambiguous_same_id_accesses_do_not_establish_independent_repetitions(ledger):
    result = run(ledger, [app(), edge('web', 1), edge('web', 2), edge('waf')])
    item = alert_items(result)[0]
    assert item['independent_request_count'] == 0 and item['triage_score'] == 20
    assert item['evidence_completeness']['state'] == 'ambiguous'
    assert 'ambiguous_request_id' in item['uncertainty_factors']


def test_hashes_provenance_event_ids_remain_intact(ledger):
    hits = [app(), edge('web'), edge('waf')];alerts = detected(hits)
    item = alert_items(run(ledger, hits, alerts))[0]
    expected = alerts[0]['_source']['cloud_soc']['provenance']['evidence'][0]
    ref = next(ref for ref in item['evidence_references'] if ref['normalized'] == expected['normalized'])
    assert all(ref[key] == expected[key] for key in ('raw', 'normalized', 'event_hash'))
    assert ref['verification'] == 'matched_normalized_hash'
    assert ref['event_id'] == hits[0]['_source']['event']['id']
    assert item['linked_alert_ids'] == [{'index': alerts[0]['_index'], 'id': alerts[0]['_id']}]


def test_same_revision_replay_and_reopen_are_noops(ledger, queue):
    run(ledger, [app()]);snapshot = ledger.snapshot(VIEWER)
    assert queue.replace(snapshot, START, END)['applied']
    before = queue.queue(START, END, VIEWER)
    assert not queue.replace(snapshot, START, END)['applied']
    assert TriageStore(queue.path, SCOPE).queue(START, END, VIEWER) == before
    assert ledger.snapshot(VIEWER) == snapshot


def test_late_revision_replaces_bundle_ids_but_alert_queue_id_is_stable(ledger, queue):
    run(ledger, [app()]);first = ledger.snapshot(VIEWER);queue.replace(first, START, END)
    old = alert_items(queue.queue(START, END, VIEWER))[0]
    ledger.ingest([edge('web', 0), edge('waf', 0)])
    later = ledger.snapshot(VIEWER);assert later['revision_order']['sequence'] > first['revision_order']['sequence']
    queue.replace(later, START, END);new = alert_items(queue.queue(START, END, VIEWER))[0]
    assert new['id'] == old['id'] and new['linked_request_bundle_ids'] != old['linked_request_bundle_ids']
    assert new['evidence_confidence'] == 'corroborated_metadata'
    assert len(queue.queue(START, END, VIEWER)['items']) == 1
    with pytest.raises(ValueError, match='triage_stale_revision'):queue.replace(first, START, END)
    assert alert_items(queue.queue(START, END, VIEWER))[0] == new


def test_revision_same_sequence_different_content_is_conflict(ledger, queue):
    run(ledger, [app()]);first = ledger.snapshot(VIEWER);queue.replace(first, START, END)
    ledger.ingest([edge('web')]);new = ledger.snapshot(VIEWER)
    new['revision_order']['sequence'] = first['revision_order']['sequence']
    with pytest.raises(ValueError, match='triage_revision_conflict'):queue.replace(new, START, END)


def test_new_publisher_requires_manual_rebind_not_implicit_reset(ledger, queue, tmp_path):
    run(ledger, [app()]);queue.replace(ledger.snapshot(VIEWER), START, END)
    fresh = CorrelationStore(tmp_path / 'fresh.sqlite', SCOPE)
    run(fresh, [app()])
    with pytest.raises(ValueError, match='triage_publisher_changed'):queue.replace(fresh.snapshot(VIEWER), START, END)


@pytest.mark.parametrize('part', ['organization', 'site', 'host', 'service'])
def test_scope_mismatch_cannot_replace_saved_queue(ledger, queue, part):
    run(ledger, [app()]);snapshot = ledger.snapshot(VIEWER);queue.replace(snapshot, START, END)
    before = queue.queue(START, END, VIEWER)
    bad = deepcopy(snapshot);bad['scope'][part] = 'another-' + part
    with pytest.raises(ValueError, match='triage_scope_mismatch'):queue.replace(bad, START, END)
    assert queue.queue(START, END, VIEWER) == before


def test_cross_org_reads_hide_items_and_existing_case_references(ledger, queue):
    run(ledger, [app()]);queue.replace(ledger.snapshot(VIEWER), START, END)
    item = queue.queue(START, END, VIEWER)['items'][0]
    other = LogPrincipal('other', 'investigator', ('another-org',), ())
    assert queue.queue(START, END, other) == {'items': []}
    for key in (item['id'], 'nonexistent'):
        with pytest.raises(LookupError, match='^triage_not_found$'):queue.item(key, START, END, other)


def test_storage_failure_rolls_back_head_and_results(ledger, queue):
    run(ledger, [app()]);queue.replace(ledger.snapshot(VIEWER), START, END)
    old = queue.queue(START, END, VIEWER)
    ledger.ingest([edge('web')]);snapshot = ledger.snapshot(VIEWER)
    with queue.connect() as db:
        db.execute("CREATE TRIGGER fail_write BEFORE UPDATE ON frames BEGIN SELECT RAISE(ABORT,'synthetic_storage_failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match='synthetic_storage_failure'):queue.replace(snapshot, START, END)
    assert queue.queue(START, END, VIEWER) == old


def test_range_replacement_does_not_change_another_frame(ledger, queue):
    run(ledger, [app()]);queue.replace(ledger.snapshot(VIEWER), START, END)
    old = queue.queue(START, END, VIEWER)
    ledger.ingest([app(2, 1300, 'B' * 27)], detected([app(2, 1300, 'B' * 27)]))
    queue.replace(ledger.snapshot(VIEWER), stamp(1200), stamp(2400))
    assert queue.queue(START, END, VIEWER) == old


def test_range_bounds_and_evaluation_order_are_deterministic(ledger):
    result = run(ledger, repeated_hits())
    assert evaluate(ledger.snapshot(VIEWER), SCOPE, START, END) == result
    assert result['items'] == sorted(result['items'], key=lambda i: (-i['triage_score'], i['occurred_at'], i['id']))
    assert all(item['explanation'] for item in result['items'])
    with pytest.raises(ValueError, match='triage_range_invalid'):evaluate(ledger.snapshot(VIEWER), SCOPE, END, START)


def test_policy_is_central_versioned_and_does_not_modify_base(ledger):
    hits = repeated_hits();run(ledger, hits)
    default = evaluate(ledger.snapshot(VIEWER), SCOPE, START, END)
    other = evaluate(ledger.snapshot(VIEWER), SCOPE, START, END, replace(Policy(), max_repetition_bonus=0))
    assert default['policy_id'] != other['policy_id']
    assert all(item['triage_score'] == item['base_risk_score'] == 20 for item in alert_items(other))


def test_privacy_output_and_revision_tampering(ledger, queue):
    hits = [app()];hits[0]['_source'].update(password='PRIVATE_CANARY', message='PRIVATE_CANARY', cookie='PRIVATE_CANARY')
    run(ledger, hits);snapshot = ledger.snapshot(VIEWER);queue.replace(snapshot, START, END)
    assert 'PRIVATE_CANARY' not in json.dumps(queue.queue(START, END, VIEWER))
    assert b'PRIVATE_CANARY' not in queue.path.read_bytes()
    bad = deepcopy(snapshot);bad['requests'][0]['events'][0]['metadata']['password'] = 'PRIVATE_CANARY'
    with pytest.raises(ValueError) as error:queue.replace(bad, START, END)
    assert 'PRIVATE_CANARY' not in str(error.value)
    with pytest.raises(ValueError, match='triage_revision_invalid'):
        wrong = deepcopy(snapshot);wrong['revision'] = '0' * 64;queue.replace(wrong, START, END)


def test_late_ingestion_is_uncertainty_not_risk_discount(ledger):
    hit = app();hit['_source']['event']['ingested'] = stamp(600)
    item = alert_items(run(ledger, [hit]))[0]
    assert 'delayed_evidence' in item['uncertainty_factors'] and item['triage_score'] == 20


def test_correlation_sequence_is_durable_idempotent_and_transactional(ledger):
    before = ledger.snapshot(VIEWER)['revision_order']
    ledger.ingest([app()]);after = ledger.snapshot(VIEWER)['revision_order']
    assert after['sequence'] == before['sequence'] + 1
    ledger.ingest([app()]);assert ledger.snapshot(VIEWER)['revision_order'] == after
    conflict = app();conflict['_source']['cloud_soc']['security_mall']['account_key_id'] = 'changed'
    with pytest.raises(ValueError):ledger.ingest([app(2), conflict])
    assert ledger.snapshot(VIEWER)['revision_order'] == after
    assert CorrelationStore(ledger.path, SCOPE).snapshot(VIEWER)['revision_order'] == after


def test_schema_upgrade_of_own_old_7a_ledger_preserves_evidence(ledger):
    run(ledger, [app()]);before = ledger.snapshot(VIEWER)
    with ledger.connect() as db:db.execute('DROP TABLE revision_state')
    reopened = CorrelationStore(ledger.path, SCOPE);after = reopened.snapshot(VIEWER)
    assert {k: v for k, v in before.items() if k != 'revision_order'} == {k: v for k, v in after.items() if k != 'revision_order'}
    assert after['revision_order']['sequence'] == 0


def test_no_order_legacy_snapshot_cannot_overwrite_queue(ledger, queue):
    run(ledger, [app()]);snapshot = ledger.snapshot(VIEWER);queue.replace(snapshot, START, END)
    old = deepcopy(snapshot);old.pop('revision_order')
    with pytest.raises(ValueError, match='triage_snapshot_contract'):queue.replace(old, START, END)


def test_repetition_window_does_not_include_expired_or_future_requests(ledger):
    hits = repeated_hits(2)
    rid = 'Z' * 27
    hits.extend([app(99, 500, rid), edge('web', 500, rid), edge('waf', 500, rid)])
    items = alert_items(run(ledger, hits))
    assert all(item['triage_score'] == 20 for item in items)


def test_score_cap_100_keeps_original_risk_and_no_summing(ledger):
    hits = repeated_hits();alerts = detected(hits)
    alerts[-1]['_source']['cloud_soc'].update(risk_score=99, severity='critical', risk_level='critical')
    item = alert_items(run(ledger, hits, alerts))[0]
    assert item['triage_score'] == 100 and item['base_risk_score'] == 99 and item['triage_priority'] == 'critical'


@pytest.mark.parametrize('value', [-1, True, '2'])
def test_invalid_revision_sequence_cannot_change_queue(ledger, queue, value):
    run(ledger, [app()]);snapshot = ledger.snapshot(VIEWER);queue.replace(snapshot, START, END)
    before = queue.queue(START, END, VIEWER)
    snapshot['revision_order']['sequence'] = value
    with pytest.raises(ValueError, match='triage_order_invalid'):queue.replace(snapshot, START, END)
    assert queue.queue(START, END, VIEWER) == before


def test_no_request_id_alert_still_visible_and_never_independent(ledger):
    item = alert_items(run(ledger, [app(rid=None)]))[0]
    assert item['triage_score'] == 20 and item['linked_request_ids'] == []
    assert item['independent_request_count'] == 0 and item['evidence_confidence'] == 'limited'


def test_empty_snapshot_has_empty_durable_queue(ledger, queue):
    queue.replace(ledger.snapshot(VIEWER), START, END)
    assert queue.queue(START, END, VIEWER)['items'] == []


def test_frame_limit_failure_is_atomic(ledger, tmp_path):
    queue = TriageStore(tmp_path / 'bounded.sqlite', SCOPE, replace(Policy(), max_queue_frames=1))
    run(ledger, [app()]);snapshot = ledger.snapshot(VIEWER);queue.replace(snapshot, START, END)
    with pytest.raises(ValueError, match='triage_frame_capacity'):queue.replace(snapshot, END, stamp(2400))
    assert len(queue.queue(START, END, VIEWER)['items']) == 1
    assert queue.queue(END, stamp(2400), VIEWER) == {'items': []}


def test_foreign_database_and_changed_policy_cannot_overwrite_state(ledger, queue):
    run(ledger, [app()]);queue.replace(ledger.snapshot(VIEWER), START, END)
    before = queue.path.read_bytes()
    with pytest.raises(ValueError, match='triage_store_binding_mismatch'):
        TriageStore(queue.path, SCOPE, replace(Policy(), max_repetition_bonus=0))
    assert queue.path.read_bytes() == before
    old_ledger = ledger.path.read_bytes()
    with pytest.raises(ValueError, match='foreign_triage_database'):TriageStore(ledger.path, SCOPE)
    assert ledger.path.read_bytes() == old_ledger
