from copy import deepcopy
from datetime import timedelta

import pytest

from cloud_soc.detection.engine import detect_events, rule_revision, observation_identity
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.profiles import source_observed
from cloud_soc.detection.rule_loader import validate_rule
from cloud_soc.detection.worker import approved_rules
from cloud_soc.elastic.repository import save_security_alert
from cloud_soc.main import build_security_alert, make_alert_id
from security_mall_fixtures import BASE, mall
from test_early_notices import Fixture

IDS = ['WEB-ACCESS-01', 'WEB-AUTH-01']


def rules():
    return approved_rules(additional_rule_ids=IDS)


def sequence(count=5, success=60):
    return [mall(i, seconds=i * 10) for i in range(count)] + [mall(100, seconds=success, outcome='success')]


def hits(rows):
    result = []
    for row in deepcopy(rows):
        meta = row.pop('_cloud_soc_meta')
        result.append({'_index': meta['index'], '_id': meta['document_id'], '_source': row})
    return result


def test_explicit_profile_keeps_auth_default_and_source_classification():
    assert [r['id'] for r in rules()] == IDS
    assert [r['id'] for r in approved_rules()] == ['AUTH-001']
    assert [r['id'] for r in approved_rules(rule_ids=IDS)] == ['AUTH-001', *IDS]
    assert all(source_observed(mall(1), key) for key in IDS)
    assert not source_observed({'event': {'action': 'http_access'}}, IDS[0])


def test_four_event_shape_access_only_low_and_complete_evidence():
    rows = [mall(0), mall(1, outcome='success'), mall(2, outcome='success'), mall(3, action='order_view')]
    before = deepcopy(rows)
    found = detect_events(rows, rules())
    assert len(found) == 1 and found[0]['rule_id'] == 'WEB-ACCESS-01'
    assert found[0]['severity'] == 'low' and found[0]['event_count'] == 1
    alert = build_security_alert(found[0])
    assert alert['organization']['id'] == 'mall-org'
    assert alert['cloud_soc']['provenance']['evidence'][0]['raw'] == rows[-1]['cloud_soc']['provenance']['raw']
    assert found[0]['evidence_status'] == 'complete'
    assert rows == before


@pytest.mark.parametrize('path,value', [
    ('event.action', 'http_access'), ('event.outcome', 'success'),
    ('cloud_soc.security_mall.resource_type', 'admin'),
    ('cloud_soc.security_mall.authorization_reason', 'admin_required'),
    ('cloud_soc.security_mall.authorization_reason', 'unauthenticated'),
    ('service.name', 'other-service'), ('cloud_soc.detail.adapter', 'web_access_agent_v1')])
def test_general_403_or_different_semantics_do_not_alert(path, value):
    row = mall(0, action='order_view')
    current = row
    parts = path.split('.')
    for part in parts[:-1]: current = current[part]
    current[parts[-1]] = value
    row['http'] = {'response': {'status_code': 403}}
    assert detect_events([row], rules()) == []


@pytest.mark.parametrize('count', [1, 2, 3, 4])
def test_below_failure_threshold(count):
    assert detect_events(sequence(count), rules()) == []


def test_five_failures_then_success_medium_with_six_provenance_refs():
    found = detect_events(sequence(), rules())
    assert len(found) == 1 and found[0]['rule_id'] == 'WEB-AUTH-01'
    assert found[0]['severity'] == 'medium' and len(found[0]['evidence']) == 6
    assert found[0]['engine_version'] == 'failure-success-v3'
    assert found[0]['evidence_status'] == 'complete'
    # Preserve the existing triage calculation; severity and risk band are distinct.
    alert = build_security_alert(found[0])
    assert alert['cloud_soc']['severity'] == 'medium' and alert['cloud_soc']['risk_score'] == 60


def test_failure_window_and_success_wait_boundaries():
    rows = [mall(i, seconds=i * 75) for i in range(5)]
    assert len(detect_events(rows + [mall(8, seconds=900, outcome='success')], rules())) == 1
    assert detect_events(rows + [mall(8, seconds=901, outcome='success')], rules()) == []
    assert detect_events([mall(i, seconds=i * 100) for i in range(5)] +
                         [mall(8, seconds=450, outcome='success')], rules()) == []


def test_equal_or_preceding_success_is_not_valid_order():
    assert detect_events([mall(100, seconds=0, outcome='success')] +
                         [mall(i, seconds=10) for i in range(5)], rules()) == []
    assert detect_events([mall(i, seconds=10) for i in range(5)] +
                         [mall(100, seconds=10, outcome='success')], rules()) == []


@pytest.mark.parametrize('changed', [{'account': 'b' * 64}, {'ip': '192.0.2.11'},
    {'organization': 'other-org'}, {'key': 'lab-v2'}, {'service': 'other-service'}])
def test_correlation_scope_cannot_mix(changed):
    rows = sequence()[:-1] + [mall(100, seconds=60, outcome='success', **changed)]
    assert detect_events(rows, rules()) == []


@pytest.mark.parametrize('field', ['account_id', 'account_key_id'])
def test_missing_pseudonym_or_key_cannot_be_guessed(field):
    rows = sequence()
    for row in rows: row['cloud_soc']['security_mall'][field] = None
    assert detect_events(rows, rules()) == []


def test_reordered_events_and_duplicate_failure_do_not_inflate_count():
    rows = sequence()
    assert make_alert_id(detect_events(rows, rules())[0]) == make_alert_id(detect_events(rows[::-1], rules())[0])
    short = sequence(4)
    duplicate = deepcopy(short[0])
    duplicate['_cloud_soc_meta']['document_id'] = 're-normalized'
    duplicate['cloud_soc']['provenance']['raw']['id'] = 'replayed-raw'
    assert observation_identity(short[0]) == observation_identity(duplicate)
    assert detect_events(short + [duplicate], rules()) == []


@pytest.mark.parametrize('access', [True, False])
def test_original_event_id_anchors_immutable_alert_across_reprocessing(access):
    rows = [mall(0, action='order_view')] if access else sequence()
    initial = detect_events(rows, rules())[0]
    revised = deepcopy(rows)
    for row in revised:
        row['_cloud_soc_meta']['document_id'] += '-revision'
        row['cloud_soc']['provenance']['raw']['id'] += '-replay'
        row['cloud_soc']['normalized_at'] = (BASE + timedelta(hours=1)).isoformat()
    replay = detect_events(revised, rules())[0]
    assert make_alert_id(initial) == make_alert_id(replay)
    f = Fixture([])
    for found, expected in [(initial, 'created'), (replay, 'existing')]:
        assert save_security_alert(f.client, build_security_alert(found), document_id=make_alert_id(found),
            index_name='security-alerts', index_prepared=True, refresh=False)['result'] == expected
    assert len(f.docs) == 1
    assert next(iter(f.docs.values()))['cloud_soc']['provenance']['evidence'] == initial['evidence']


def test_cooldown_and_success_reset():
    rows = sequence(success=60)
    rows += [mall(200 + i, seconds=100 + i) for i in range(5)] + [mall(300, seconds=110, outcome='success')]
    rows += [mall(400 + i, seconds=1000 + i) for i in range(5)] + [mall(500, seconds=1010, outcome='success')]
    assert len(detect_events(rows, rules())) == 2
    assert detect_events(sequence(4) + [mall(9, seconds=70), mall(10, seconds=80, outcome='success')], rules()) == []


def test_isolated_failure_does_not_erase_still_valid_burst():
    assert len(detect_events(sequence(success=500) + [mall(10, seconds=400)], rules())) == 1


def test_thresholds_are_validated_config_and_legacy_revision_unchanged():
    rule = rules()[1]
    tuned = deepcopy(rule); tuned['threshold']['count'] = 3
    validate_rule(tuned)
    assert len(detect_events(sequence(3), [tuned])) == 1
    assert rule_revision(tuned) != rule_revision(rule)
    for value in [0, True, 86401, '600']:
        bad = deepcopy(rule); bad['success_window']['seconds'] = value
        with pytest.raises(ValueError): validate_rule(bad)
    legacy = [r for r in approved_rules(include_sequence=True) if r['id'] == 'AUTH-SEQ-001'][0]
    legacy['cooldown'] = {'seconds': 900}
    with pytest.raises(ValueError): validate_rule(legacy)


def test_incremental_retains_burst_during_ten_minute_wait_and_restart(tmp_path):
    rows = sequence(success=540)
    rows[-1]['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=550)).isoformat()
    f = Fixture(hits(rows)); path = tmp_path / 'mall.sqlite'
    options = dict(state_path=path, start=BASE, lateness_seconds=60, scanner=f.scan, additional_rule_ids=IDS)
    for seconds, created in [(140, 0), (440, 0), (680, 1), (740, 0)]:
        assert run_incremental(f.client, now=BASE + timedelta(seconds=seconds), **options)['created'] == created
    alerts = [v for (index, _), v in f.docs.items() if index == 'security-alerts']
    assert len(alerts) == 1 and alerts[0]['rule']['id'] == 'WEB-AUTH-01'
    assert not path.with_name(path.name + '.early.sqlite').exists()


def test_receipt_order_reversal_is_buffered_and_over_late_events_are_recorded(tmp_path):
    rows = sequence(success=60)
    for row in rows[:-1]: row['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=200)).isoformat()
    rows[-1]['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=100)).isoformat()
    f = Fixture(hits(rows))
    options = dict(state_path=tmp_path / 'buffer.sqlite', start=BASE, scanner=f.scan, additional_rule_ids=IDS)
    created = [run_incremental(f.client, now=BASE + timedelta(seconds=n), **options)['created']
               for n in [150, 260, 560, 860, 1160]]
    assert created == [0, 0, 0, 0, 1]
    late = Fixture(hits(rows))
    options = dict(state_path=tmp_path / 'late.sqlite', start=BASE, scanner=late.scan,
                   lateness_seconds=60, additional_rule_ids=IDS)
    assert run_incremental(late.client, now=BASE + timedelta(seconds=150), **options)['created'] == 0
    result = run_incremental(late.client, now=BASE + timedelta(seconds=300), **options)
    assert result['created'] == 0 and result['late'] == 5
    assert any(v.get('reason') == 'late_event' for (index, _), v in late.docs.items()
               if index == 'soc-detection-exclusions-v1')


def test_cooldown_survives_persisted_restart_and_expires(tmp_path):
    rows = sequence(success=60)
    rows[-1]['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=70)).isoformat()
    for offset, success in [(200, 210), (1000, 1010)]:
        burst = [mall(offset + i, seconds=offset + i) for i in range(5)]
        burst += [mall(offset + 10, seconds=success, outcome='success')]
        for row in burst:
            row['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=success + 10)).isoformat()
        rows += burst
    f = Fixture(hits(rows))
    options = dict(state_path=tmp_path / 'cooldown.sqlite', start=BASE, scanner=f.scan,
                   lateness_seconds=60, additional_rule_ids=IDS)
    created = [run_incremental(f.client, now=BASE + timedelta(seconds=n), **options)['created']
               for n in [200, 380, 680, 980, 1280]]
    assert created == [1, 0, 0, 0, 1]
    assert len([v for (index, _), v in f.docs.items() if index == 'security-alerts']) == 2
