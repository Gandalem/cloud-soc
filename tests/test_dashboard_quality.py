"""Independent expected results and independently isolated RBAC/CSRF failures."""
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from cloud_soc.portal.insight_metrics import assessment_score, evaluation_metrics
import dashboard_quality_fixtures as fixtures

portal = fixtures.portal
session = fixtures.session
state_snapshot = fixtures.state_snapshot
from test_dashboard_insights_decisions import policy, assessment, evaluation_run


@pytest.mark.parametrize(('tp', 'fp', 'fn', 'tn', 'precision', 'recall'), [
    (3, 1, 2, 1, 75, 60), (0, 1, 2, 1, 0, 0),
    (0, 0, 2, 1, None, 0), (0, 1, 0, 1, 0, None),
    (3, 0, 0, 1, 100, 100), (0, 0, 0, 1, None, None),
])
def test_asymmetric_metrics_and_independent_zero_denominators(tp, fp, fn, tn, precision, recall):
    run = evaluation_run()
    run.update(started_at='2020-01-01T00:00:00Z', completed_at='2020-01-01T00:01:00Z')
    run['cases'] = []
    for name, count, expected, verdict in [('tp', tp, True, 'alert'), ('fp', fp, False, 'alert'),
                                            ('fn', fn, True, 'no_alert'), ('tn', tn, False, 'no_alert')]:
        run['cases'].extend({'id': f'{name}-{i}', 'expected': expected, 'verdict': verdict,
                             'evidence': 'synthetic-reference'} for i in range(count))
    result = evaluation_metrics([run])
    assert (result['TP'], result['FP'], result['FN'], result['TN']) == (tp, fp, fn, tn)
    assert result['precision'] == precision
    assert result['recall'] == recall
    assert result['eligible_cases'] == tp + fp + fn + tn


@pytest.mark.parametrize('status', ['failed', 'cancelled', 'inconclusive'])
def test_noncomplete_runs_and_indeterminate_cases_are_excluded(status):
    good = evaluation_run()
    good.update(started_at='2020-01-01T00:00:00Z', completed_at='2020-01-01T00:01:00Z')
    good['cases'] = [good['cases'][0],
                     {'id': 'uncertain', 'expected': True, 'verdict': 'inconclusive', 'evidence': 'synthetic'},
                     {'id': 'error', 'expected': True, 'verdict': 'execution_failed', 'evidence': 'synthetic'}]
    failed = deepcopy(good)
    failed.update(id='other-run', status=status)
    result = evaluation_metrics([good, failed])
    assert result['precision'] == 100 and result['recall'] == 100
    assert result['eligible_cases'] == 1 and result['excluded_cases'] == 5
    assert result['case_total'] == 6 and result['failed_runs'] == 1


@pytest.mark.parametrize(('states', 'score', 'coverage', 'applicable', 'failed'), [
    (('fail', 'pass'), 25, 100, 4, 1), (('pass', 'pass'), 0, 100, 4, 0),
    (('fail', 'fail'), 100, 100, 4, 4), (('fail', 'unknown'), None, 25, 4, 1),
    (('fail', 'exempt'), 100, 100, 1, 1), (('exempt', 'pass'), 0, 100, 3, 0),
    (('exempt', 'exempt'), None, 0, 0, 0),
])
def test_weighted_score_and_approved_exception_denominator(states, score, coverage, applicable, failed):
    body = assessment()
    body.update(observed_at='2020-01-01T00:00:00Z', expires_at='2020-01-31T00:00:00Z')
    for item, state in zip(body['items'], states):
        item['state'] = state
        if state == 'exempt':
            item['exception_reason'] = 'Approved exception with assessment expiry'
    result = assessment_score(policy(), body, datetime(2020, 1, 15, tzinfo=timezone.utc))
    assert result['score'] == score and result['coverage_percent'] == coverage
    assert result['applicable_weight'] == applicable and result['failed_weight'] == failed


@pytest.mark.parametrize('stamp', ['2019-12-31T23:59:59+00:00', '2020-01-31T00:00:00+00:00'])
def test_assessment_before_observation_or_at_expiry_has_no_score(stamp):
    body = assessment()
    body.update(observed_at='2020-01-01T00:00:00Z', expires_at='2020-01-31T00:00:00Z')
    result = assessment_score(policy(), body, datetime.fromisoformat(stamp))
    assert result['score'] is None and result['coverage_percent'] == 0


@pytest.mark.parametrize('failure', ['viewer', 'missing_csrf', 'wrong_csrf', 'anonymous'])
def test_management_rejection_preserves_state_with_one_invalid_boundary(portal, failure):
    client, headers = session(portal, 'reader' if failure == 'viewer' else 'admin')
    if failure == 'missing_csrf':
        del headers['X-CSRF-Token']
    elif failure == 'wrong_csrf':
        headers['X-CSRF-Token'] = 'wrong-synthetic-token'
    elif failure == 'anonymous':
        client = portal.test_client()
    store = portal.extensions['insights']
    before = state_snapshot(store)
    response = client.post('/api/dashboard-records/policy', json=policy(), headers=headers, base_url='https://soc.test')
    assert response.status_code == (401 if failure == 'anonymous' else 403)
    assert state_snapshot(store) == before


def test_authorized_policy_save_commits_exact_record_and_audit_once(portal):
    client, headers = session(portal, 'admin')
    store = portal.extensions['insights']
    response = client.post('/api/dashboard-records/policy', json=policy(), headers=headers, base_url='https://soc.test')
    assert response.status_code == 201 and response.json['duplicate'] is False
    records = store.records('policy', ('org-a',))
    assert len(records) == 1 and records[0]['body'] == policy() and records[0]['actor'] == 'admin'
    before = state_snapshot(store)
    repeated = client.post('/api/dashboard-records/policy', json=policy(), headers=headers, base_url='https://soc.test')
    assert repeated.status_code == 201 and repeated.json['duplicate'] is True
    assert state_snapshot(store) == before


def test_reader_cannot_query_another_organization_records(portal):
    from cloud_soc.portal.insight_metrics import validate_evaluation
    store = portal.extensions['insights']
    for org in ('org-a', 'org-b'):
        store.put_record('evaluation', {**evaluation_run(), 'organization': org, 'id': org}, 'admin', validate_evaluation)
    client, _ = session(portal, 'reader')
    response = client.get('/api/dashboard-data/evaluation?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z', base_url='https://soc.test')
    assert response.status_code == 200 and response.json['run_total'] == 1
    assert {r['body']['organization'] for r in response.json['runs']} == {'org-a'}
