"""Fixed SQL retains tenant selection, ordering and a global capacity boundary."""
from copy import deepcopy
import json

import pytest

from cloud_soc.portal.insight_metrics import validate_evaluation
from cloud_soc.portal.insight_state import InsightStore, InsightError
from test_dashboard_insights_decisions import evaluation_run


def body(identifier, organization):
    return {**deepcopy(evaluation_run()), 'id': identifier, 'organization': organization,
            'started_at': '2020-01-01T00:00:00Z', 'completed_at': '2020-01-01T00:01:00Z'}


@pytest.mark.parametrize(('organizations', 'expected'), [
    (None, ['a', 'b', 'c']), ((), []), (('org-a',), ['b']),
    (('org-b', 'org-a'), ['a', 'b']), (('org-a', 'org-a'), ['b']),
    (("org-a') OR 1=1 --",), []),
])
def test_record_scope_is_bound_data_and_order_is_global(tmp_path, organizations, expected):
    store = InsightStore(tmp_path / 'insights.sqlite', clock=lambda: 100)
    for identifier, organization in [('c', 'org-foreign'), ('b', 'org-a'), ('a', 'org-b')]:
        store.put_record('evaluation', body(identifier, organization), 'operator', validate_evaluation)
    rows = store.records('evaluation', organizations)
    assert [row['body']['id'] for row in rows] == expected
    if organizations is not None:
        assert all(row['body']['organization'] in organizations for row in rows)
    assert store.records("evaluation' OR 1=1 --", None) == []


@pytest.mark.parametrize('count', [1000, 1001])
def test_record_capacity_is_shared_across_selected_organizations(tmp_path, count):
    store = InsightStore(tmp_path / 'insights.sqlite')
    with store.connect() as db:
        db.executemany('INSERT INTO insight_records VALUES (?,?,?,?,?,?,?)', [
            ('evaluation', f'row-{i:04}', 'org-a' if i % 2 else 'org-b', 'synthetic',
             json.dumps(body(f'row-{i:04}', 'org-a' if i % 2 else 'org-b')), 'operator', 100)
            for i in range(count)])
    if count == 1001:
        with pytest.raises(InsightError) as failure:
            store.records('evaluation', ('org-a', 'org-b'))
        assert failure.value.code == 'record_query_capacity' and failure.value.status == 413
    else:
        assert len(store.records('evaluation', ('org-a', 'org-b'))) == 1000
    assert len(store.records('evaluation', ('org-a',))) == count // 2
