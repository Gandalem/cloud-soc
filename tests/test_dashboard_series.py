from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import patch
import pytest
from cloud_soc.portal.operations import display_summary, Operations
from cloud_soc.privacy import redact_metadata, REDACTED
from test_integration_security import session_portal as session_portal, login


def payload(size=289):
    start = datetime(2026, 10, 12, tzinfo=timezone.utc)
    buckets = [{'time': (start + timedelta(minutes=5*i)).isoformat(), 'count': i % 3,
                'password': 'BUCKET_PRIVATE_CANARY'} for i in range(size)]
    sections = {name: {'state': 'ok', 'count': sum(row['count'] for row in buckets),
                      'buckets': deepcopy(buckets), 'rows': []} for name in ('intake','processing','alerts','quality')}
    sections['alerts']['rows'] = [{'title':'password=TITLE_PRIVATE_CANARY', 'password':'ROW_PRIVATE_CANARY'}]
    return {'sections': sections, 'password':'TOP_PRIVATE_CANARY', 'other': ['PRIVATE_ARRAY_CANARY']*300}


def test_numeric_chart_collection_survives_without_weakening_other_privacy():
    data=payload();before=deepcopy(data);result=display_summary(data)
    assert data==before
    assert result['other']==REDACTED and result['password']==REDACTED
    assert redact_metadata(data)['sections']['intake']['buckets']==REDACTED
    for name in ('intake','processing','alerts','quality'):
        chart=result['sections'][name]['buckets']
        assert len(chart)==289 and sum(row['count'] for row in chart)==result['sections'][name]['count']
        assert all(set(row)=={'time','count'} for row in chart)
    assert 'PRIVATE_CANARY' not in json.dumps(result)


def test_actual_authenticated_operations_route_preserves_full_chart(session_portal):
    app,_,_,_=session_portal;http,_=login(app,'admin')
    with patch.object(Operations,'summary',return_value=json.dumps(payload()).encode()):
        response=http.get('/api/operations')
    assert response.status_code==200
    assert len(response.json['sections']['intake']['buckets'])==289
    assert 'PRIVATE_CANARY' not in response.get_data(as_text=True)
    assert app.test_client().get('/api/operations').status_code==401


@pytest.mark.parametrize('change',[{'count':True},{'count':-1},{'count':2**53},{'time':'token=PRIVATE_CANARY'}])
def test_invalid_fixed_chart_fields_fail_closed(change):
    data=payload(1);data['sections']['intake']['buckets'][0].update(change)
    with pytest.raises(ValueError):display_summary(data)


def test_chart_bound_and_zero_series_preserved():
    with pytest.raises(ValueError):display_summary(payload(1001))
    data=payload(289)
    for section in data['sections'].values():
        section['count']=0
        for bucket in section['buckets']:bucket['count']=0
    result=display_summary(data)
    assert len(result['sections']['alerts']['buckets'])==289
    assert all(row['count']==0 for row in result['sections']['alerts']['buckets'])
