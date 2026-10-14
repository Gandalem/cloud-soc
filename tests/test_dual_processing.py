"""Independent live coverage and exact historical receipt backlog, scoped safely."""
from unittest.mock import Mock,patch
import pytest
from cloud_soc.portal.operations import Operations

LOW='2026-10-14T00:51:16Z';HIGH='2026-10-14T04:12:00Z'
def reader():
    client=Mock();client.options.return_value=client
    client.indices.resolve_index.return_value={'indices':[{'name':'soc-host-raw-test'}]}
    client.field_caps.return_value={'fields':{'event.ingested':{'date':{}}}}
    client.count.return_value={'count':3500000,'_shards':{'failed':0}}
    return Operations(client),client

def test_live_coverage_does_not_hide_historical_backlog_or_additional_failure():
    operations,client=reader()
    stages={'normalizer':{'state':'running','health':'delayed','checkpoint':LOW},
        'normalizer-priority':{'state':'success','health':'healthy','checkpoint':HIGH,'initial_start':HIGH},
        'detector':{'state':'success','health':'healthy'},'detector-additional':{'state':'not_started'}}
    with patch.object(operations,'worker_status',side_effect=lambda name:stages.get(name,{'state':'not_started'})):
        result=operations.pipeline()
        assert result['realtime_coverage']['state']=='observed'
        assert result['coverage']['state']=='delayed'
        assert result['historical_backlog']['count']==3500000
        stages['detector-additional']={'state':'failed','health':'failed'}
        failed=operations.pipeline()
        assert failed['realtime_coverage']=={'state':'blocked','reason':'additional_detector_failed'}
    assert client.count.call_args.kwargs['query']=={'range':{'event.ingested':{'gte':LOW,'lt':HIGH}}}

@pytest.mark.parametrize('bad',[-1,True,1.5,'0'])
def test_invalid_or_partial_backlog_is_never_a_confirmed_zero(bad):
    operations,client=reader();client.count.return_value={'count':bad}
    with pytest.raises(ValueError):operations.backlog(LOW,HIGH)
    client.count.return_value={'count':0,'_shards':{'failed':1}}
    with pytest.raises(RuntimeError):operations.backlog(LOW,HIGH)

def test_missing_receipt_mapping_and_scoped_access_fail_closed():
    operations,client=reader();client.field_caps.return_value={'fields':{}}
    with pytest.raises(ValueError):operations.backlog(LOW,HIGH)
    client.count.assert_not_called()
    scoped=Operations(client,organizations=['tenant-a'])
    assert scoped.backlog(LOW,HIGH)=={'state':'unavailable'}
    client.count.assert_not_called()

def test_historical_checkpoint_past_live_floor_confirms_zero_without_scanning():
    operations,client=reader()
    assert operations.backlog(HIGH,LOW)['count']==0
    client.indices.resolve_index.assert_not_called()

def test_backlog_query_failure_leaves_realtime_status_visible():
    operations,client=reader();client.count.side_effect=RuntimeError('unavailable')
    stages={'normalizer':{'state':'running','health':'delayed','checkpoint':LOW},
        'normalizer-priority':{'state':'success','health':'healthy','checkpoint':HIGH,'initial_start':HIGH},
        'detector':{'state':'success','health':'healthy'},'detector-additional':{'state':'not_started'}}
    with patch.object(operations,'worker_status',side_effect=lambda name:stages.get(name,{'state':'not_started'})):result=operations.pipeline()
    assert result['historical_backlog']=={'state':'unavailable'}
    assert result['realtime_coverage']['state']=='observed'

def test_late_review_failure_is_visible_without_hiding_live_coverage():
    operations,client=reader()
    stages={'normalizer':{'state':'success','health':'healthy','checkpoint':HIGH},
        'normalizer-priority':{'state':'success','health':'healthy','checkpoint':HIGH,'initial_start':HIGH},
        'detector':{'state':'success','health':'healthy'},
        'detector-retrospective':{'state':'failed','health':'failed','pending_contexts':2}}
    with patch.object(operations,'worker_status',side_effect=lambda name:stages.get(name,{'state':'not_started'})):
        result=operations.pipeline()
    assert result['realtime_coverage']['state']=='observed'
    assert result['coverage']=={'state':'blocked','reason':'retrospective_failed'}
    assert result['late_review']['pending_contexts']==2

def test_alert_row_exposes_only_fixed_historical_review_flag():
    from cloud_soc.portal.operations import alert_row
    source={'rule':{'id':'WEB-404-001'},'cloud_soc':{'provenance':{'review':{
        'mode':'retrospective','private':'SECRET_CANARY'}}}}
    row=alert_row({'_id':'a'*64,'_source':source})
    assert row['historical_review'] is True and 'SECRET_CANARY' not in str(row)
    source['cloud_soc']['provenance']['review']['mode']='SECRET_CANARY'
    assert alert_row({'_id':'a'*64,'_source':source})['historical_review'] is False
