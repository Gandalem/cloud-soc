"""Recent/history isolation, durable progress and read-only runtime reporting."""
from datetime import datetime, timedelta, timezone
import sqlite3
from unittest.mock import Mock

import pytest

from cloud_soc.processing.worker import run_once
from cloud_soc.processing.scoped_service import configuration
from cloud_soc.detection.managed import ManagedWorker
from cloud_soc.detection.managed_health import snapshot
from cloud_soc.portal.rule_library import RuleLibrary
from cloud_soc.portal.operations import Operations
from test_managed_rules import Remote


def client():
    c=Mock();c.options.return_value=c
    c.bulk.side_effect=lambda **kw:{'items':[{'create':{'status':201}} for _ in kw['operations'][::2]]}
    return c


def test_recent_can_reach_now_while_old_history_remains(tmp_path):
    now=datetime(2026,10,20,12,tzinfo=timezone.utc)
    old=tmp_path/'old.sqlite';recent=tmp_path/'recent.sqlite';c=client()
    history=run_once(c,old,'2026-10-18T00:00:00Z',now=now,scanner=lambda *_:[])
    current=run_once(c,recent,'2026-10-20T11:45:00Z',now=now,scanner=lambda *_:[],
                     status_id='normalizer-priority',window_minutes=60,receipt_lag_seconds=2)
    assert current['checkpoint']=='2026-10-20T11:59:58Z'
    with sqlite3.connect(old) as db:assert db.execute('SELECT checkpoint FROM state').fetchone()[0]==history['checkpoint']
    with pytest.raises(ValueError,match='separate explicit state'):
        run_once(c,old,'2026-10-18T00:00:00Z',now=now,receipt_lag_seconds=2)


def test_recent_failure_does_not_advance_coverage(tmp_path):
    now=datetime(2026,10,20,12,tzinfo=timezone.utc);path=tmp_path/'recent.sqlite';c=client()
    first=run_once(c,path,'2026-10-20T11:45:00Z',now=now,scanner=lambda *_:[],window_minutes=60,receipt_lag_seconds=2)
    def fail(*_):raise ConnectionError('private-canary')
    with pytest.raises(RuntimeError,match='checkpoint retained'):
        run_once(c,path,'2026-10-20T11:45:00Z',now=now+timedelta(seconds=10),scanner=fail,window_minutes=60,receipt_lag_seconds=2)
    with sqlite3.connect(path) as db:assert db.execute('SELECT checkpoint FROM state').fetchone()[0]==first['checkpoint']


def test_managed_heartbeat_no_rules_is_not_an_analysis_claim(tmp_path):
    path=tmp_path/'cases.sqlite';RuleLibrary(path,['fixture'])
    cfg={'organizations':['fixture'],'normalized_indices':['norm-unit'],'raw_indices':['soc-host-raw-unit'],'alerts_index':'security-alerts','revisions_index':'revisions-unit','max_events':100,'max_alerts':1000,'late_seconds':60,'future_seconds':0};worker=ManagedWorker(path,cfg);remote=Remote()
    now=datetime(2026,10,20,12,tzinfo=timezone.utc)
    worker.run(remote,now=now)
    health=snapshot(path,cfg,now=now)
    assert health['active_rules']==0 and health['state']=='waiting'
    assert snapshot(path,cfg,now=now+timedelta(seconds=46))['state']=='stale'


def test_explicit_processing_scope_does_not_widen_mall_evidence():
    scope={'alerts':'soc-mall-alerts-lab-live-unit','raw':['soc-host-raw-mall-unit'],'normalized':['soc-normalized-mall-unit']}
    op=Operations(None,mall_scope=scope,processing_scope={'records':'records-unit','status':'status-unit'})
    assert op.evidence({'normalized':{'index':'other','id':'x'},'raw':{'index':'other','id':'x'}})['state']=='unsupported_or_invalid_reference'
    with pytest.raises(ValueError):Operations(None,processing_scope={'status':'*','records':'records-unit'})


def test_scoped_service_rejects_alias_and_history_policy_change(tmp_path):
    c={'mode':'history','start':'2026-01-01T00:00:00Z','state':str(tmp_path/'x.sqlite'),
       'es_url':'https://localhost:9200','ca_file':str(tmp_path/'ca.crt'),'api_key_file':str(tmp_path/'key'),
       'source_indices':['soc-host-raw-test'],'normalized_index':'norm-test','records_index':'records-test',
       'status_index':'status-test','interval_seconds':2,'window_minutes':60,'max_pages':10,
       'receipt_lag_seconds':30,'overlap_seconds':900,'burst_cycles':3}
    assert configuration(c)['mode']=='history'
    with pytest.raises(ValueError):configuration({**c,'source_indices':['soc-host-raw-*']})
    with pytest.raises(ValueError):configuration({**c,'receipt_lag_seconds':2})


def test_log_update_snapshot_closes_pit_without_issuing_page_cursor():
    from cloud_soc.portal.log_query import LogReader
    from test_log_query import client as log_client, response, hits
    import json
    c=log_client();c.search.return_value=response(hits(26))
    reader=LogReader(c,secret='synthetic-secret',principal='test',clock=lambda:100)
    result=json.loads(reader.page([],preview=True))
    assert len(result['rows'])==25 and result['next_cursor'] is None
    c.close_point_in_time.assert_called_once_with(id='rotated-pit')


def test_backup_recognizes_complete_managed_state_but_rejects_unknown_tables(tmp_path):
    from cloud_soc.portal.cases import CaseStore
    from cloud_soc.portal.backup import inspect_database, Budget, BackupError
    path=tmp_path/'cases.sqlite';CaseStore(path,'admin');RuleLibrary(path,['fixture'])
    cfg={'organizations':['fixture'],'normalized_indices':['norm-unit'],'raw_indices':['soc-host-raw-unit'],
         'alerts_index':'security-alerts','revisions_index':'revisions-unit','max_events':100,
         'max_alerts':1000,'late_seconds':60,'future_seconds':0}
    ManagedWorker(path,cfg).run(Remote())
    counts=inspect_database(path,'cases.sqlite',Budget())
    assert counts['managed_heartbeat']==1
    with sqlite3.connect(path) as db:db.execute('CREATE TABLE unknown_state (secret TEXT)')
    with pytest.raises(BackupError):inspect_database(path,'cases.sqlite',Budget())
