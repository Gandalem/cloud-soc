"""Late context is independent, bounded, create-only, scoped and replayable."""
from contextlib import closing
from copy import deepcopy
from datetime import timedelta
import json
import sqlite3
from unittest.mock import patch

import pytest

from cloud_soc.detection.__main__ import main
from cloud_soc.detection.engine import detect_rule
from cloud_soc.detection.incremental import utc
from cloud_soc.detection.retrospective import run_retrospective
from cloud_soc.detection.worker import approved_rules
from cloud_soc.detection.profiles import RULE_IDS
from cloud_soc.main import make_alert_id, build_security_alert
from ruleset_fixtures import BASE, positive
from test_early_notices import Fixture

def fixture(identifier='WEB-404-001', delay=1000):
    hits=[]
    for row in positive(identifier):
        meta=row.pop('_cloud_soc_meta')
        row['cloud_soc']['normalized_at']=(BASE+timedelta(seconds=delay)).isoformat()
        hits.append({'_index':meta['index'],'_id':meta['document_id'],'_source':row})
    return Fixture(hits)

def context(fixture):
    def read(client,rule,job,limit):
        return [deepcopy(h) for h in fixture.hits]
    return read

def run(fixture,path,seconds=1200,**kwargs):
    return run_retrospective(fixture.client,state_path=path,start=BASE+timedelta(seconds=900),
        now=BASE+timedelta(seconds=seconds),scanner=fixture.scan,context_scanner=context(fixture),
        additional_rule_ids=['WEB-404-001'],**kwargs)

def state(path):
    with closing(sqlite3.connect(path)) as db:
        return json.loads(db.execute('SELECT body FROM review_state').fetchone()[0])

def test_late_404_creates_one_historical_alert_and_restart_does_not_duplicate(tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    before=deepcopy(f.hits)
    result=run(f,path)
    assert result['late_events']==20 and result['created']==1
    alerts=[body for (index,key),body in f.docs.items() if index=='security-alerts']
    assert len(alerts)==1 and alerts[0]['cloud_soc']['provenance']['review']['mode']=='retrospective'
    assert len(alerts[0]['cloud_soc']['provenance']['evidence'])==20
    first=deepcopy(f.docs)
    assert run(f,path,1300)['created']==0
    assert f.docs==first and f.hits==before
    assert not (tmp_path/'runtime.sqlite').exists()
    statuses=[call.kwargs for call in f.client.index.call_args_list]
    assert {c['id'] for c in statuses}=={'detector-retrospective'}

def test_existing_current_alert_is_never_modified_by_historical_review(tmp_path):
    f=fixture();rule=approved_rules(additional_rule_ids=['WEB-404-001'])[0]
    rows=[]
    for hit in f.hits:
        row=deepcopy(hit['_source']);row['_cloud_soc_meta']={'index':hit['_index'],'document_id':hit['_id']};rows.append(row)
    detection=detect_rule(rows,rule)[0];key=('security-alerts',make_alert_id(detection))
    f.docs[key]=build_security_alert(detection);before=deepcopy(f.docs[key])
    result=run(f,tmp_path/'retro.sqlite')
    assert result['existing']==1 and result['created']==0 and f.docs[key]==before
    assert 'review' not in f.docs[key]['cloud_soc']['provenance']

def test_later_page_failure_and_context_overflow_retain_checkpoint_and_retry(tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    with patch('cloud_soc.detection.retrospective.context',side_effect=RuntimeError('partial')):
        with pytest.raises(RuntimeError):
            run_retrospective(f.client,state_path=path,start=BASE+timedelta(seconds=900),
                now=BASE+timedelta(seconds=1200),scanner=f.scan,additional_rule_ids=['WEB-404-001'])
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT body FROM review_state').fetchall()==[]
    assert not any(index=='security-alerts' for index,key in f.docs)
    assert run(f,path)['created']==1
    old=state(path)
    with pytest.raises(ValueError):
        run(f,path,1300,lateness_seconds=901)
    assert state(path)==old

def test_missing_trigger_and_wrong_org_never_become_complete_context(tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    bad=deepcopy(f.hits)
    for h in bad:h['_source']['organization']['id']='another-tenant'
    with pytest.raises(RuntimeError):
        run_retrospective(f.client,state_path=path,start=BASE+timedelta(seconds=900),
            now=BASE+timedelta(seconds=1200),scanner=f.scan,context_scanner=lambda *a,**kw:bad,
            additional_rule_ids=['WEB-404-001'])
    assert not any(index=='security-alerts' for index,key in f.docs)

def test_newer_events_are_not_replayed_instead_of_the_live_worker(tmp_path):
    f=fixture(delay=500)
    for h in f.hits:h['_source']['cloud_soc']['normalized_at']=(BASE+timedelta(seconds=1000)).isoformat();h['_source']['@timestamp']=(BASE+timedelta(seconds=500)).isoformat()
    result=run(f,tmp_path/'retro.sqlite')
    assert result['late_events']==0 and result['created']==0

def test_live_database_and_early_notice_modes_are_refused(tmp_path):
    f=fixture();path=tmp_path/'existing.sqlite'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE runtime (body TEXT)');db.execute("INSERT INTO runtime VALUES('original')")
    path.chmod(0o600)
    before=path.read_bytes()
    with pytest.raises(ValueError,match='independent_state'):
        run(f,path)
    assert path.read_bytes()==before
    with patch('cloud_soc.detection.__main__.Elasticsearch') as es:
        assert main(['--retrospective'])==1
        assert main(['--retrospective','--state',str(tmp_path/'r.sqlite'),'--early-auth'])==1
        es.assert_not_called()

@pytest.mark.parametrize('identifier',RULE_IDS)
def test_all_real_rule_engines_support_bounded_late_context(identifier,tmp_path):
    f=fixture(identifier,delay=2000)
    rule=next(r for r in approved_rules(isolated_all=True) if r['id']==identifier)
    with patch('cloud_soc.detection.retrospective.approved_rules',return_value=[rule]):
        result=run_retrospective(f.client,state_path=tmp_path/'retro.sqlite',
            start=BASE+timedelta(seconds=1900),now=BASE+timedelta(seconds=2200),
            scanner=f.scan,context_scanner=context(f))
    assert result['created']==1
    alert=next(body for (index,key),body in f.docs.items() if index=='security-alerts')
    assert alert['rule']['id']==identifier and len(alert['cloud_soc']['provenance']['evidence'])==len(f.hits)

def test_late_success_arriving_before_failures_can_be_correlated_on_later_context(tmp_path):
    f=fixture('AUTH-SEQ-001',delay=2000);complete=deepcopy(f.hits)
    success=complete[-1];failures=complete[:-1]
    f.hits=[success];path=tmp_path/'retro.sqlite'
    def run_sequence(seconds):
        return run_retrospective(f.client,state_path=path,start=BASE+timedelta(seconds=1900),
            now=BASE+timedelta(seconds=seconds),scanner=f.scan,context_scanner=context(f),
            additional_rule_ids=['AUTH-SEQ-001'])
    assert run_sequence(2200)['created']==0
    for h in failures:h['_source']['cloud_soc']['normalized_at']=(BASE+timedelta(seconds=2230)).isoformat()
    f.hits=failures+[success]
    assert run_sequence(2300)['created']==1
    assert run_sequence(2400)['created']==0

def test_partial_input_page_commits_spool_without_advancing_discovery_checkpoint(tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    first=run(f,path,max_documents=20)
    assert first['events']==0 and first['created']==0
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM input_hits').fetchone()[0]==20
        assert db.execute('SELECT body FROM review_state').fetchall()==[]
    assert run(f,path,1300,max_documents=20)['created']==1

def test_context_limit_retains_work_and_cannot_publish_partial_alert(tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    with pytest.raises(RuntimeError):run(f,path,max_context_documents=19)
    assert not any(index=='security-alerts' for index,key in f.docs)
    assert run(f,path,max_context_documents=20)['created']==1

def test_alert_created_before_commit_failure_is_immutable_on_retry(tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    def fail_completed_status(**kwargs):
        if kwargs['document']['state']=='success':raise RuntimeError('delivery_failed')
    f.client.index.side_effect=fail_completed_status
    with pytest.raises(RuntimeError):run(f,path)
    old={key:deepcopy(body) for key,body in f.docs.items() if key[0]=='security-alerts'}
    assert len(old)==1
    f.client.index.side_effect=None
    assert run(f,path,1300)['existing']==1
    assert {key:body for key,body in f.docs.items() if key[0]=='security-alerts'}==old

@pytest.mark.parametrize('distance,expected', [(299, 0), (300, 1)])
def test_historical_cooldown_survives_restart_and_respects_exact_boundary(distance, expected, tmp_path):
    f=fixture();path=tmp_path/'retro.sqlite'
    assert run(f,path)['created']==1
    old=deepcopy(f.docs)
    for hit in f.hits:
        hit['_id']+='-later'
        hit['_source']['cloud_soc']['provenance']['raw']['id']+='-later'
        hit['_source']['@timestamp']=(utc(hit['_source']['@timestamp'])+timedelta(seconds=distance)).isoformat()
        hit['_source']['cloud_soc']['normalized_at']=(BASE+timedelta(seconds=1300)).isoformat()
    result=run(f,path,1500)
    assert result['created']==expected
    assert (result['cooldown_suppressed']>0)==(expected==0)
    assert all(f.docs[key]==body for key,body in old.items())

def test_historical_review_refuses_alert_alias_without_mutating_existing_documents(tmp_path):
    f=fixture();f.client.indices.get_mapping.side_effect=None
    f.client.indices.get_mapping.return_value={'unexpected-concrete-index':{}}
    with pytest.raises(RuntimeError):run(f,tmp_path/'retro.sqlite')
    assert not f.docs
