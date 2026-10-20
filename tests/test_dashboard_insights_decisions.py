"""Only decision/math and major new access paths; no live ingestion or broad suite."""
from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import Mock

import pytest
from cloud_soc.portal.insight_state import InsightStore, InsightError, report_state
from cloud_soc.portal.dashboard_insights import InsightReader, cloud_summary


@pytest.mark.parametrize(('age','expected'),[(0,'reporting'),(90,'reporting'),(91,'delayed'),(180,'delayed'),(181,'report_missing'),(-1,'unknown')])
def test_report_age_boundaries(age,expected):
    assert report_state(1000-age,1000,30)==expected


def test_device_identity_duplicates_rotation_and_revocation(tmp_path):
    now=[1900000000];store=InsightStore(tmp_path/'insights.sqlite',clock=lambda:now[0])
    request={'request_id':'one','organization':'org-a','label':'synthetic','interval':30,'days':1}
    key=store.register(request,'admin');stamp=datetime.fromtimestamp(now[0],timezone.utc).isoformat()
    report={'generation':key['generation'],'sequence':1,'generated_at':stamp,'collector':{'state':'running'}}
    assert store.heartbeat(key['credential'],report)['accepted']
    now[0]+=10
    assert store.heartbeat(key['credential'],report)['received_at']==1900000000
    with pytest.raises(InsightError,match='request_conflict'):store.register({**request,'organization':'org-b'},'admin')
    with pytest.raises(InsightError,match='already_delivered'):store.register(request,'admin')
    with pytest.raises(InsightError,match='sequence_conflict'):store.heartbeat(key['credential'],{**report,'collector':{'state':'error'}})
    rotated=store.change_device(key['id'],{'action':'rotate','version':1,'days':1},'admin')
    with pytest.raises(InsightError,match='authentication_failed'):store.heartbeat(key['credential'],report)
    assert store.heartbeat(rotated['credential'],{**report,'generation':rotated['generation']})['accepted']
    store.change_device(key['id'],{'action':'revoke','version':2},'admin')
    with pytest.raises(InsightError,match='authentication_failed'):store.heartbeat(rotated['credential'],{**report,'generation':rotated['generation'],'sequence':2})
    assert key['credential'] not in json.dumps(store.fleet())
    assert key['credential'].split('.')[1].encode() not in (tmp_path/'insights.sqlite').read_bytes()


def test_full_cloud_counts_are_not_latest_fifty_and_account_identity_is_scoped():
    rows=[{'source_kind':'aws_cloudtrail','cloud_provider':'aws','organization':'org-a' if i<60 else 'org-b',
           'cloud_account':'same','cloud_service':'iam','action':'CreateUser','interpretation':{'status':'recognized'}} for i in range(70)]
    result=cloud_summary(rows)
    assert result['recognized']==70 and len(result['rows'])==50
    assert result['iam']['count']==70
    assert [r['count'] for r in result['accounts']]==[60,10]


def test_scanner_rejects_partial_failure_and_closes_pit():
    reader=Mock();reader.allowed_indices=['soc-cloud-aws-one'];reader.organizations=('org-a',)
    reader.indices.return_value=reader.allowed_indices
    reader.client.open_point_in_time.return_value={'id':'synthetic-pit'}
    reader.body.return_value={'query':{'bool':{'filter':[]}}}
    reader.client.search.return_value={'timed_out':True}
    from cloud_soc.portal.log_contract import parse_filters
    f=parse_filters([])
    with pytest.raises(InsightError,match='incomplete_query'):InsightReader(reader).scan(f,'cloud',{})
    reader.close.assert_called_once_with('synthetic-pit')


def test_heartbeat_api_does_not_bypass_browser_admin_auth_or_tls(tmp_path):
    from cloud_soc.portal.app import create_app
    from werkzeug.security import generate_password_hash
    settings={'STATE_DIR':tmp_path,'AGENT_SOURCE':Path(__file__).resolve().parents[1]/'deploy/agents',
              'CA_BYTES':b'synthetic','ENDPOINT':'https://es.test:9200','PUBLIC_URL':'https://soc.test',
              'ADMIN_USER':'admin','ADMIN_HASH':generate_password_hash('synthetic-password'),'ES_URL':'https://es.test:9200',
              'ES_PASSWORD':'synthetic'}
    app=create_app(settings,issuer=Mock());client=app.test_client()
    assert client.post('/api/dashboard-devices',base_url='https://soc.test',json={}).status_code==401
    assert client.post('/api/dashboard-heartbeat',base_url='https://soc.test',json={},headers={'X-Cloud-SOC':'portal'}).status_code==403
    assert client.post('/api/dashboard-heartbeat',base_url='http://soc.test',json={},headers={'X-Cloud-SOC':'heartbeat'}).status_code==503
    assert client.post('/api/dashboard-heartbeat',base_url='https://soc.test',json={},headers={'X-Cloud-SOC':'heartbeat'}).status_code==401


def policy():
    return {'id':'policy-one','organization':'org-a','version':'v1','approved':True,'purpose':'Synthetic assessment of defined controls',
            'items':[{'id':k,'title':k,'weight':weight,'criterion':'Evidence meets the stated control','rationale':'Explicit importance of this control'} for k,weight in [('one',1),('two',3)]]}


def assessment():
    return {'id':'assessment-one','organization':'org-a','provider':'aws','account':'123456789012','policy_id':'policy-one',
            'observed_at':'2026-10-01T00:00:00Z','expires_at':'2026-10-31T00:00:00Z','source':'operator_evidence_review',
            'items':[{'id':'one','state':'fail','evidence':'reference-one'},{'id':'two','state':'pass','evidence':'reference-two'}]}


def evaluation_run():
    return {'id':'run-one','organization':'org-a','kind':'rule','status':'complete','started_at':'2026-10-01T00:00:00Z',
            'completed_at':'2026-10-01T00:01:00Z','rule_id':'AUTH-001','rule_version':'v1','code_revision':'code-one',
            'input_digest':'a'*64,'scenario_revision':'v1','scope':'synthetic_scenarios','cases':[
                {'id':'tp','expected':True,'verdict':'alert','evidence':'positive-input-one'},
                {'id':'fn','expected':True,'verdict':'no_alert','evidence':'positive-input-two'},
                {'id':'fp','expected':False,'verdict':'alert','evidence':'negative-input-one'},
                {'id':'tn','expected':False,'verdict':'no_alert','evidence':'negative-input-two'}]}


def test_score_uses_weights_and_missing_or_expired_data_is_not_zero():
    from cloud_soc.portal.insight_metrics import assessment_score
    now=datetime(2026,10,21,tzinfo=timezone.utc)
    scored=assessment_score(policy(),assessment(),now)
    assert scored['score']==25 and scored['coverage_percent']==100
    unknown=assessment();unknown['items'][1]['state']='unknown'
    incomplete=assessment_score(policy(),unknown,now)
    assert incomplete['score'] is None and incomplete['coverage_percent']==25
    assert assessment_score(policy(),{**assessment(),'items':assessment()['items'][:1]},now)['score'] is None
    assert assessment_score(policy(),assessment(),datetime(2026,11,1,tzinfo=timezone.utc))['score'] is None
    with pytest.raises(InsightError,match='scope_mismatch'):
        assessment_score(policy(),{**assessment(),'organization':'org-b'},now)


def test_exempt_controls_cannot_manufacture_a_zero_score():
    from cloud_soc.portal.insight_metrics import assessment_score
    body=assessment()
    for item in body['items']:item.update(state='exempt',exception_reason='Approved exception until assessment expiry')
    assert assessment_score(policy(),body,datetime(2026,10,21,tzinfo=timezone.utc))['score'] is None


def test_evaluation_formula_and_failed_runs_are_explicitly_separate():
    from cloud_soc.portal.insight_metrics import evaluation_metrics
    run=evaluation_run();value=evaluation_metrics([run])
    assert (value['TP'],value['FN'],value['FP'],value['TN'])==(1,1,1,1)
    assert value['precision']==50 and value['recall']==50
    failed=evaluation_metrics([{**run,'status':'failed'}])
    assert failed['precision'] is None and failed['recall'] is None
    assert failed['failed_runs']==1 and failed['excluded_cases']==4
    only_normal=evaluation_metrics([{**run,'cases':[run['cases'][-1]]}])
    assert only_normal['precision'] is None and only_normal['recall'] is None


def test_evaluation_revisions_and_tenants_are_not_mixed(tmp_path):
    from cloud_soc.portal.insight_metrics import evaluation_summary,validate_evaluation
    store=InsightStore(tmp_path/'insights.sqlite')
    for key,org,digest in [('one','org-a','a'),('two','org-a','b'),('three','org-b','a')]:
        store.put_record('evaluation',{**evaluation_run(),'id':key,'organization':org,'input_digest':digest*64},'operator',validate_evaluation)
    reply=evaluation_summary(store,('org-a',),[('start','2026-10-01T00:00:00Z'),('end','2026-10-02T00:00:00Z')])
    assert reply['run_total']==2 and len(reply['groups'])==2
    assert all(g['organization']=='org-a' for g in reply['groups'])
    with pytest.raises(InsightError,match='record_conflict'):
        store.put_record('evaluation',{**evaluation_run(),'id':'one','code_revision':'changed'},'operator',validate_evaluation)


def test_geographic_denominators_and_special_addresses(monkeypatch,tmp_path):
    import sys
    from types import SimpleNamespace
    from cloud_soc.portal.insight_metrics import geographic
    from cloud_soc.portal.log_contract import parse_filters
    class Geo:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def metadata(self):return SimpleNamespace(build_epoch=int(datetime.now(timezone.utc).timestamp())-60,database_type='GeoLite2-Country')
        def get(self,ip):return {'country':{'iso_code':'US'}} if ip=='8.8.8.8' else {}
    monkeypatch.setitem(sys.modules,'maxminddb',SimpleNamespace(open_database=lambda *a,**k:Geo(),MODE_MMAP=1))
    rows=[{'reference':{'index':'soc-host-raw-one','id':str(i)},'source_kind':'generic_web_access',
           'source_ip':ip,'interpretation':{'status':'recognized','fields':{}}} for i,ip in enumerate(['8.8.8.8','1.1.1.1','127.0.0.1','224.0.0.1',None])]
    reader=Mock();reader.dataset.return_value=(rows,'ok',parse_filters([]),{},0)
    path=tmp_path/'country.mmdb';path.write_bytes(b'synthetic-placeholder-not-a-real-db')
    result=geographic(reader,[],path)
    assert result['total']==5 and result['located']==1 and result['public']==2
    assert result['internal']==2 and result['missing_ip']==1 and result['unknown']==1
    assert result['coverage_percent']==20 and result['public_coverage_percent']==50


def test_database_only_restore_does_not_revive_report_credentials(tmp_path):
    from cloud_soc.portal.packages import PackageStore
    from cloud_soc.portal.backup import backup,restore
    now=1900000000;source=tmp_path/'portal';source.mkdir()
    PackageStore(source,Path(__file__).resolve().parents[1]/'deploy/agents',b'synthetic','https://es.test')
    store=InsightStore(source/'dashboard-insights.sqlite',clock=lambda:now)
    key=store.register({'request_id':'one','organization':'org-a','label':'synthetic','interval':30,'days':1},'operator')
    report=backup(source,tmp_path/'backup');assert report['format']==5
    assert 'dashboard-report-auth.key' not in [f['name'] for f in report['files']]
    restore(tmp_path/'backup',tmp_path/'restored')
    restored=InsightStore(tmp_path/'restored/dashboard-insights.sqlite',clock=lambda:now)
    assert restored.fleet()['rows'][0]['state']=='credential_reset_required'
    with pytest.raises(InsightError,match='authentication_failed'):
        restored.heartbeat(key['credential'],{'generation':key['generation'],'sequence':1,
            'generated_at':datetime.fromtimestamp(now,timezone.utc).isoformat(),'collector':{'state':'running'}})


def test_new_read_api_scopes_records_and_denies_viewer_management(tmp_path):
    from cloud_soc.portal.app import create_app
    from cloud_soc.portal.insight_metrics import validate_evaluation
    from cloud_soc.portal.auth import COOKIE
    from werkzeug.security import generate_password_hash
    hashed=generate_password_hash('synthetic-pass',method='pbkdf2:sha256:1000')
    users=tmp_path/'users.json';users.write_text(json.dumps({'admin':{'role':'admin','password_hash':hashed},'reader':{'role':'viewer','password_hash':hashed}}));users.chmod(0o600)
    settings={'STATE_DIR':tmp_path/'state','AGENT_SOURCE':Path(__file__).resolve().parents[1]/'deploy/agents','CA_BYTES':b'synthetic',
              'ENDPOINT':'https://es.test:9200','PUBLIC_URL':'https://soc.test','ADMIN_USER':'admin','ADMIN_HASH':hashed,
              'ES_URL':'https://es.test:9200','ES_PASSWORD':'synthetic','USERS_FILE':str(users),
              'LOG_ACCESS_POLICY':{'version':1,'protected_source_enabled':False,'admin_source_organizations':[],
                                  'users':[{'username':'reader','password_hash':hashed,'role':'viewer','organizations':['org-a']}]}}
    app=create_app(settings,issuer=Mock());store=app.extensions['insights']
    for org in ('org-a','org-b'):store.put_record('evaluation',{**evaluation_run(),'id':org,'organization':org},'operator',validate_evaluation)
    client=app.test_client();token=app.extensions['sessions'].login('reader','synthetic-pass');client.set_cookie(COOKIE,token,domain='soc.test')
    reply=client.get('/api/dashboard-data/evaluation?start=2026-10-01T00:00:00Z&end=2026-10-02T00:00:00Z',base_url='https://soc.test')
    assert reply.status_code==200 and reply.json['run_total']==1 and reply.json['can_manage'] is False
    assert 'org-b' not in reply.get_data(as_text=True)
    assert client.get('/api/dashboard-data/fleet',base_url='https://soc.test').status_code==403
    for asset in ('dashboard-insights.js','dashboard-insight-metrics.js','assets/world-countries-110m.json'):
        assert client.get('/'+asset,base_url='https://soc.test').status_code==200
    assert client.post('/api/dashboard-records/policy',base_url='https://soc.test',json=policy(),headers={'X-Cloud-SOC':'portal'}).status_code==403


def test_cloud_alert_filter_is_applied_before_total_and_top_fifty():
    from cloud_soc.portal.operations import Operations
    client=Mock();client.options.return_value=client
    client.indices.resolve_index.return_value={'indices':[{'name':'security-alerts'}]}
    client.field_caps.return_value={'fields':{'@timestamp':{'date':{'searchable':True,'aggregatable':True}}}}
    client.search.return_value={'timed_out':False,'_shards':{'failed':0},'hits':{'total':{'value':1,'relation':'eq'},
      'hits':[{'_id':'a'*64,'_source':{'@timestamp':'2026-10-01T00:01:00Z','organization':{'id':'org-a'},'rule':{'id':'AWS-001'}}}]},
      'aggregations':{'trend':{'buckets':[{'key_as_string':'2026-10-01T00:00:00Z','doc_count':1}]}}}
    reply=Operations(client,organizations=('org-a',)).series(['security-alerts'],'@timestamp','2026-10-01T00:00:00Z','2026-10-01T01:00:00Z','5m',alerts=True,cloud_only=True)
    assert reply['count']==1
    query=json.dumps(client.search.call_args.kwargs['query'])
    assert 'AWS-' in query and 'OCI-' in query and 'org-a' in query and 'range' in query


def test_record_save_failure_is_not_reported_as_success(tmp_path):
    store=InsightStore(tmp_path/'insights.sqlite')
    with store.connect() as db:db.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON insight_audit BEGIN SELECT RAISE(ABORT,'synthetic'); END")
    from cloud_soc.portal.insight_metrics import validate_evaluation
    with pytest.raises(InsightError,match='state_unavailable'):
        store.put_record('evaluation',evaluation_run(),'operator',validate_evaluation)
    assert not store.records('evaluation',None)


def test_redacted_or_missing_accounts_are_not_counted_as_distinct_accounts():
    row={'source_kind':'aws_cloudtrail','cloud_provider':'aws','organization':'org-a','cloud_account':'123456789012','cloud_service':'iam','action':'CreateUser','interpretation':{'status':'recognized'}}
    result=cloud_summary([row,{**row,'cloud_account':'[REDACTED]'},{**row,'cloud_account':None}])
    assert result['recognized']==3 and len(result['accounts'])==1
    assert result['unidentified_account_events']==2
