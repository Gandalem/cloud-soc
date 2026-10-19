"""Manual MVP acceptance: real engine/SQLite, isolated Portal, no external services."""
from copy import deepcopy
import hashlib
import json
import sqlite3

import pytest
import yaml

from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.profiles import FILES, catalog
from cloud_soc.detection.rule_loader import PROJECT_ROOT, load_rules
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.rule_management import RuleDraftStore, RuleError, validate_draft
from test_integration_security import make_session_portal, login
from security_mall_fixtures import mall

ADMIN = LogPrincipal('admin', 'admin', None, ())
SCOPED = LogPrincipal('scope-admin', 'admin', ('synthetic',), ())


def rule():
    return {'id':'CUSTOM-AUTH-001','type':'threshold','name':'Repeated login failures',
        'description':'Same IP fails authentication repeatedly','enabled':True,'severity':'medium',
        'group_by':['organization.id','source.ip'],'threshold':{'count':10},'time_window':{'seconds':300},
        'cooldown':{'seconds':900},'conditions':[
            {'field':'organization.id','operator':'equals','value':'synthetic'},
            {'field':'event.category','operator':'contains','value':'authentication'},
            {'field':'event.outcome','operator':'equals','value':'failure'}],
        'alert':{'title':'Repeated failures','message':'Review evidence; compromise is not confirmed',
                 'category':'authentication','tags':['manual']}}


def text(value=None):
    return yaml.safe_dump({'rules':[value or rule()]},sort_keys=False)


@pytest.fixture
def store(tmp_path):
    return RuleDraftStore(tmp_path/'cases.sqlite', ('synthetic','foreign'))


def create(store, value=None):
    return store.create({'organization':'synthetic','yaml':text(value),'intent':'Ten failures in five minutes'}, ADMIN)


def act(store, row, action, principal=ADMIN):
    return store.action(row['id'],action,{k:row[k] for k in ('version','content_hash')},principal)


def test_real_engine_compatibility_approval_export_and_no_active_change(store, tmp_path):
    before={f:hashlib.sha256((PROJECT_ROOT/'rules'/f).read_bytes()).hexdigest() for f in FILES}
    row=create(store);assert row['status']=='draft' and not row['active']
    with pytest.raises(RuleError,match='규칙') as error:store.export(row['id'],ADMIN)
    assert error.value.code=='approval_required'
    row=act(store,row,'validate');assert row['status']=='validated' and row['validation']['engine_schema']
    assert not row['validation']['detection_verified']
    with pytest.raises(RuleError) as error:act(store,row,'apply')
    assert error.value.code=='approval_required' and store.detail(row['id'],ADMIN)==row
    with pytest.raises(RuleError):store.export(row['id'],ADMIN)
    row=act(store,row,'approve');assert row['status']=='approved' and row['approved_by']=='admin' and row['approved_at']
    assert row['application_state']=='awaiting_application' and not row['active']
    row=act(store,row,'apply');assert row['application_state']=='pending_deployment' and not row['active']
    approved=store.export(row['id'],ADMIN);assert hashlib.sha256(approved.encode()).hexdigest()==row['content_hash']
    p=tmp_path/'approved.yml';p.write_text(approved,encoding='utf-8')
    loaded=load_rules(p);events=[mall(i+1,seconds=i,organization='synthetic') for i in range(10)]
    assert len(detect_events(events,loaded))==1
    assert detect_events(events[:9],loaded)==[]
    other=deepcopy(events)
    for e in other:e['organization']['id']='foreign'
    assert detect_events(other,loaded)==[]
    assert before=={f:hashlib.sha256((PROJECT_ROOT/'rules'/f).read_bytes()).hexdigest() for f in FILES}
    assert len(catalog())==19
    actions=[h['action'] for h in row['history']];assert actions==['created','validate','approve','apply']
    assert all(h['content_hash']==row['content_hash'] for h in row['history'])
    assert RuleDraftStore(store.path,store.organizations).detail(row['id'],ADMIN)['status']=='approved'


@pytest.mark.parametrize('change', ['id','field','operator','threshold','time','extra','condition_extra','org','group','type','enabled','missing'])
def test_unsupported_schema_and_bounds_rejected(change):
    r=rule()
    if change=='id':r['id']='AUTH-001'
    elif change=='field':r['conditions'][0]['field']='message'
    elif change=='operator':r['conditions'][0]['operator']='execute'
    elif change=='threshold':r['threshold']['count']=True
    elif change=='time':r['time_window']['seconds']=864000
    elif change=='extra':r['command']='echo unsafe'
    elif change=='condition_extra':r['conditions'][0]['script']='unsafe'
    elif change=='org':r['conditions'][0]['value']='foreign'
    elif change=='group':r['group_by']=['source.ip']
    elif change=='type':r['type']='sequence'
    elif change=='enabled':r['enabled']=False
    else:del r['description']
    with pytest.raises(RuleError):validate_draft(text(r),'synthetic',{'AUTH-001'})


@pytest.mark.parametrize('raw', ['rules: [', '!!python/object/apply:os.system [CANARY]',
    'rules: &a [*a]', 'rules: []\nrules: []', 'rules:\n  - id: X\n    id: Y',
    'rules: ['*30+']'*30])
def test_unsafe_yaml_and_duplicates_rejected_without_echo(raw):
    with pytest.raises(RuleError) as error:validate_draft(raw,'synthetic',set())
    assert 'CANARY' not in str(error.value)


def test_validate_failure_keeps_draft_and_approval_blocked(store):
    row=store.create({'organization':'synthetic','yaml':'rules: [','intent':''},ADMIN)
    row=act(store,row,'validate');assert row['status']=='draft' and not row['validation']['valid']
    assert json.loads(row['history'][-1]['result'])['validation']['valid'] is False
    for action in ('approve','apply'):
        with pytest.raises(RuleError):act(store,row,action)


def test_duplicate_id_rechecked_at_approval_and_stale_hash_blocked(store):
    one=act(store,create(store),'validate');two=act(store,create(store),'validate')
    act(store,one,'approve')
    with pytest.raises(RuleError) as error:act(store,two,'approve')
    assert error.value.code=='rule_id_unavailable'
    with pytest.raises(RuleError) as error:
        store.action(two['id'],'approve',{'version':two['version'],'content_hash':'0'*64},ADMIN)
    assert error.value.code=='rule_draft_changed'


def test_rejection_and_unauthorized_principals(store):
    row=act(store,create(store),'reject');assert row['status']=='rejected'
    with pytest.raises(RuleError):act(store,row,'approve')
    with pytest.raises(RuleError):store.export(row['id'],ADMIN)
    for principal in (LogPrincipal('view','viewer',('synthetic',),()),LogPrincipal('analyst','investigator',('synthetic',),())):
        for op in (lambda:store.listing(principal),lambda:store.detail(row['id'],principal),lambda:act(store,row,'approve',principal)):
            with pytest.raises(RuleError) as error:op()
            assert error.value.status==403
    foreign=store.create({'organization':'foreign','yaml':text(),'intent':''},ADMIN)
    for ident in (foreign['id'],'f'*32):
        with pytest.raises(RuleError) as error:store.detail(ident,SCOPED)
        assert (error.value.code,error.value.status)==('rule_draft_missing',404)
    assert all(r['organization']=='synthetic' for r in store.listing(SCOPED)['drafts'])


def test_sqlite_failure_rolls_back_status_and_audit(store):
    row=act(store,create(store),'validate')
    with store.connect() as db:
        db.execute("CREATE TRIGGER reject_audit BEFORE INSERT ON rule_history BEGIN SELECT RAISE(ABORT,'test'); END")
    with pytest.raises(sqlite3.IntegrityError):act(store,row,'approve')
    assert store.detail(row['id'],ADMIN)==row


def test_content_tampering_cannot_export_or_apply(store):
    row=act(store,act(store,create(store),'validate'),'approve')
    with store.connect() as db:db.execute('UPDATE rule_drafts SET yaml=yaml||? WHERE id=?', ('\n# changed',row['id']))
    for op in (lambda:store.export(row['id'],ADMIN),lambda:act(store,row,'apply')):
        with pytest.raises(RuleError) as error:op()
        assert error.value.code=='draft_integrity_failed'


def test_existing_portal_admin_csrf_and_other_org_access(tmp_path):
    app,monitor,settings,_=make_session_portal(tmp_path)
    http,headers=login(app,'admin')
    assert http.get('/settings-rules.html').status_code==200
    assert 'settings-rules.html' in http.get('/api/auth/me').json['navigation']
    info=http.get('/api/settings/rules').json;assert info['ai']=='not_connected'
    body={'organization':'synthetic','yaml':text(),'intent':'Repeated failure detection'}
    assert http.post('/api/settings/rules',json=body,headers={'X-Cloud-SOC':'portal'}).status_code==403
    result=http.post('/api/settings/rules',json=body,headers=headers);assert result.status_code==201
    row=result.json
    assert http.get('/api/settings/rules/'+row['id']+'/export').status_code==409
    for action in ('validate','approve','apply'):
        response=http.post('/api/settings/rules/'+row['id']+'/'+action,json={k:row[k] for k in ('version','content_hash')},headers=headers)
        assert response.status_code==200;row=response.json
    exported=http.get('/api/settings/rules/'+row['id']+'/export');assert exported.status_code==200
    assert 'CUSTOM-AUTH-001' in exported.text and row['application_state']=='pending_deployment'
    for user in ('view','investigate','other'):
        client,h=login(app,user)
        for path in ('/settings-rules.html','/settings-rules.js','/api/settings/rules','/api/settings/rules/'+row['id'],
                     '/api/settings/rules/'+row['id']+'/export'):
            assert client.get(path).status_code==403
        assert client.post('/api/settings/rules/'+row['id']+'/approve',json={k:row[k] for k in ('version','content_hash')},headers=h).status_code==403
    assert http.get('/api/settings/rules?organization=foreign').status_code==400
    assert http.get('/api/settings/rules/'+row['id']+'?index=other').status_code==400
    assert not any(c[0] in ('index','update','delete','bulk') for c in monitor.method_calls)
