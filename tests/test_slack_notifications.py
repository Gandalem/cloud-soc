from contextlib import closing
from copy import deepcopy
import json
import logging
import socket
import sqlite3
from unittest.mock import Mock, patch

import pytest

from cloud_soc.notifications.store import SlackStore
from cloud_soc.notifications.transport import Result, SlackError, addresses, send, validate_url
from cloud_soc.notifications.worker import INDICES, Source, deliver, event, scan

URL = 'https://hooks.slack.com/services/T00000000/B00000000/SYNTHETIC_TOKEN_1234567890'


def configured(tmp_path, enabled=True):
    clock = [1000.0]
    store = SlackStore(tmp_path/'notifications', clock=lambda: clock[0])
    store.save({'revision': 0, 'webhook_url': URL, 'enabled': enabled, 'minimum_severity': 'high'}, check_address=lambda: None)
    return store, clock


def final(seq, identifier=None, rule='FUTURE-RULE-205', severity='high'):
    return {'_seq_no': seq, '_id': identifier or str(seq), '_source': {'@timestamp': '2020-01-01T00:00:00Z',
        'rule': {'id': rule}, 'cloud_soc': {'severity': severity, 'event_count': 10}}}


def notice(seq, revision=1, state='initial', **extra):
    return {'_seq_no': seq, '_id': 'immutable-'+str(seq), '_source': {
        'notice': {'id': 'logical-notice', 'revision': revision, 'state': state},
        'body': {'rule_id': 'FUTURE-NOTICE-205', 'severity': 'high', 'observed_count': 10, **extra}}}


class MemorySource:
    def __init__(self):
        self.docs={INDICES[0]: {0: []}, INDICES[1]: {0: []}};self.uuid='original-index';self.calls=[]
    def shards(self,index):return [(self.uuid,shard) for shard in self.docs[index]]
    def page(self,index,shard,after,baseline=False):
        self.calls.append((index,shard,after,baseline))
        rows=self.docs[index][shard]
        return deepcopy(rows[-1:] if baseline else [row for row in rows if row['_seq_no']>after][:100])


@pytest.mark.parametrize('url', ['http://hooks.slack.com/services/T00000000/B00000000/x',
    URL+'?token=secret',URL+'#fragment',URL.replace('hooks.slack.com','hooks.slack.com.evil.test'),
    URL.replace('hooks.slack.com','127.0.0.1'),URL.replace('hooks.slack.com','[::1]'),
    URL.replace('hooks.slack.com','user@hooks.slack.com'),URL.replace('hooks.slack.com','hooks.slack.com:443'),
    URL.replace('/services/','/%73ervices/'),URL.replace('hooks.slack.com','hooks.slack.com.'),
    '\n'+URL,URL+'\r\n', URL.replace('https://','https:\\\\'), URL.replace('hooks.slack.com','hooks.slack-gov.com')])
def test_only_exact_supported_official_webhook_is_allowed(url):
    with pytest.raises(SlackError,match='invalid_slack_webhook'):validate_url(url)
    assert validate_url(URL)==URL


@pytest.mark.parametrize('ip', ['127.0.0.1','10.0.0.1','192.168.1.1','169.254.169.254','0.0.0.0','::1','fc00::1','fe80::1','::ffff:127.0.0.1','224.0.0.1'])
def test_dns_private_mixed_or_ipv6_destinations_fail_closed(ip):
    rows=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),
          (socket.AF_INET6 if ':' in ip else socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))]
    with pytest.raises(SlackError,match='slack_address_unavailable'):addresses(lambda *_,**__: rows)


@pytest.mark.parametrize('status,body,retry,expected',[(200,b'ok',None,'sent'),(200,b'not_ok',None,'permanent'),
    (301,b'https://10.0.0.1',None,'permanent'),(400,b'PRIVATE_ERROR_BODY',None,'permanent'),
    (403,b'token_revoked',None,'permanent'),(404,b'no_service',None,'permanent'),
    (429,b'limited','75','retry'),(429,b'limited','9999999','permanent'),(503,b'error',None,'retry')])
def test_http_results_redact_bodies_never_redirect_and_honor_retry_after(status,body,retry,expected,caplog):
    caplog.set_level(logging.DEBUG)
    conn=Mock();response=conn.getresponse.return_value
    response.status=status;response.read.return_value=body;response.getheader.return_value=retry or ''
    with patch('cloud_soc.notifications.transport.PinnedHTTPS',return_value=conn):result=send(URL,{'text':'test'})
    assert result.outcome==expected and conn.request.call_count==1
    assert URL not in caplog.text and 'PRIVATE_ERROR_BODY' not in str(result)
    if status==429 and retry=='75':assert result.retry_after==75


def test_network_failure_before_write_retries_but_ambiguous_post_is_held():
    conn=Mock();conn.connect.side_effect=OSError(URL)
    with patch('cloud_soc.notifications.transport.PinnedHTTPS',return_value=conn):assert send(URL,{}).outcome=='retry'
    conn.connect.side_effect=None;conn.getresponse.side_effect=TimeoutError(URL)
    with patch('cloud_soc.notifications.transport.PinnedHTTPS',return_value=conn):assert send(URL,{}).outcome=='unknown'


def test_encrypted_storage_redacted_status_revision_delete_and_test_limit(tmp_path):
    store,clock=configured(tmp_path)
    assert store.status()['minimum_severity']=='high' and store.status()['enabled']
    for p in store.directory.iterdir():
        if p.is_file():assert URL.encode() not in p.read_bytes() and b'SYNTHETIC_TOKEN' not in p.read_bytes()
    assert URL not in json.dumps(store.status())
    test=store.test();assert test['status']=='queued'
    with pytest.raises(SlackError) as error:store.test()
    assert error.value.status==429
    clock[0]+=31;store.test()
    with pytest.raises(SlackError) as error:store.delete(0)
    assert error.value.status==409
    store.delete(1)
    assert not store.status()['configured'] and not store.status()['enabled']
    assert store.status()['deliveries']=={'cancelled':2}
    assert URL not in json.dumps(store.status())


def test_baselines_all_shards_skips_old_alerts_and_sends_any_future_rule_once(tmp_path):
    store,clock=configured(tmp_path);source=MemorySource()
    source.docs[INDICES[0]]={0:[final(100)],1:[final(2,identifier='other-old')]}
    scan(store,source);assert not store.status()['deliveries']
    source.docs[INDICES[0]][0]+=[final(101,rule='ANY-NEW-RULE'),final(102,severity='low')]
    source.docs[INDICES[0]][1]+=[final(3,identifier='new-on-lower-sequence-shard')]
    scan(store,source);scan(store,source)
    assert store.status()['deliveries']=={'queued':2}
    sender=Mock(return_value=Result('sent','slack_accepted'))
    deliver(store,sender=sender);clock[0]+=2;deliver(store,sender=sender)
    assert sender.call_count==2 and store.status()['deliveries']=={'sent':2}
    assert 'ANY-NEW-RULE' in json.dumps([call.args[1] for call in sender.call_args_list])
    source.docs[INDICES[0]][0]+=[final(103,identifier='101',rule='ANY-NEW-RULE')]
    scan(store,source);clock[0]+=2;deliver(store,sender=sender)
    assert sender.call_count==2


def test_notice_revisions_states_and_linked_final_are_not_double_sent(tmp_path):
    store,clock=configured(tmp_path);source=MemorySource();scan(store,source)
    source.docs[INDICES[1]][0]+=[notice(1),notice(2),notice(3,revision=2,state='delayed'),
        notice(4,revision=3,state='confirmed',final_alert_id='real-final')]
    source.docs[INDICES[0]][0]+=[final(1,identifier='real-final')]
    scan(store,source)
    assert store.status()['deliveries']=={'queued':3}
    sender=Mock(return_value=Result('sent','slack_accepted'))
    for _ in range(3):deliver(store,sender=sender);clock[0]+=2
    assert sender.call_count==3
    assert sum('최종 경보' in c.args[1]['text'] for c in sender.call_args_list)==1


def test_unconfigured_and_off_do_not_query_es_and_test_is_explicit(tmp_path):
    source=Mock();store=SlackStore(tmp_path/'notifications')
    assert scan(store,source)=='disabled';source.shards.assert_not_called()
    with pytest.raises(SlackError):store.test()
    store,_=configured(tmp_path,False)
    assert scan(store,source)=='disabled';source.shards.assert_not_called()
    store.test();sender=Mock(return_value=Result('sent','slack_accepted'));deliver(store,sender=sender)
    sender.assert_called_once()


def test_retry_429_permanent_and_crash_restart_do_not_reset_detection_state(tmp_path):
    preserved=tmp_path/'existing.sqlite'
    with closing(sqlite3.connect(preserved)) as db:db.execute('create table checkpoint(value)');db.execute('insert into checkpoint values(987)');db.commit()
    before=preserved.read_bytes();store,clock=configured(tmp_path);store.test()
    sender=Mock(return_value=Result('retry','slack_rate_limited',75))
    deliver(store,sender=sender);clock[0]+=74;deliver(store,sender=sender);assert sender.call_count==1
    clock[0]+=2;sender.return_value=Result('permanent','slack_rejected');deliver(store,sender=sender)
    clock[0]+=400;deliver(store,sender=sender);assert sender.call_count==2
    store.test()
    with pytest.raises(KeyboardInterrupt):deliver(store,sender=Mock(side_effect=KeyboardInterrupt()))
    fresh=SlackStore(store.directory,clock=lambda:clock[0]);fresh.recover()
    assert fresh.status()['deliveries']=={'permanent':1,'unknown':1}
    assert preserved.read_bytes()==before


def test_index_replacement_or_partial_search_never_silently_resets_a_cursor(tmp_path):
    store,_=configured(tmp_path);source=MemorySource();scan(store,source);source.uuid='replacement'
    with pytest.raises(SlackError,match='notification_index_or_scope_changed'):scan(store,source)
    client=Mock();client.search.return_value={'timed_out':True}
    with pytest.raises(SlackError,match='notification_search_incomplete'):Source(client).page(INDICES[0],0,0)


def test_risk_band_is_preferred_and_old_notice_revisions_do_not_resend(tmp_path):
    hit=final(1,severity='medium');hit['_source']['cloud_soc']['risk_level']='high'
    assert event(INDICES[0],hit)['severity']=='high'
    store,clock=configured(tmp_path);source=MemorySource();scan(store,source)
    source.docs[INDICES[1]][0]+=[notice(1,revision=3,state='delayed'),notice(2,revision=1,state='initial')]
    scan(store,source);assert store.status()['deliveries']=={'queued':1}


def test_numeric_dns_address_is_pinned_and_hostname_used_only_for_tls():
    from cloud_soc.notifications.transport import PinnedHTTPS
    address=('8.8.8.8',443);raw=Mock();context=Mock();context.verify_mode=2;context.check_hostname=True
    with patch('cloud_soc.notifications.transport.addresses',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',address)]),patch('cloud_soc.notifications.transport.socket.socket',return_value=raw):
        conn=PinnedHTTPS('hooks.slack.com',timeout=5,context=context);conn.connect()
    raw.connect.assert_called_once_with(address)
    context.wrap_socket.assert_called_once_with(raw,server_hostname='hooks.slack.com')


def test_configuration_change_cancels_pending_and_never_uses_the_old_webhook(tmp_path):
    store,clock=configured(tmp_path);store.test()
    changed=URL[:-1]+'9'
    store.save({'revision':1,'webhook_url':changed,'enabled':True,'minimum_severity':'critical'},check_address=lambda:None)
    sender=Mock(return_value=Result('sent','slack_accepted'));deliver(store,sender=sender);sender.assert_not_called()
    clock[0]+=31;store.test();deliver(store,sender=sender)
    assert sender.call_args.args[0]==changed


def test_retry_budget_is_bounded_and_missing_encryption_key_is_not_rotated(tmp_path):
    store,clock=configured(tmp_path);store.test();sender=Mock(return_value=Result('retry','slack_temporarily_unavailable',2))
    for _ in range(10):deliver(store,sender=sender);clock[0]+=4000
    assert sender.call_count==8 and store.status()['deliveries']=={'permanent':1}
    store.test();(store.directory/'slack.key').unlink();deliver(store,sender=sender)
    assert not (store.directory/'slack.key').exists() and store.status()['deliveries']=={'permanent':2}


def test_partial_notification_migration_reuses_new_read_only_key_and_preserves_configuration(tmp_path):
    from test_deployment_parity import FakeSetup
    from cloud_soc.deployment.migrations import notification_prerequisites
    from cloud_soc.notifications.worker import READ_ROLE
    client=FakeSetup();(tmp_path/'keys').mkdir();folder=tmp_path/'notifications'
    with patch('cloud_soc.notifications.store.SlackStore.status',side_effect=RuntimeError('isolated setup failure')):
        with pytest.raises(RuntimeError):notification_prerequisites(client,tmp_path,notification_directory=folder)
    saved=(tmp_path/'keys/slack-notifier.key').read_bytes()
    assert not any(e[0]=='invalidate' for e in client.security.events)
    notification_prerequisites(client,tmp_path,notification_directory=folder)
    assert (tmp_path/'keys/slack-notifier.key').read_bytes()==saved
    assert sum(e[0]=='key_create' for e in client.security.events)==1
    assert list(client.security.keys.values())[0]['role_descriptors']=={'cloud_soc_notifications':READ_ROLE}
    assert not SlackStore(folder).status()['configured']


def test_webhook_encryption_key_and_config_survive_upgrade_restart_and_webhook_change(tmp_path):
    from test_deployment_parity import FakeSetup
    from cloud_soc.deployment.migrations import notification_prerequisites
    store,clock=configured(tmp_path)
    key=(store.directory/'slack.key').read_bytes()
    with store.connect() as db:encrypted=db.execute('select secret from config where id=1').fetchone()[0]
    client=FakeSetup();(tmp_path/'keys').mkdir()
    notification_prerequisites(client,tmp_path,notification_directory=store.directory)
    restarted=SlackStore(store.directory,clock=lambda:clock[0]);restarted.recover()
    assert (store.directory/'slack.key').read_bytes()==key
    with restarted.connect() as db:assert db.execute('select secret from config where id=1').fetchone()[0]==encrypted
    restarted.save({'revision':1,'webhook_url':URL[:-1]+'8','enabled':True,'minimum_severity':'high'},check_address=lambda:None)
    assert (store.directory/'slack.key').read_bytes()==key
    notification_prerequisites(client,tmp_path,notification_directory=store.directory)
    assert (store.directory/'slack.key').read_bytes()==key and restarted.status()['configured']


def canonical_notification_role():
    from cloud_soc.notifications.worker import READ_ROLE
    role=deepcopy(READ_ROLE)
    role.update(applications=[],run_as=[],metadata={},transient_metadata={'enabled':True})
    role['indices'][0]['allow_restricted_indices']=False
    return {'cloud_soc_notifications':role}


def test_elasticsearch_canonical_read_only_key_is_reused_after_first_install(tmp_path):
    from test_deployment_parity import FakeSetup,POLICY,NOW
    from cloud_soc.deployment.contract import build_contract
    from cloud_soc.deployment.migrations import notification_prerequisites,validate_notification_role
    from cloud_soc.deployment.preflight import inspect
    client=FakeSetup();(tmp_path/'keys').mkdir();folder=tmp_path/'notifications'
    notification_prerequisites(client,tmp_path,notification_directory=folder)
    saved=(tmp_path/'keys/slack-notifier.key').read_bytes()
    record=next(iter(client.security.keys.values()));record['role_descriptors']=canonical_notification_role()
    validate_notification_role(record['role_descriptors'])
    notification_prerequisites(client,tmp_path,notification_directory=folder)
    assert (tmp_path/'keys/slack-notifier.key').read_bytes()==saved
    assert sum(e[0]=='key_create' for e in client.security.events)==1
    contract,_=build_contract(POLICY,{},tmp_path,now=NOW)
    assert inspect(client,POLICY,contract,{}, {},saved.decode().strip())['notification_key']=='existing_read_only_key_verified'


@pytest.mark.parametrize('change',['cluster','applications','run_as','metadata','disabled','transient_extra','extra_role','remote',
    'names','privileges','restricted','query','fls','extra_index','unknown','duplicate_name'])
def test_canonical_notification_role_refuses_every_unexpected_scope(change):
    from cloud_soc.deployment.migrations import validate_notification_role
    roles=canonical_notification_role();r=roles['cloud_soc_notifications'];g=r['indices'][0]
    if change=='cluster':r['cluster']=['monitor']
    elif change=='applications':r['applications']=[{'application':'*','privileges':['*'],'resources':['*']}]
    elif change=='run_as':r['run_as']=['*']
    elif change=='metadata':r['metadata']={'unexpected':True}
    elif change=='disabled':r['transient_metadata']={'enabled':False}
    elif change=='transient_extra':r['transient_metadata']={'enabled':True,'unexpected':True}
    elif change=='extra_role':roles['extra']={'indices':[]}
    elif change=='remote':r['remote_indices']=[]
    elif change=='names':g['names']=['security-*','soc-alert-notices-v1']
    elif change=='privileges':g['privileges']+=['write']
    elif change=='restricted':g['allow_restricted_indices']=True
    elif change=='query':g['query']={'match_all':{}}
    elif change=='fls':g['field_security']={'grant':['*']}
    elif change=='extra_index':r['indices'].append(deepcopy(g))
    elif change=='unknown':g['unexpected']=False
    elif change=='duplicate_name':g['names'].append('security-alerts')
    with pytest.raises(ValueError):validate_notification_role(roles)


def test_worker_restart_after_ack_loss_holds_event_instead_of_automatic_duplicate(tmp_path):
    store,clock=configured(tmp_path);source=MemorySource();scan(store,source)
    source.docs[INDICES[0]][0]+=[final(1)];scan(store,source)
    accepted=[]
    def ack_lost(_url,payload):
        accepted.append(payload)
        raise KeyboardInterrupt()  # Remote side accepted; local commit/response did not complete.
    with pytest.raises(KeyboardInterrupt):deliver(store,sender=ack_lost)
    restarted=SlackStore(store.directory,clock=lambda:clock[0]);restarted.recover();clock[0]+=300
    sender=Mock(return_value=Result('sent','slack_accepted'));scan(restarted,source);deliver(restarted,sender=sender)
    sender.assert_not_called()
    assert len(accepted)==1 and restarted.status()['deliveries']=={'unknown':1}


def test_multibatch_scan_and_off_on_skip_pending_history_without_changing_existing_data(tmp_path):
    store,clock=configured(tmp_path);source=MemorySource();scan(store,source)
    source.docs[INDICES[0]][0]+=[final(n) for n in range(1,212)]
    scan(store,source);scan(store,source);scan(store,source)
    assert store.status()['deliveries']=={'queued':211}
    store.save({'revision':1,'enabled':False,'minimum_severity':'high'},check_address=lambda:None)
    source.docs[INDICES[0]][0]+=[final(212)]
    store.save({'revision':2,'enabled':True,'minimum_severity':'medium'},check_address=lambda:None)
    scan(store,source)
    assert store.status()['deliveries']=={'cancelled':211}
    source.docs[INDICES[0]][0]+=[final(213,severity='medium')];scan(store,source)
    assert store.status()['deliveries']=={'cancelled':211,'queued':1}


def test_unknown_details_manual_retry_requires_ack_preserves_cursor_and_audits_actor(tmp_path):
    store,clock=configured(tmp_path);source=MemorySource();scan(store,source)
    source.docs[INDICES[0]][0]+=[final(1)];scan(store,source)
    deliver(store,sender=lambda *_:Result('unknown','delivery_unconfirmed'))
    page=store.unconfirmed();row=page['items'][0]
    assert page['total']==1 and row['source_id']=='1' and row['can_retry'] and 'payload' not in row
    assert URL not in json.dumps(page) and 'SYNTHETIC_TOKEN' not in json.dumps(page) and 'generation' not in row
    body={'revision':1,'notification_id':row['id'],'accept_duplicate_risk':False}
    with pytest.raises(SlackError,match='confirmation_required'):store.retry_unconfirmed(body,actor='admin')
    body['accept_duplicate_risk']=True
    with store.connect() as db:before=[tuple(r) for r in db.execute('select * from cursors')]
    assert store.retry_unconfirmed(body,actor='admin')['duplicate_risk_acknowledged']
    with pytest.raises(SlackError,match='unavailable'):store.retry_unconfirmed(body,actor='admin')
    with store.connect() as db:
        assert [tuple(r) for r in db.execute('select * from cursors')]==before
        assert [tuple(r) for r in db.execute('select notification_id,actor,previous_attempts from manual_retries')]==[(row['id'],'admin',1)]
    clock[0]+=2;sender=Mock(return_value=Result('sent','slack_accepted'));deliver(store,sender=sender)
    assert sender.call_count==1 and store.unconfirmed()['total']==0 and store.status()['deliveries']=={'sent':1}


def test_manual_retry_pagination_throttle_stale_revision_and_changed_webhook_fail_closed(tmp_path):
    store,clock=configured(tmp_path);source=MemorySource();scan(store,source)
    source.docs[INDICES[0]][0]+=[final(n) for n in range(1,22)];scan(store,source)
    with store.connect() as db:db.execute("update outbox set status='unknown',attempts=1")
    page=store.unconfirmed();assert len(page['items'])==20 and page['next_offset']==20
    assert len(store.unconfirmed(20)['items'])==1
    for offset in (-1,100001,'0',True):
        with pytest.raises(SlackError):store.unconfirmed(offset)
    body={'revision':0,'notification_id':page['items'][0]['id'],'accept_duplicate_risk':True}
    with pytest.raises(SlackError,match='settings_changed'):store.retry_unconfirmed(body,actor='admin')
    body['revision']=1;store.retry_unconfirmed(body,actor='admin')
    body['notification_id']=page['items'][1]['id']
    with pytest.raises(SlackError) as error:store.retry_unconfirmed(body,actor='admin')
    assert error.value.status==429
    clock[0]+=31;store.save({'revision':1,'webhook_url':URL[:-1]+'9','enabled':True,'minimum_severity':'high'},check_address=lambda:None)
    assert all(not item['can_retry'] for item in store.unconfirmed()['items'])
    body['revision']=2
    with pytest.raises(SlackError,match='unavailable'):store.retry_unconfirmed(body,actor='admin')
    with store.connect() as db:db.execute("update outbox set status='permanent'")
    assert store.unconfirmed()['total']==0
    with pytest.raises(SlackError,match='unavailable'):store.retry_unconfirmed(body,actor='admin')


def test_admin_session_rbac_csrf_secret_nonreturn_and_queued_test(tmp_path):
    from test_integration_security import make_session_portal,login
    app,_,_,_=make_session_portal(tmp_path);http,headers=login(app,'admin');view,vheaders=login(app,'view')
    path='/api/settings/notifications/slack'
    assert http.get('/settings-slack.html').status_code==200
    assert view.get('/settings-slack.html').status_code==403 and view.get('/settings-slack.js').status_code==403
    assert view.get(path).status_code==403 and view.post(path+'/test',json={},headers=vheaders).status_code==403
    assert http.post(path,json={},headers={'X-Cloud-SOC':'portal'}).status_code==403
    assert app.test_client().get(path).status_code==401
    assert view.get(path+'/unconfirmed?offset=0').status_code==403
    assert view.post(path+'/retry',json={},headers=vheaders).status_code==403
    assert http.post(path+'/retry',json={},headers={'X-Cloud-SOC':'portal'}).status_code==403
    assert http.get(path+'/unconfirmed?offset=0').json=={'items':[],'total':0,'offset':0,'next_offset':None}
    for query in ('offset=-1','offset=100001','offset=0&offset=1','url=PRIVATE','offset=Infinity'):
        assert http.get(path+'/unconfirmed?'+query).status_code==400
    with patch('cloud_soc.notifications.transport.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]):
        reply=http.post(path,json={'revision':0,'webhook_url':URL,'enabled':True,'minimum_severity':'high'},headers=headers)
    assert reply.status_code==200 and URL not in reply.get_data(as_text=True)
    assert URL not in http.get(path).get_data(as_text=True)
    assert http.post(path+'/test',json={},headers=headers).status_code==202
    assert http.post(path+'/test',json={},headers=headers).status_code==429
    store=app.extensions['slack']
    with store.connect() as db:
        db.execute("update outbox set status='unknown'")
        db.execute('update control set test_after=0')
    item=http.get(path+'/unconfirmed').json['items'][0]
    body={'revision':1,'notification_id':item['id'],'accept_duplicate_risk':True}
    assert http.post(path+'/retry',json={**body,'accept_duplicate_risk':False},headers=headers).status_code==400
    assert http.post(path+'/retry',json=body,headers=headers).status_code==202
    assert http.post(path+'/retry',json=body,headers=headers).status_code==409
    assert http.delete(path,json={'revision':1},headers=headers).status_code==200


def test_basic_admin_requires_origin_and_unsafe_storage_is_rejected(tmp_path):
    from test_portal import AUTH,HASH,ROOT
    from cloud_soc.portal.app import create_app
    app=create_app({'STATE_DIR':tmp_path/'basic','AGENT_SOURCE':ROOT/'deploy/agents','CA_BYTES':b'SYNTHETIC CA',
       'PUBLIC_URL':'http://localhost','ENDPOINT':'https://example.test:9200','ADMIN_USER':'admin','ADMIN_HASH':HASH},issuer=Mock())
    client=app.test_client();headers={'Authorization':AUTH,'X-Cloud-SOC':'portal'}
    assert client.get('/api/settings/notifications/slack',headers=headers).status_code==200
    body={'revision':0,'enabled':False,'minimum_severity':'high'}
    assert client.post('/api/settings/notifications/slack',json=body,headers=headers).status_code==403
    assert client.post('/api/settings/notifications/slack',json=body,headers={**headers,'Origin':'http://localhost'}).status_code==200
    # Storage hardlinks/symlinks must fail even if their contents are a valid synthetic URL/key.
    store,_=configured(tmp_path)
    target=tmp_path/'linked'
    try:target.symlink_to(store.directory,target_is_directory=True)
    except OSError:pytest.skip('Creating symlinks is unavailable on this host')
    with pytest.raises(SlackError,match='notification_storage_unsafe'):SlackStore(target).status()
