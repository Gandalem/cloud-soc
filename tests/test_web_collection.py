"""Isolated web collection: no real servers, credentials, requests, or log rotation."""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
from unittest.mock import Mock, patch

import pytest

from cloud_soc.web.metadata import INDEX, VERSION, project, validate
from cloud_soc.web.spool import collect, export
from cloud_soc.web.relay import check_export, create_publisher, run_once, ssh_export
from cloud_soc.processing.contract import normalize
from cloud_soc.portal.security_detail import security_detail
from cloud_soc.portal.log_query import project_list_hit, LogReader, LogQueryError
from cloud_soc.portal.log_contract import parse_filters

NOW='2026-10-13T07:45:00Z'
CONFIG={'organization':'aws-dvwa-lab','host':'i-0123456789abcdef0','container':'a'*64,'region':'ap-northeast-3'}
CANARY='CANARY_WEB_NEVER_TRANSMIT'


def test_exact_web_mapping_forbids_raw_messages_and_final_receipt_cannot_be_spoofed():
    root=Path(__file__).resolve().parents[1]/'deploy/web'
    template=json.loads((root/'index-template.json').read_text());pipeline=json.loads((root/'receipt-pipeline.json').read_text());role=json.loads((root/'publisher-role.json').read_text())
    assert template['index_patterns']==[INDEX] and template['template']['mappings']['dynamic']=='strict'
    assert 'message' not in template['template']['mappings']['properties']
    assert template['template']['settings']['index.final_pipeline']=='cloud-soc-web-received-at-v1'
    setters={p['set']['field']:p['set'] for p in pipeline['processors']}
    assert setters['event.ingested']=={'field':'event.ingested','value':'{{{_ingest.timestamp}}}','override':True}
    assert setters['organization.id']=={'field':'organization.id','value':CONFIG['organization'],'override':True}
    assert role['indices']==[{'names':[INDEX],'privileges':['create_doc']}] and role['cluster']==[]


def line(target='/login.php', *, ip='192.0.2.10', status=200, method='GET', seconds=1):
    return f'{ip} - - [13/Oct/2026:16:45:{seconds:02} +0900] "{method} {target} HTTP/1.1" {status} 120 "token={CANARY}" "Cookie={CANARY}"\n'.encode()


def event(value=None, offset=0):
    return project(value or line(),**CONFIG,generation=1,device=1,inode=2,offset=offset,collected_at=NOW)


def received(body=None):
    body=deepcopy(body or event());body['event']['ingested']=NOW;return body


@pytest.mark.parametrize('code,outcome',[(200,'success'),(204,'success'),(302,'unknown'),(404,'failure'),(500,'failure')])
def test_apache_time_status_and_privacy_before_queue(code,outcome):
    body=event(line('/login.php?password='+CANARY,status=code,method='POST'))
    assert body['@timestamp']=='2026-10-13T07:45:01Z'
    assert body['event']['outcome']==outcome and body['http']['request']['method']=='POST'
    encoded=json.dumps(body)
    assert CANARY not in encoded and 'password' not in encoded and 'Cookie' not in encoded and '/login.php' not in encoded
    assert body['web']['path_class']=='login' and body['source']['ip']=='192.0.2.10'


def test_docker_json_is_a_real_envelope_without_reconstructing_apache():
    record={'log':line('/?token='+CANARY).decode(),'time':NOW,'stream':'stdout'}
    body=project(json.dumps(record).encode(),**CONFIG,generation=1,device=1,inode=2,offset=0,collected_at=NOW,docker=True)
    assert body['web']['source_kind']=='docker_json' and CANARY not in json.dumps(body)
    record['stream']='stderr'
    assert project(json.dumps(record).encode(),**CONFIG,generation=1,device=1,inode=2,offset=0,collected_at=NOW,docker=True) is None


@pytest.mark.parametrize('value',[b'bad log\n',line(status=600),line().replace(b'13/Oct',b'32/Oct'),line(method='BREW'),line()+b'POST body secret',b'x'*8193,line().replace(b'+0900',b'+9960')])
def test_malformed_fields_are_excluded_without_fabrication(value):
    assert event(value) is None


def test_hostname_or_placeholder_is_partial_not_a_guessed_ip():
    for peer in ('client.example.test','0.0.0.0','::','192.0.2.10%zone'):
        body=event(line(ip=peer));assert 'source' not in body
        result=security_detail(received(body));assert result['status']=='partial' and result['missing']==['source_ip']


def test_stable_identity_distinguishes_offsets_and_does_not_include_secrets():
    assert event()['event']['id']==event()['event']['id']
    assert event(offset=1)['event']['id']!=event()['event']['id']
    assert event(line('/?token='+CANARY))['event']['id']==event()['event']['id']


@pytest.mark.parametrize('field',['url','message','request_body','Authorization','Cookie','environment'])
def test_unknown_fields_rejected_at_intake_and_adapter(field):
    body=received();body[field]=CANARY
    with pytest.raises(ValueError):validate(body,received=True)
    assert security_detail(body)['status']=='unsupported'


def test_nested_fields_ids_scopes_and_bool_status_cannot_be_smuggled():
    for mutate in (lambda b:b['http']['request'].update(body=CANARY),lambda b:b['web'].update(query=CANARY),lambda b:b['http']['response'].update(status_code=True),lambda b:b['organization'].update(id='different-org'),lambda b:b['event'].update(id='0'*64)):
        body=event();mutate(body)
        with pytest.raises(ValueError):validate(body)


def test_normalization_has_exact_protected_raw_reference_and_distinct_version():
    body=received();hit={'_index':INDEX,'_id':body['event']['id'],'_source':body};original=deepcopy(hit)
    ident,record,normalized=normalize(hit,NOW)
    assert hit==original and record['status']=='normalized' and record['version']==VERSION
    assert normalized['event']['category']==['web'] and normalized['event']['action']=='http_access'
    assert normalized['cloud_soc']['detail']['adapter']=='web_access_metadata_v1'
    assert normalized['cloud_soc']['provenance']['raw']=={'index':INDEX,'id':body['event']['id']}
    assert normalized['cloud_soc']['provenance']['time']['raw_is_protected_metadata'] is True
    assert record['normalized']['id']==ident and CANARY not in json.dumps(normalized)
    row=project_list_hit(hit)
    assert row['source_kind']=='web_access_metadata' and row['interpretation']['fields']['http_status']==200
    assert parse_filters([('collector','web-collector')]).collector=='web-collector'
    hit['_index']='soc-host-raw-linux-other'
    assert normalize(hit,NOW)[1]['reason']=='source_scope_mismatch'


def test_web_org_scope_guard_refuses_foreign_detail_before_disclosing_metadata():
    from elasticsearch import NotFoundError
    client=Mock();client.options.return_value=client;client.indices.resolve_index.return_value={'indices':[{'name':INDEX}]}
    client.indices.get_mapping.return_value={INDEX:{'mappings':{'properties':{'organization':{'properties':{'id':{'type':'keyword'}}}}}}}
    client.get.return_value={'_index':INDEX,'_id':event()['event']['id'],'_source':received()}
    reader=LogReader(client,secret='synthetic-secret-for-tests',principal='synthetic-viewer',organizations=['other-org'])
    with pytest.raises((LogQueryError,NotFoundError,ValueError)):reader.detail([('index',INDEX),('id',event()['event']['id'])])


def start(tmp_path):
    log=tmp_path/'access.log';state=tmp_path/'state'/'spool.sqlite';log.write_bytes(b'')
    collect(log,state,CONFIG,NOW);return log,state


def test_restart_cursor_atomicity_partial_line_and_queue_privacy(tmp_path):
    log,state=start(tmp_path);raw=line('/?token='+CANARY)
    log.write_bytes(raw[:30]);collect(log,state,CONFIG,NOW)
    assert export(state,{'schema':1,'after':0,'limit':100})['rows']==[]
    log.write_bytes(raw);collect(log,state,CONFIG,NOW)
    first=export(state,{'schema':1,'after':0,'limit':100});assert len(first['rows'])==1
    collect(log,state,CONFIG,NOW);assert export(state,{'schema':1,'after':0,'limit':100})==first
    assert CANARY.encode() not in state.read_bytes()
    with patch('cloud_soc.web.spool.project',side_effect=RuntimeError('synthetic_crash')):
        with log.open('ab') as file:file.write(line(seconds=2))
        with pytest.raises(RuntimeError):collect(log,state,CONFIG,NOW)
    assert export(state,{'schema':1,'after':0,'limit':100})==first
    collect(log,state,CONFIG,NOW);assert len(export(state,{'schema':1,'after':0,'limit':100})['rows'])==2


def test_rename_rotation_drains_retired_inode_even_after_restart(tmp_path):
    log,state=start(tmp_path);log.write_bytes(line());collect(log,state,CONFIG,NOW)
    with log.open('ab') as file:file.write(line(seconds=2))
    log.rename(tmp_path/'access.log.1');log.write_bytes(line(seconds=3));collect(log,state,CONFIG,NOW)
    rows=export(state,{'schema':1,'after':0,'limit':100})['rows']
    assert len(rows)==3 and len({r['body']['event']['id'] for r in rows})==3
    assert [r['body']['web']['position']['generation'] for r in rows]==[1,1,2]


def test_copytruncate_or_missing_rotated_source_marks_possible_loss(tmp_path):
    log,state=start(tmp_path);log.write_bytes(line());collect(log,state,CONFIG,NOW)
    log.write_bytes(line(seconds=2));collect(log,state,CONFIG,NOW)
    reply=export(state,{'schema':1,'after':0,'limit':100});assert reply['health']['source_gaps']==1 and len(reply['rows'])==2
    log.rename(tmp_path/'deleted-unavailable');log.write_bytes(line(seconds=3));collect(log,state,CONFIG,NOW)
    assert export(state,{'schema':1,'after':0,'limit':100})['health']['source_gaps']==2


def test_long_outage_queue_is_bounded_and_eviction_is_visible(tmp_path):
    log,state=start(tmp_path);log.write_bytes(b''.join(line(seconds=i) for i in range(1,8)))
    collect(log,state,CONFIG,NOW,max_rows=2,max_bytes=4096)
    reply=export(state,{'schema':1,'after':0,'limit':100})
    assert len(reply['rows'])<=2 and reply['health']['queued_bytes']<=4096 and reply['health']['evicted']>=5


def test_export_is_read_only_and_refuses_arbitrary_requests(tmp_path):
    log,state=start(tmp_path);log.write_bytes(line());collect(log,state,CONFIG,NOW);before=state.read_bytes()
    export(state,{'schema':1,'after':0,'limit':100});assert state.read_bytes()==before
    for req in ({'schema':1,'after':0,'limit':101},{'schema':1,'after':False,'limit':1},{'schema':1,'after':0,'limit':1,'command':CANARY}):
        with pytest.raises(ValueError):export(state,req)
    with pytest.raises(ValueError):collect(log,state,{**CONFIG,'organization':'other-org'},NOW)


def relay_config(tmp_path):
    return {**CONFIG,'state':str(tmp_path/'relay.sqlite'),'es_url':'https://soc.example.test:9200','api_key_file':str(tmp_path/'publisher.key'),'ca_file':str(tmp_path/'ca.crt'),'ssh_key':str(tmp_path/'ssh.key'),'known_hosts':str(tmp_path/'known_hosts')}


@pytest.mark.parametrize('host', [None, '56.155.117.55'])
def test_export_uses_configured_address_without_weakening_pinned_ssh(tmp_path, host):
    config = relay_config(tmp_path)
    if host is not None:
        config['ssh_host'] = host
    with patch('cloud_soc.web.relay.protected', side_effect=Path), patch('cloud_soc.web.relay.subprocess.run') as run:
        run.return_value = Mock(returncode=0, stdout=b'{"schema":1}')
        assert ssh_export(config, 7) == {'schema': 1}
    args = run.call_args.args[0]
    assert args[-2:] == ['ec2-user@' + (host or '13.208.175.237'), 'cloud-soc-web-export']
    assert 'StrictHostKeyChecking=yes' in args and 'ForwardAgent=no' in args and 'IdentitiesOnly=yes' in args
    assert json.loads(run.call_args.kwargs['input']) == {'schema': 1, 'after': 7, 'limit': 100}


@pytest.mark.parametrize('host', ['', None, 123, '-oProxyCommand=bad', 'host;command', 'https://56.155.117.55', '127.0.0.1', '0.0.0.0', '224.0.0.1'])
def test_invalid_export_address_never_starts_ssh(tmp_path, host):
    with patch('cloud_soc.web.relay.subprocess.run') as run:
        with pytest.raises(ValueError, match='invalid_ssh_host'):
            ssh_export({**relay_config(tmp_path), 'ssh_host': host}, 0)
    run.assert_not_called()


def test_delivery_failure_retry_restart_and_gap_do_not_advance_unwritten_events(tmp_path):
    log,state=start(tmp_path);log.write_bytes(line()+line(seconds=2));collect(log,state,CONFIG,NOW)
    cfg=relay_config(tmp_path);fetch=lambda c,a:export(state,{'schema':1,'after':a,'limit':100})
    written=set()
    def publisher(body):
        if body['http']['request']['method']=='GET' and len(written)==1:raise OSError('synthetic outage')
        written.add(body['event']['id']);return 'created'
    with pytest.raises(OSError):run_once(cfg,fetch=fetch,publish=publisher)
    with sqlite3.connect(cfg['state']) as db:
        assert db.execute('SELECT seq FROM relay').fetchone()[0]==1
        assert json.loads(db.execute('SELECT body FROM report').fetchone()[0])['state']=='failed'
    result=run_once(cfg,fetch=fetch,publish=lambda b:'existing');assert result['last_seq']==2 and result['counts']['existing']==1
    assert run_once(cfg,fetch=fetch,publish=lambda b:'created')['counts']['created']==0
    changed=deepcopy(fetch(cfg,0));changed['stream_id']='b'*32
    with pytest.raises(ValueError):run_once(cfg,fetch=lambda c,a:changed,publish=lambda b:'created')


def test_relay_cross_org_or_reordered_exports_are_rejected_before_publish(tmp_path):
    log,state=start(tmp_path);log.write_bytes(line());collect(log,state,CONFIG,NOW);reply=export(state,{'schema':1,'after':0,'limit':100})
    with pytest.raises(ValueError):check_export(reply,{**CONFIG,'organization':'other-org'},0)
    reply['rows'][0]['seq']=0
    with pytest.raises(ValueError):check_export(reply,CONFIG,0)
    cfg=relay_config(tmp_path)
    with pytest.raises(ValueError):create_publisher({**cfg,'es_url':'http://soc.example.test:9200'})
