import copy
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest
from cloud_soc.portal.packages import validate_spec, build_bundle
from cloud_soc.portal.site_agents import profile
from cloud_soc.portal.log_query import project_list_hit
from cloud_soc.processing.contract import normalize
from cloud_soc.portal.collection_components import state, snapshot
from cloud_soc.portal.log_contract import parse_filters
from cloud_soc.portal.log_query import LogReader
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock
import importlib.util

ROOT=Path(__file__).resolve().parents[1]
SITE={'id':'dvwa','name':'DVWA','server_type':'apache','log_path':'/var/log/apache2/access.log','start_at':'2026-10-14T09:00:00+09:00'}


def spec(os='ubuntu', **extra):
    site={**SITE,'log_path':r'C:\Apache\logs\access.log' if os=='windows' else SITE['log_path']}
    return validate_spec({'name':'site-agent','os':os,'organization':'lab','network':False,'system':True,'sites':[site],**extra},'https://soc.example.invalid:9200')


@pytest.mark.parametrize('os',['ubuntu','amazon_linux_2023','windows'])
def test_real_bundle_contains_one_web_input_and_only_opted_network(os):
    s=spec(os); blob,filename=build_bundle(s,ROOT/'deploy/agents',b'SYNTHETIC CA')
    if os=='windows':
        with zipfile.ZipFile(io.BytesIO(blob)) as z:members={name:z.read(name) for name in z.namelist()}
    else:
        with tarfile.open(fileobj=io.BytesIO(blob)) as z:members={m.name:z.extractfile(m).read() for m in z.getmembers()}
    compiled=json.loads(members['collection-profile.json'])
    assert len(compiled['web_inputs'])==1 and compiled['system'] is True
    assert compiled['web_inputs'][0]['prospector.scanner.fingerprint.length']==64
    assert compiled['web_inputs'][0]['processors'][0]['script']['params']['start_at']=='2026-10-14T00:00:00Z'
    assert not any(name.startswith('install-network') for name in members)
    assert 'site-privacy.js' in members and 'SHA256SUMS' in members


@pytest.mark.parametrize('path',['/etc/passwd','/proc/1/root/access.log','/var/log/../secrets.log','/var/log/*.log','/home/kopo/access.log','/var/log/token?secret.log','/var/log/log.key'])
def test_private_glob_and_unsafe_paths_refused(path):
    with pytest.raises(ValueError):spec(sites=[{**SITE,'log_path':path}])


def test_independent_scope_and_legacy_package_contract():
    assert not profile(spec(system=False))['system']
    with pytest.raises(ValueError):spec(system=False,sites=[])
    with pytest.raises(ValueError):spec(sites=[SITE,SITE])
    with pytest.raises(ValueError):spec(sites=[{**SITE,'start_at':'2026-10-14T00:00:00'}])
    legacy=validate_spec({'name':'old','os':'ubuntu','organization':'lab','network':False},'https://soc.example.invalid')
    assert 'sites' not in legacy and 'system' not in legacy
    assert set(profile(spec())['web_exclusions'])=={'/var/log/apache2','/var/log/httpd','/var/log/nginx'}
    assert set(profile(spec(sites=[]))['web_exclusions'])=={'/var/log/apache2','/var/log/httpd','/var/log/nginx'}


def web_hit():
    return {'_index':'soc-host-raw-linux-9.5.2-2026.10.14','_id':'fixture-reference','_source':{
        '@timestamp':'2026-10-14T00:00:00Z','event':{'ingested':'2026-10-14T00:00:02Z','category':['web'],'action':'http_access','dataset':'cloud_soc.web_access','outcome':'failure'},
        'organization':{'id':'lab'},'agent':{'id':'fixture-agent','type':'filebeat'},'host':{'id':'fixture-host','os':{'type':'linux'}},
        'labels':{'log_source':'generic_web_access','privacy_policy':'v3'},'service':{'id':'dvwa','name':'DVWA'},
        'web':{'schema':'web-access-agent-v1','server_type':'apache','ip_basis':'observed_peer'},
        'http':{'request':{'method':'POST'},'response':{'status_code':401}},'source':{'ip':'192.0.2.1'},'log':{'offset':42}}}


def test_generic_raw_to_normalized_and_portal_keeps_exact_reference():
    hit=web_hit(); row=project_list_hit(hit)
    assert row['source_kind']=='generic_web_access' and row['interpretation']['fields']['http_status']==401
    _,record,doc=normalize(hit,processed_at='2026-10-14T00:00:03Z')
    assert record['status']=='normalized' and doc['cloud_soc']['detail']['adapter']=='web_access_agent_v1'
    assert record['raw']['id']==hit['_id']
    invalid=copy.deepcopy(hit);invalid['_source']['http']['request']['body']='PRIVATE_CANARY'
    assert normalize(invalid,processed_at='2026-10-14T00:00:03Z')[1]['status']=='unsupported'


def test_component_states_do_not_turn_missing_data_or_errors_into_success():
    now=datetime(2026,10,14,tzinfo=timezone.utc)
    assert state(False,None,now)['state']=='unconfigured'
    assert state(True,None,now)['state']=='no_data'
    assert state(None,None,now)['state']=='unknown'
    assert state(True,now,now,errors=1)['state']=='error'
    assert state(True,now-timedelta(minutes=20),now)['state']=='delayed'
    assert state(True,now,now)['state']=='normal'
    assert state(False,now,now,report_recent=False)['state']=='delayed'


def test_component_upstream_failures_are_not_empty_healthy_status():
    client=Mock();client.options.return_value=client
    client.search.return_value={'timed_out':True}
    with pytest.raises(ValueError):snapshot(client)


def test_web_query_keeps_organization_authority_and_both_contract_versions():
    filters=parse_filters([('source_kind','web')])
    reader=LogReader(Mock(),secret='synthetic-test-secret',principal='fixture',organizations=('lab',))
    body=reader.body(filters,'synthetic-pit',None)
    clauses=body['query']['bool']['filter']
    assert {'terms':{'organization.id':['lab']}} in clauses
    assert {'terms':{'soc_query_source':['generic_web_access','web_access_metadata']}} in clauses
    with pytest.raises(ValueError):parse_filters([('source_kind','arbitrary-raw')])


def test_local_switches_preserve_immutable_profile_and_reserved_web_directory(tmp_path):
    loader=importlib.util.spec_from_file_location('profile_reader',ROOT/'deploy/agents/profile-reader.py')
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    p=tmp_path/'collection-profile.json';original=json.dumps(profile(spec())).encode();p.write_bytes(original)
    (tmp_path/'collection-switches.json').write_text(json.dumps({'system':False,'web':{'dvwa':False}}))
    result=module.read(p)
    assert result['system'] is False and result['web_inputs'][0]['enabled'] is False
    assert '/var/log/apache2' in result['web_exclusions'] and p.read_bytes()==original
    (tmp_path/'collection-switches.json').write_text(json.dumps({'web':{'unknown-site':False}}))
    with pytest.raises(ValueError):module.read(p)
