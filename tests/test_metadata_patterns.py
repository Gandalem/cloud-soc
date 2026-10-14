"""Disabled candidates exercise the real supported adapters, not attack tools."""
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import pytest
from cloud_soc.detection.engine import detect_rule, event_fingerprint
from cloud_soc.detection.patterns import evaluate_pattern
from cloud_soc.detection.rule_loader import load_rules, validate_rule
from cloud_soc.detection.worker import approved_rules
from cloud_soc.processing.contract import normalize, NORMALIZED
from test_linux_ssh_live_formats import raw, event, BASE
from test_processing import fixture
from test_cloud_detection import event as cloud_event
from test_linux_operational import hit

RULES={r['id']:r for r in load_rules(Path(__file__).resolve().parents[1]/'rules/metadata_patterns.yml',enabled_only=False)}


def normalized(raw_hit):
    key, record, body=normalize(raw_hit,BASE.isoformat())
    assert record['status']=='normalized'
    body['_cloud_soc_meta']={'index':NORMALIZED,'document_id':key}
    return body


def ssh(i, user=None):
    r=raw(i)
    r['_source']['message']=r['_source']['message'].replace('for fixture ',f'for {user or "account"+str(i%4)} ')
    return event(r)


def windows(i, logon=10, code='4625'):
    r=fixture();r['_id']=str(i);s=r['_source'];s['@timestamp']=(BASE+timedelta(seconds=i)).isoformat()
    s['host']={'id':'host-a'};s['event']['code']=code;s['winlog']['event_id']=code
    s['winlog']['event_data']['LogonType']=str(logon)
    return normalized(r)


def web(i,status=404):
    r=hit(f'192.0.2.1 - - [05/Oct/2026:13:00:{i%60:02d} +0900] "GET /?token=PRIVATE_CANARY HTTP/1.1" {status} 12 "PRIVATE_CANARY" "PRIVATE_CANARY"',kind='linux_file')
    r['_id']=str(i);r['_source']['host']={'id':'web-a'};r['_source']['source']={'ip':'192.0.2.1'}
    r['_source']['log']={'file':{'path':'/var/log/nginx/access_log'}}
    return normalized(r)


def flow(i,port=None,final=True):
    r=fixture();r['_index']='soc-network-test';r['_id']=str(i);s=r['_source'];s.pop('winlog')
    s['@timestamp']=(BASE+timedelta(seconds=i)).isoformat()
    s.update(agent={'type':'packetbeat'},labels={'log_source':'network_packetbeat'},
        source={'ip':'192.0.2.1','port':40000},destination={'ip':'198.51.100.1','port':port or 1000+i},
        network={'transport':'tcp'},flow={'id':f'flow-{i}','final':final})
    return normalized(r)


def console(i):
    r=cloud_event('ConsoleLogin','signin.amazonaws.com',failure=True,number=i+1)
    r['@timestamp']=(BASE+timedelta(seconds=i)).isoformat()
    return r


GENERATORS={'AUTH-SPRAY-001':ssh,'WIN-AUTH-001':windows,'WEB-404-001':web,'NET-PORT-001':flow,'AWS-CONSOLE-001':console}


@pytest.mark.parametrize('identifier',RULES)
def test_real_adapter_threshold_count_boundary_dedup_and_immutable_input(identifier):
    rule=RULES[identifier];n=rule['threshold']['count'];rows=[GENERATORS[identifier](i) for i in range(n)]
    before=event_fingerprint(rows)
    assert all(evaluate_pattern(row,rule)[0]=='matched' for row in rows)
    assert detect_rule(rows[:-1],rule)==[]
    found=detect_rule(rows,rule)
    assert len(found)==1 and found[0]['event_count']==n
    assert found[0]['assessment']['attack_success']=='not_established'
    assert len(found[0]['evidence'])==n
    assert detect_rule(rows[:-1]+[deepcopy(rows[0])]*20,rule)==[]
    assert event_fingerprint(rows)==before and 'PRIVATE_CANARY' not in json.dumps(found)


@pytest.mark.parametrize('identifier',RULES)
def test_required_metadata_missing_unknown_and_organizations_do_not_mix(identifier):
    rule=RULES[identifier];n=rule['threshold']['count'];rows=[GENERATORS[identifier](i) for i in range(n)]
    rows[-1]['organization']['id']='other'
    assert detect_rule(rows,rule)==[]
    for field in rule['required_fields']:
        row=GENERATORS[identifier](0);target=row;parts=field.split('.')
        for part in parts[:-1]:target=target[part]
        target.pop(parts[-1])
        assert evaluate_pattern(row,rule)[0]=='unknown'
        assert detect_rule([row]*n,rule)==[]


def test_multi_account_separation_cooldown_and_journal_mirror():
    rule=RULES['AUTH-SPRAY-001']
    assert detect_rule([ssh(i,'same') for i in range(10)],rule)==[]
    rows=[ssh(i) for i in range(10)]
    for i in range(9):
        r=raw(i,'rfc3339');r['_source']['message']=r['_source']['message'].replace('for fixture ',f'for account{i%4} ')
        rows.append(event(r))
    assert len(detect_rule(rows,rule))==1
    runtime={};assert len(detect_rule([ssh(i) for i in range(10)],rule,runtime=runtime))==1
    assert detect_rule([ssh(i) for i in range(10,30)],rule,runtime=runtime)==[]
    assert len(detect_rule([ssh(i) for i in range(310,320)],rule,runtime=runtime))==1


def test_windows_type_host_ip_not_assumed_rdp_and_success_normal():
    rule=RULES['WIN-AUTH-001']
    assert detect_rule([windows(i,code='4624') for i in range(10)],rule)==[]
    mixed=[windows(i,logon=3 if i<5 else 10) for i in range(10)]
    assert detect_rule(mixed,rule)==[]
    for field in ('host','source'):
        rows=[windows(i) for i in range(10)];rows[-1][field]['id' if field=='host' else 'ip']='other' if field=='host' else '192.0.2.2'
        assert detect_rule(rows,rule)==[]
    found=detect_rule([windows(i,logon=3) for i in range(10)],rule)[0]
    assert found['group']['cloud_soc.detail.fields.logon_type']==3
    assert 'RDP' not in found['alert']['title']


def test_web_no_false_vulnerability_claim_and_crawler_false_positive_disclosed():
    rule=RULES['WEB-404-001']
    for status in (200,400,401,403,500):assert detect_rule([web(i,status) for i in range(20)],rule)==[]
    found=detect_rule([web(i) for i in range(20)],rule)[0]
    assert found['severity']=='low' and 'crawler_bad_links_healthchecks_can_match' in found['assessment']['limitations']
    assert not {'WEB-01','WEB-02','WEB-03','WEB-04','WEB-05'} & {r['id'] for r in approved_rules(include_patterns=True,include_attacks=True)}
    assert all('url' not in row and 'message' not in row for row in [web(i) for i in range(20)])


def test_ports_distinct_final_flow_and_host_scopes():
    rule=RULES['NET-PORT-001']
    assert detect_rule([flow(i,443) for i in range(30)],rule)==[]
    assert detect_rule([flow(i,final=False) for i in range(15)],rule)==[]
    rows=[flow(i) for i in range(15)];rows[-1]['destination']['ip']='198.51.100.2'
    assert detect_rule(rows,rule)==[]
    rows=[flow(i) for i in range(14)];duplicate=deepcopy(rows[0]);duplicate['_cloud_soc_meta']['document_id']='second-raw'
    assert detect_rule(rows+[duplicate],rule)==[]
    found=detect_rule([flow(i) for i in range(15)],rule)[0]
    assert found['assessment']['distinct_count']==15
    assert 'no_nmap_or_syn_tool_attribution' in found['assessment']['limitations']


def test_console_principal_and_event_id_not_inferred_and_success_excluded():
    rule=RULES['AWS-CONSOLE-001'];rows=[console(i) for i in range(5)]
    rows[-1]['user']['id']='different'
    assert detect_rule(rows,rule)==[]
    rows=[console(i) for i in range(5)];rows[-1]['event']['outcome']='success'
    assert detect_rule(rows,rule)==[]
    rows=[console(i) for i in range(5)]
    for row in rows:row['cloud_soc']['detail']['fields']['identity_type']='Unknown'
    assert detect_rule(rows,rule)==[]
    assert 'password_mfa_lockout_can_match' in detect_rule([console(i) for i in range(5)],rule)[0]['assessment']['limitations']


def test_opt_in_identity_and_strict_cardinality_validation():
    assert [r['id'] for r in approved_rules()]==['AUTH-001']
    assert [r['id'] for r in approved_rules(include_patterns=True)]==['AUTH-001','AUTH-SPRAY-001','WIN-AUTH-001','WEB-404-001','NET-PORT-001']
    for key,value in [('distinct',{'field':'user.name','count':True}),('dedup_fields',['url.query']),
                      ('required_fields',['source.ip']),('limitations',[]),('cooldown',{'seconds':3601})]:
        r=deepcopy(RULES['AUTH-SPRAY-001']);r[key]=value
        with pytest.raises(ValueError):validate_rule(r)


def test_bounded_large_duplicate_input_and_finalized_runtime_order():
    rule=RULES['NET-PORT-001'];rows=[flow(i,443) for i in range(400)]
    assert detect_rule(rows*5,rule)==[]
    runtime={};detect_rule(rows[:20],rule,runtime=runtime)
    with pytest.raises(ValueError,match='finalized event order'):detect_rule(rows[:1],rule,runtime=runtime)
