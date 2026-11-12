"""Join verified Osaka CloudWatch originals to the two Filebeat source streams."""
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from types import SimpleNamespace

import worker as common
from cloud_soc.aws.streaming import project
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.portal.log_contract import document_reference

PRIVATE = tuple(ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16','fc00::/7'))
SOURCES = {
    'vpc': ('aws_vpc_flowlogs', 'aws.vpc_flow',
            'AWS-VPC-MGMT-ACCEPT-001', 'cloudwatch-vpc-recovery-v1'),
    'waf': ('aws_waf', 'aws.waf',
            'AWS-WAF-INJECTION-BLOCK-001', 'cloudwatch-waf-recovery-v1'),
}
MANAGED_INJECTION = re.compile(r'^(?:SQLi(?:_[A-Za-z0-9_]+)?|CrossSiteScripting(?:_[A-Za-z0-9_]+)?)$')

def utc_ms(value):
    return datetime.fromtimestamp(value / 1000, timezone.utc).isoformat()

def project_vpc(message, stream):
    record = project(message, None, SimpleNamespace(format='vpc_flow_v2',account_id=common.ACCOUNT,
        source_id='osaka-vpc-flow',team=None), SimpleNamespace(organization=common.ORG))
    if stream != record['observer']['name']+'-all':
        raise ValueError('flow_stream_mismatch')
    status = record['aws']['stream']['log_status']
    fields = {'log_status':status}
    event = record['event']
    if status == 'OK':
        origin = ip_address(record['source']['ip'])
        target = ip_address(record['destination']['ip'])
        fields['public_to_private'] = origin.is_global and not origin.is_multicast and any(
            target.version == subnet.version and target in subnet for subnet in PRIVATE)
        record['network']['transport'] = {6:'tcp',17:'udp',1:'icmp',58:'icmp'}.get(record['network']['iana_number'],'other')
        record['network'].pop('iana_number')
        event['outcome'] = 'success' if event['action']=='accept' else 'failure'
    return record,fields,{'NODATA':'not_applicable','SKIPDATA':'not_evaluable'}.get(status)

def project_waf(message, expected_time):
    value = json.loads(message)
    stamp = value.get('timestamp')
    action = value.get('action')
    if (value.get('formatVersion')!=1 or type(stamp) is not int or abs(stamp-expected_time)>300000
            or action not in ('ALLOW','BLOCK','CAPTCHA','CHALLENGE')):
        raise ValueError('invalid_waf_record')
    arn = value.get('webaclId')
    if not isinstance(arn,str) or not arn.startswith(f'arn:aws:wafv2:{common.REGION}:{common.ACCOUNT}:regional/webacl/'):
        raise ValueError('waf_scope_mismatch')
    signal = False
    if action == 'BLOCK':
        ids = [value.get('terminatingRuleId')]
        details = list(value.get('terminatingRuleMatchDetails') or [])
        for group in value.get('ruleGroupList') or []:
            rule = group.get('terminatingRule') or {}
            ids.append(rule.get('ruleId'))
            details.extend(rule.get('ruleMatchDetails') or [])
        signal = any(isinstance(x,str) and MANAGED_INJECTION.fullmatch(x) for x in ids) or any(
            isinstance(x,dict) and x.get('conditionType') in ('SQL_INJECTION','XSS') for x in details)
    record={'@timestamp':utc_ms(stamp),'event':{'action':action.lower(),
             'outcome':'failure' if action=='BLOCK' else 'success' if action=='ALLOW' else 'unknown'}}
    return record,{'injection_signal':bool(signal)},None

def recovered(kind, hit, original, stamp, historical):
    raw = hit['_source']
    event_id = common.field(raw,'event.id')
    stream = common.field(raw,'aws.cloudwatch.log_stream')
    if not original:
        return 'original_missing',None
    if original['logStreamName']!=stream or original['timestamp']!=common.millis(raw['@timestamp']):
        return 'original_mismatch',None
    try:
        record,fields,eligibility = (project_vpc(original['message'],stream) if kind=='vpc'
                                     else project_waf(original['message'],original['timestamp']))
        ref = document_reference(hit['_index'],hit['_id'])
    except (ValueError,TypeError,KeyError,AttributeError,OverflowError):
        return 'format_or_scope_rejected',None
    received = common.field(raw,'event.ingested')
    label,dataset,_,version = SOURCES[kind]
    key = hashlib.sha256(json.dumps(['intake-v1',ref],sort_keys=True).encode()).hexdigest()
    event = {'@timestamp':record['@timestamp'], 'organization':{'id':common.ORG},
             'event':{**record['event'],'kind':'event','dataset':dataset,'id':event_id,'ingested':received},
             'cloud':{'provider':'aws','account':{'id':common.ACCOUNT},'region':common.REGION},
             'cloud_soc':{'normalized_at':stamp,'normalizer_version':version,'parse_status':'recognized',
                 'recovery_mode':'cloudwatch_history' if historical else 'cloudwatch_source_worker',
                 'detail':{'adapter':label+'_v1','status':'recognized','fields':fields},
                 'provenance':{'schema_version':1,'raw':ref,'time':{'basis':'provider_event_time',
                     'receipt_basis':'original_soc_receipt','year_inferred':False},
                     'cloudwatch_match':{'method':'event_id_stream_timestamp',
                        'collector_timestamp':raw['@timestamp'],
                        'collector_event_id_sha256':hashlib.sha256(event_id.encode()).hexdigest()}}}}
    for name in ('source','destination','network'):
        if name in record:
            event[name]=record[name]
    if eligibility:
        event['cloud_soc']['detail']['fields']['eligibility']=eligibility
    processing={'@timestamp':stamp,'version':'intake-v1','status':'normalized','reason':'recognized',
                'adapter':label+'_v1','raw':ref,'event':{'ingested':received},
                'normalized':{'index':common.NORMALIZED,'id':key},
                'recovery':{'version':version,'previous_reason':'adapter_not_supported'}}
    return 'prepared',(key,processing,event)

def configure(kind):
    label,_,rule_id,version=SOURCES[kind]
    common.configure_scope(label)
    common.WRITE_ALERTS=False
    common.VERSION=version
    common.recovery=lambda *args: recovered(kind,*args)
    selected=[rule for rule in load_rules(Path(__file__).with_name('network-waf-rules.json')) if rule['id']==rule_id]
    if len(selected)!=1 or selected[0]['type']!='single':
        raise ValueError('osaka_rule_contract')
    common.approved_rules=lambda **kwargs:selected
    return selected

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('source',choices=SOURCES)
    args=parser.parse_args()
    configure(args.source)
    common.main()
