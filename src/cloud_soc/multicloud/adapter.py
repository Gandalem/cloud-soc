"""Strict interpretation of the collector's allowlisted ECS envelope, not native payloads."""
import re
from ipaddress import ip_address
from cloud_soc.privacy import sensitive, REDACTED

ADAPTER='multicloud_audit_v1'
VERSION='multicloud-audit-v1'
PATTERN='soc-multicloud-*'
DATASETS={'aws':'aws.cloudtrail','azure':'azure.activitylogs','naver':'naver.cloudactivitytracer'}
FIELDS=('soc.schema_version','soc.collector_id','resource.id')

def value(source,path):
    for key in path.split('.'):
        if not isinstance(source,dict):return None
        source=source.get(key)
    return source

def safe(source,path,*,required=False):
    item=value(source,path)
    if item in (None,'') and not required:return None
    if not isinstance(item,str) or not item.strip() or len(item)>512 or item!=item.strip() or item==REDACTED or sensitive(item):
        raise ValueError('invalid_multicloud_metadata')
    return item

def interpret(source):
    provider=value(source,'cloud.provider')
    if type(value(source,'soc.schema_version')) is not int or value(source,'soc.schema_version')!=1 or not isinstance(provider,str) or provider not in DATASETS:
        raise ValueError('invalid_multicloud_schema')
    if value(source,'event.dataset')!=DATASETS[provider]:raise ValueError('multicloud_dataset_mismatch')
    identifier=safe(source,'event.id',required=True)
    if not re.fullmatch('[0-9a-f]{64}',identifier):raise ValueError('invalid_multicloud_event_id')
    outcome=value(source,'event.outcome')
    if not isinstance(outcome,str) or outcome not in ('success','failure','unknown'):raise ValueError('invalid_multicloud_outcome')
    category=value(source,'event.category')
    if category not in (['authentication'],['configuration']):raise ValueError('invalid_multicloud_category')
    fields={'category':category[0],'action':safe(source,'event.action',required=True),'outcome':outcome,
            'api':safe(source,'event.action',required=True),'event_id':identifier,
            'cloud_account':safe(source,'cloud.account.id',required=True),'cloud_region':safe(source,'cloud.region'),
            'provider':safe(source,'event.provider'),'actor':safe(source,'user.id'),
            'collector_id':safe(source,'soc.collector_id',required=True),'resource_id':safe(source,'resource.id')}
    safe(source,'organization.id',required=True)
    address=value(source,'source.ip')
    if address is not None:
        try:fields['source_ip']=str(ip_address(address))
        except (ValueError,TypeError):raise ValueError('invalid_multicloud_source_ip') from None
    return fields

def detail(source):
    result={'version':1,'adapter':ADAPTER,'status':'recognized','audit_configuration':'not_checked',
            'fields':{},'missing':[],'process_link':'not_established',
            'limitations':['collector_projected_metadata_not_native_payload','api_result_not_attack_confirmation',
                           'event_ingested_is_collector_receipt_time']}
    try:
        result['fields']=interpret(source)
        result['missing']=[k for k in ('actor','cloud_region','provider') if not result['fields'].get(k)]
        if result['missing']:result['status']='partial'
    except ValueError:
        result.update(status='invalid',reason='multicloud_metadata_invalid')
    return result
