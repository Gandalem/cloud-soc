"""Final acceptance of selection, typed display and unchanged evidence references."""
import json
from pathlib import Path
import re

import pytest

from cloud_soc.portal.log_query import project_list_hit
from cloud_soc.portal.log_types import classification

ROOT=Path(__file__).resolve().parents[1]


def test_embedded_windows_catalogue_matches_the_single_source():
    c=json.loads((ROOT/'deploy/agents/security-catalog.json').read_text())
    ps=(ROOT/'deploy/agents/discover-windows.ps1').read_text()
    cs=(ROOT/'deploy/agents/discovery-native.cs').read_text()
    for channel,ids in c['windows_channels'].items():
        assert "'"+channel+"' = '"+ids+"'" in ps
        assert '{ '+json.dumps(channel)+', '+json.dumps(ids)+' },' in cs
    assert 'Application' not in c['windows_channels']
    assert '4624' in c['windows_channels']['Security'].split(',')
    assert '4625' in c['windows_channels']['Security'].split(',')
    assert '1102' in c['windows_channels']['Security'].split(',')


@pytest.mark.parametrize(('path','expected'),[
    ('/var/log/auth.log',True),('/var/log/auth.log.1',True),('/var/log/secure',True),
    ('/var/log/audit/audit.log.12',True),('/var/log/ufw.log',True),
    ('/var/log/auth.log.evil',False),('/var/log/cloud-init.log',False),
    ('/var/log/syslog',False),('/var/log/installer/auth.log',False),('/tmp/auth.log',False),
])
def test_linux_default_paths_are_not_recursive_text_collection(path,expected):
    c=json.loads((ROOT/'deploy/agents/security-catalog.json').read_text())
    assert bool(re.fullmatch(c['linux_core_files'],path)) is expected


@pytest.mark.parametrize(('source','code','label'),[
    ({'labels':{'log_source':'linux_file'},'log':{'file':{'path':'/var/log/auth.log'}}},'authentication','Linux 인증·권한'),
    ({'labels':{'log_source':'linux_file'},'log':{'file':{'path':'/var/log/audit/audit.log'}}},'security_audit','Linux 보안 감사'),
    ({'labels':{'log_source':'linux_journald'},'systemd':{'transport':'kernel'}},'kernel_security','Linux 커널·보안 정책'),
    ({'labels':{'log_source':'agent_health'}},'collection_health','에이전트 수집 상태'),
    ({'labels':{'log_source':'windows_event'},'winlog':{'channel':'Security','event_id':1102}},'audit_change','Windows 감사 중단·정책 변경'),
    ({'labels':{'log_source':'windows_event'},'winlog':{'channel':'Mystery','event_id':1102}},'windows_other','Windows 기타 이벤트'),
])
def test_type_is_metadata_not_an_attack_or_altered_raw_document(source,code,label):
    source={'organization':{'id':'one'},**source}
    before=json.dumps(source,sort_keys=True)
    row=project_list_hit({'_index':'soc-host-raw-fixture','_id':'same-id','_source':source})
    assert row['log_type']['code']==code and row['log_type']['label']==label
    assert row['reference']=={'index':'soc-host-raw-fixture','id':'same-id'}
    assert json.dumps(source,sort_keys=True)==before
    assert row['organization']=='one'


def test_unknown_sources_and_sensitive_values_do_not_gain_trusted_types():
    row=project_list_hit({'_index':'soc-host-raw-fixture','_id':'one',
      '_source':{'labels':{'log_source':'not-configured'},'log':{'file':{'path':'/var/log/auth.log'}}}})
    assert row['log_type']['code']=='unknown'
    assert classification({'source_kind':'linux_file','file_path':'/var/log/auth.log.evil'}, {})['code']=='linux_other'


def test_lab_access_exclusion_is_narrow_and_waf_aware():
    from importlib.util import spec_from_file_location,module_from_spec
    spec=spec_from_file_location('lab_policy',ROOT/'deploy/lab/apply_collection_policy.py')
    module=module_from_spec(spec);spec.loader.exec_module(module)
    proxy='CustomLog "${WAF_LAB_ROOT}/logs/access.tsv" soc_mall_safe'
    after='SecAction "id:10001,phase:5,nolog,ctl:auditLogParts=AKZ"'
    p,a=module.candidates(proxy,after,'# no custom rules')
    for value in ('SOC_COLLECTION_READY','SOC_COLLECTION_SEVERITY','QUERY_STRING','Content-Length','Transfer-Encoding','REQUEST_STATUS'):
        assert value in p
    assert 'HIGHEST_SEVERITY' in a
    with pytest.raises(ValueError):module.candidates(proxy,after,'SecRule ARGS x "id:123"')


def test_web_list_uses_only_validated_http_and_service_metadata():
    from cloud_soc.parsers.security_mall_edge import parse_access, envelope
    body=parse_access('soc-mall-access-v1\t2026-10-20T12:00:00+0000\t192.0.2.1\tGET\t/static\t200\t10\t'+'A'*27+'\n')
    source=envelope(body,'org-one','host-one');source['event']['ingested']='2026-10-20T12:00:01Z'
    row=project_list_hit({'_index':'soc-host-raw-one','_id':'one','_source':source})
    fields=row['interpretation']['fields']
    assert fields['http_status']==200 and fields['http_method']=='GET'
    assert fields['path']=='/static' and fields['service_name']=='security-mall'
    source['security_mall_edge']['path']='/untrusted?secret=value'
    rejected=project_list_hit({'_index':'soc-host-raw-one','_id':'one','_source':source})
    assert not rejected['interpretation']['fields']
