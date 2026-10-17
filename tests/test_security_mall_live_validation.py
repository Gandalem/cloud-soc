"""One-shot CLI tests with existing synthetic events; no network or service actions."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_security_mall_correlation import SCOPE, app, detected, edge, stamp

FILE = Path(__file__).resolve().parents[1] / 'deploy/security-mall/validate_correlation_triage.py'
spec = importlib.util.spec_from_file_location('mall_live_validation', FILE)
tool = importlib.util.module_from_spec(spec);spec.loader.exec_module(tool)


def test_real_engine_processing_revision_and_rollbacks_in_isolated_sqlite(tmp_path):
    hits = [app(), edge('web'), edge('waf')]
    result = tool.process(hits, detected([hits[0]]), SCOPE, tmp_path, {'start': stamp(0), 'end': stamp(1200)})
    assert result['three_stream_bundles'] == 1 and result['matched_hash_references'] == 1
    assert result['alert_triage'][0]['triage_score'] == 20
    assert all(result['revision_checks'].values())


def test_history_no_id_remains_partial_not_fabricated_complete(tmp_path):
    hits = [app(1, rid=None), app(2, rid=None)]
    result = tool.process(hits, detected(hits), SCOPE, tmp_path, {'start': stamp(0), 'end': stamp(1200)})
    assert result['states']['unlinked'] == 2 and result['three_stream_bundles'] == 0
    assert result['alert_links_complete'] == 2 and all(row['triage_score'] == 20 for row in result['alert_triage'])


def test_http_transport_has_no_write_or_cross_origin_operation():
    reader = tool.Reader.__new__(tool.Reader)
    for method, path in [('GET','/'), ('POST','/x/_bulk'), ('PUT','/x/_doc/1'), ('DELETE','/x'),
                         ('POST','/_security/api_key'), ('POST','https://external.invalid/_search'), ('POST','/*/_search')]:
        with pytest.raises(tool.ValidationError, match='es_operation_forbidden'):reader.request(method,path,{})


def test_query_scope_cutoff_limits_and_full_source_are_explicit():
    class Fake:
        def request(self, method, path, body):
            self.call=(method,path,body)
            return {'_shards':{'failed':0},'hits':{'total':{'value':0,'relation':'eq'},'hits':[]}}
    client=Fake();frame={'start':stamp(0),'end':stamp(100)}
    assert tool.search(client,SCOPE.normalized_indices[0],SCOPE,frame,stamp(120),'normalized') == []
    method,path,body=client.call
    assert method=='POST' and path.endswith('/_search') and body['size']==500 and body['track_total_hits'] is True
    assert '_source' not in body  # Actual detector hash needs complete source, not a projection.
    fields=json.dumps(body['query'])
    assert all(field in fields for field in ('organization.id','host.id','service.name','event.ingested','cloud_soc.normalized_at'))


def test_missing_read_permission_and_wrong_write_key_are_not_bypassed():
    class Fake:
        def request(self,*args):return self.value
    client=Fake();client.value={'cluster':{'all':False,'manage':False},
        'index':{'one':{name:False for name in tool.PRIVILEGES}}}
    name=tool.APPROVED_INDICES[0];client.value['index']={name:client.value['index']['one']}
    assert tool.permissions(client,[name]) == [name]
    client.value['index'][name]['create_doc']=True
    with pytest.raises(tool.ValidationError,match='reader_has_write_privileges'):tool.permissions(client,[name])


def test_privacy_rejection_signature_and_summary_do_not_copy_source(tmp_path):
    hit=app();hit.update(_seq_no=1,_primary_term=1,_version=1)
    original=deepcopy(hit);assert tool.no_original(hit['_source'])
    hit['_source']['message']='PRIVATE_CANARY';assert not tool.no_original(hit['_source'])
    assert 'PRIVATE_CANARY' not in tool.signature(hit)
    assert tool.signature(original) != tool.signature(hit)


def test_actual_cli_invalid_arguments_have_nonzero_exit_without_secrets():
    result=subprocess.run([sys.executable,str(FILE)],capture_output=True,text=True,timeout=20,
                          env=dict(os.environ,PYTHONPATH=str(FILE.parents[2]/'src')))
    assert result.returncode == 2 and 'Traceback' not in result.stderr


def test_safe_output_directory_failure_uses_actual_cli_entrypoint(tmp_path):
    result=subprocess.run([sys.executable,str(FILE),'--profile','history','--start',stamp(0),'--end',stamp(1200),
                           '--output-dir',str(tmp_path/'not-vm-lab'),'--api-key-file','unused'],capture_output=True,text=True,timeout=20,
                          env=dict(os.environ,PYTHONPATH=str(FILE.parents[2]/'src')))
    data=json.loads(result.stdout)
    assert result.returncode==1 and data['reason']=='isolated_output_required'
    assert not (tmp_path/'not-vm-lab').exists() and 'Traceback' not in result.stderr


def test_main_checks_only_read_privileges_without_cluster_monitor(tmp_path, monkeypatch, capsys):
    base=tmp_path/'lab';config=base/'portal-lab/config';config.mkdir(parents=True)
    metadata=config/'read-key-metadata.json';metadata.write_text(json.dumps({'expiration':2000000000000}));metadata.chmod(0o600)
    calls=[]
    class Fake:
        def __init__(self,*args):pass
        def request(self,method,path,body):
            calls.append((method,path))
            return {'cluster':{'all':False,'manage':False},'index':{
                SCOPE.normalized_indices[0]:{key:False for key in tool.PRIVILEGES}}}
    monkeypatch.setattr(tool,'BASE',base);monkeypatch.setattr(tool,'Reader',Fake)
    monkeypatch.setattr(tool,'reader_policy',lambda _:None)
    monkeypatch.setattr(tool,'plan',lambda _: (SCOPE,[SCOPE.normalized_indices[0]]))
    monkeypatch.setattr(tool,'permissions',lambda client,names: (client.request('POST','/_security/user/_has_privileges',{}),names)[1])
    result=tool.main(['--profile','history','--start',stamp(0),'--end',stamp(100),
                     '--output-dir',str(base/'validation-7ab/result'),'--api-key-file','unused'])
    assert result==4 and calls==[('POST','/_security/user/_has_privileges')]
    assert json.loads(capsys.readouterr().out)['reason']=='reader_scope_missing'


def test_synthetic_auth_and_repetition_are_separate_from_live_es(tmp_path):
    from test_security_mall_triage import auth_hits, repeated_hits
    auth=tmp_path/'auth';auth.mkdir(mode=0o700)
    repeat=tmp_path/'repeat';repeat.mkdir(mode=0o700)
    hits=auth_hits()
    result=tool.process(hits,detected(hits),SCOPE,auth,{'start':stamp(0),'end':stamp(1200)})
    assert len(result['alert_triage'])==1 and result['alert_triage'][0]['triage_score']==60
    assert result['alert_triage'][0]['original_severity']=='medium'
    hits=repeated_hits()
    result=tool.process(hits,detected(hits),SCOPE,repeat,{'start':stamp(0),'end':stamp(1200)})
    assert sorted(item['triage_score'] for item in result['alert_triage'])==[20,20,30]


def test_real_normalizer_raw_provenance_mismatch_fails_closed():
    from test_security_mall import hit, PROCESSED
    raw=hit();identifier,record,event=tool.normalize(raw,PROCESSED)
    assert record['status']=='normalized'
    normalized={'_index':'soc-normalized-mall-unit','_id':identifier,'_source':event}
    assert tool.provenance([raw],[normalized])==1
    event['event']['id']='00000000-0000-4000-8000-000000000001'
    with pytest.raises(tool.ValidationError,match='raw_normalized_metadata_mismatch'):tool.provenance([raw],[normalized])
