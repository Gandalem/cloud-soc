#!/usr/bin/env python3
"""Read-only operational counts. Never prints credentials or event documents."""
import json, os, subprocess
from pathlib import Path

if os.geteuid() != 0:
    raise SystemExit('sudo python3로 실행하세요')
state = Path('/home/lyn/cloud-soc/state/server')
base = ['docker', '--host', 'unix:///var/run/docker.sock']
ids = subprocess.check_output(base + ['ps', '-aq'], text=True).split()
objects = json.loads(subprocess.check_output(base + ['inspect', *ids], text=True)) if ids else []
portal = []
for obj in objects:
    labels = obj['Config'].get('Labels') or {}
    project, service = labels.get('com.docker.compose.project', ''), labels.get('com.docker.compose.service', '')
    if project == 'cloud-soc-central' and service == 'portal' and obj['State']['Running']:
        portal.append(obj['Id'])
    if service in ('aws', 'multicloud-normalizer', 'normalizer', 'detector', 'detector-additional', 'detector-priority', 'detector-retrospective'):
        print(json.dumps({'project': project, 'service': service, 'state': obj['State']['Status'], 'restarts': obj['RestartCount']}, ensure_ascii=False), flush=True)
if len(portal) != 1:
    raise SystemExit('중앙 Portal 하나를 확인할 수 없습니다')
code = r'''
import base64,json,ssl,sys,urllib.request,urllib.error
from pathlib import Path
password=json.load(sys.stdin)['password']
ctx=ssl.create_default_context(cafile='/run/certs/ca.crt')
def query(index,body):
    req=urllib.request.Request('https://elasticsearch:9200/'+index+'/_search',data=json.dumps(body).encode(),headers={'Content-Type':'application/json','Authorization':'Basic '+base64.b64encode(('elastic:'+password).encode()).decode()})
    try:
        with urllib.request.urlopen(req,context=ctx,timeout=30) as r:return json.load(r)
    except urllib.error.HTTPError as e:
        print(json.dumps({'index':index,'http_status':e.code}));return None
    except Exception as e:
        print(json.dumps({'index':index,'error_type':type(e).__name__}));return None
for label,index,filters in [
 ('AWS raw','soc-multicloud-*',[{'term':{'cloud.provider':'aws'}}]),
 ('AWS normalized','soc-normalized-v1',[{'term':{'cloud.provider':'aws'}},{'term':{'cloud_soc.normalizer_version':'multicloud-audit-v1'}}]),
 ('multicloud processing','soc-processing-v1',[{'term':{'adapter':'multicloud_audit_v1'}}])]:
    r=query(index,{'size':0,'track_total_hits':True,'query':{'bool':{'filter':filters}},'aggs':{'latest_receipt':{'max':{'field':'event.ingested'}},'last24h':{'filter':{'range':{'event.ingested':{'gte':'now-24h'}}}},'statuses':{'terms':{'field':'status','size':10}},'reasons':{'terms':{'field':'reason','size':10}}}})
    if r: print(json.dumps({'stage':label,'total':r['hits']['total'],'aggregations':r.get('aggregations',{})}))
r=query('soc-pipeline-status',{'size':20,'query':{'match_all':{}},'_source':['state','health','error','checkpoint','last_success','lag_seconds','excluded_total','runtime.rules.id']})
if r:
    for h in r['hits']['hits']:print(json.dumps({'pipeline_id':h['_id'],'status':h['_source']}))
try:
    contract=json.loads(Path('/run/runtime/contract.json').read_text())
    found=set()
    def walk(v):
        if isinstance(v,dict):
            for x in v.values():walk(x)
        elif isinstance(v,list):
            for x in v:walk(x)
        elif isinstance(v,str) and v.startswith('AWS-') and len(v)<100:found.add(v)
    walk(contract)
    print(json.dumps({'contract_aws_rule_references':sorted(found),'note':'references alone do not prove active detection or generated alerts'}))
except Exception as e:print(json.dumps({'contract_error_type':type(e).__name__}))
'''
payload = json.dumps({'password': (state/'secrets/elastic_password').read_text().strip()})
subprocess.run(base + ['exec', '-i', portal[0], 'python', '-c', code], input=payload, text=True, check=True)
