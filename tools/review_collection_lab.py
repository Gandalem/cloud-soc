"""Final lab-only probes; no reboot and no direct raw/normalized/alert writes."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request
from urllib.parse import quote

ROOT=Path('/home/kopo/soc-mall-lab')


def reload():
    pid=int(subprocess.check_output(['systemctl','--user','show','soc-mall-waf','-p','MainPID','--value'],text=True))
    if pid<2:raise RuntimeError('Managed WAF required')
    os.kill(pid,signal.SIGUSR1);time.sleep(1)


def probes(affected=False):
    os.umask(0o077);folder=ROOT/'live-runtime/collection-policy';report=folder/'probes.json'
    if report.exists():
        if not affected:raise ValueError('Preserve previous proof; use a separate affected probe')
        report.rename(folder/('probes-earlier-'+str(time.time_ns())+'.json'))
    proxy=ROOT/'waf-lab/conf/proxy.conf';original=proxy.read_bytes()
    css=ROOT/'waf-lab/empty/css/__soc_policy_probe.css';css.parent.mkdir(mode=0o700,exist_ok=True)
    if css.exists():raise ValueError('Existing file preserved')
    css.write_text('/* synthetic collection policy probe */\n');css.chmod(0o600)
    patch=b'    ProxyPass /css/__soc_policy_probe.css !\n'
    assert original.count(b'    ProxyPass / http://')==1
    source=original.replace(b'    ProxyPass / http://',patch+b'    ProxyPass / http://',1)
    access=ROOT/'waf-lab/logs/access.tsv';before=access.stat().st_size
    result={'at':datetime.now(timezone.utc).isoformat(),'requests':{},'reboot':False}
    try:
        proxy.write_bytes(source)
        p=subprocess.run(['/usr/sbin/apache2','-t','-f',str(proxy.parent/'httpd.conf')],capture_output=True)
        assert p.returncode==0,'Probe configuration failed syntax review'
        reload()
        def get(name,path,ua='Mozilla/5.0 SOC-Policy-Review'):
            request=urllib.request.Request('http://127.0.0.1:18082'+path,headers={'Host':'mall.policy.lab','User-Agent':ua,'Accept':'text/css,*/*;q=0.1'})
            with urllib.request.urlopen(request,timeout=15) as response:
                result['requests'][name]={'request_id':response.headers.get('X-Request-ID'),'status':response.status}
                response.read(4096)
        get('normal_static','/css/__soc_policy_probe.css')
        get('query_attack','/css/__soc_policy_probe.css?q='+quote("1' OR '1'='1 -- "))
        get('header_attack','/css/__soc_policy_probe.css','sqlmap/1.7')
        get('ordinary_page','/')
        time.sleep(2)
        with access.open('rb') as f:f.seek(before);lines=f.read().decode().splitlines()
        ids={line.split('\t')[-1] for line in lines if line}
        for name,r in result['requests'].items():
            assert r['status']==200 and r['request_id'],name
            r['access_recorded']=r['request_id'] in ids
            assert r['access_recorded']==(name!='normal_static'),name
        result['passed']=True
    finally:
        proxy.write_bytes(original);reload();css.unlink()
        result['configuration_restored_to_policy']=hashlib.sha256(proxy.read_bytes()).digest()==hashlib.sha256(original).digest()
        report.write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print(json.dumps(result,ensure_ascii=False))


def evidence():
    from elasticsearch import Elasticsearch
    from cloud_soc.detection.engine import event_fingerprint
    from cloud_soc.portal.log_query import project_list_hit
    folder=ROOT/'live-runtime/collection-policy';proof=json.loads((folder/'probes.json').read_text())
    c=json.loads((ROOT/'live-runtime/config/connection.json').read_text())
    scope=json.loads((ROOT/'portal-lab/config/mall-scope.json').read_text())
    with Elasticsearch(c['es_url'],api_key=(ROOT/'live-runtime/secrets/reader.key').read_text().strip(),ca_certs=c['ca_file'],max_retries=0) as es:
        def rows(name):return es.search(index=scope['raw'],size=100,query={'term':{'security_mall_edge.request_id':proof['requests'][name]['request_id']}})['hits']['hits']
        end=time.monotonic()+90
        while time.monotonic()<end:
            if all(len(rows(name))>=2 for name in ('query_attack','header_attack')):break
            time.sleep(1)
        assert not rows('normal_static'),'Excluded normal request reached central storage'
        checks={}
        for name in ('query_attack','header_attack','ordinary_page'):
            hits=rows(name);assert hits,name
            if name!='ordinary_page':assert {'access','waf'} <= {h['_source']['security_mall_edge']['stream'] for h in hits},name
            checks[name]=[project_list_hit(h)['log_type']['label'] for h in hits]
        rules=json.loads((folder/'browser-rules.json').read_text())
        alerts=es.search(index=scope['alerts'],size=100,query={'terms':{'rule.id':[r['key'] for r in rules['rules']]}})['hits']['hits']
        assert {h['_source']['rule']['id'] for h in alerts}=={r['key'] for r in rules['rules']}
        count=0
        for h in alerts:
            for ref in h['_source']['cloud_soc']['provenance']['evidence']:
                raw=es.get(index=ref['raw']['index'],id=ref['raw']['id'])['_source'];assert raw['organization']['id']=='mall-isolated'
                normalized=es.get(index=ref['normalized']['index'],id=ref['normalized']['id'])['_source']
                assert normalized['cloud_soc']['provenance']['raw']==ref['raw']
                normalized['_cloud_soc_meta']={'index':ref['normalized']['index'],'document_id':ref['normalized']['id']}
                assert event_fingerprint(normalized)==ref['event_hash'];count+=1
        proof['central_types']=checks;proof['alerts']=len(alerts);proof['exact_evidence_references']=count;proof['central_passed']=True
        (folder/'evidence.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2))
        print(json.dumps({'central_passed':True,'alerts':len(alerts),'evidence_references':count,'types':checks},ensure_ascii=False))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['probes','evidence']);p.add_argument('--affected',action='store_true');args=p.parse_args()
    probes(args.affected) if args.phase=='probes' else evidence()
