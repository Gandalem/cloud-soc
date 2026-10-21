"""Opt-in current lab deployment. Leaves original credentials and history intact.

Run on the lab VM using its venv after source review. Does not start/reboot services.
All private material stays on that VM. Rollback files are retained under runtime/backup.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys


def install(root,release):
    from elasticsearch import Elasticsearch
    from cloud_soc.elastic.repository import ensure_security_alerts_index, ensure_provenance_mapping
    os.umask(0o077)
    root=root.resolve();release=release.resolve()
    if root!=Path('/home/kopo/soc-mall-lab') or not (root/'collection-services/config/collection.json').is_file():
        raise ValueError('Explicit existing loopback lab required')
    runtime=root/'live-runtime'
    if (runtime/'manifest.json').exists():raise ValueError('Deployment already recorded; preserve state and use the documented update procedure')
    for name in ('config','secrets','state','backup','logs'):(runtime/name).mkdir(parents=True,exist_ok=True,mode=0o700)
    c=json.loads((root/'collection-services/config/collection.json').read_text())
    scope=json.loads((root/'portal-lab/config/mall-scope.json').read_text())
    raw=[c['app_index'],c['edge_index']]
    if list(scope['raw'])!=raw or list(scope['normalized'])!=[c['normalized_index']]:
        raise ValueError('Original Portal and collection scope must match; no implicit scope change')
    units=Path.home()/'.config/systemd/user';units.mkdir(parents=True,exist_ok=True)
    names=['soc-mall-app','soc-mall-waf','soc-mall-portal','soc-mall-normalizer',
           'soc-mall-normalizer-priority','soc-mall-managed']
    initial={n:{'active':subprocess.run(['systemctl','--user','is-active',n],capture_output=True,text=True).stdout.strip(),
                'enabled':subprocess.run(['systemctl','--user','is-enabled',n],capture_output=True,text=True).stdout.strip()} for n in names}
    # Preserve original service definitions and databases, with SQLite's consistent backup API.
    for n in names:
        source=units/(n+'.service')
        if source.exists():shutil.copy2(source,runtime/'backup'/(n+'.service'))
    for source in [root/'portal-lab/state/cases.sqlite',root/'collection-services/state/normalizer.sqlite']:
        if source.exists():
            with sqlite3.connect(source) as src,sqlite3.connect(runtime/'backup'/('cases.sqlite' if source.name=='cases.sqlite' else 'normalizer.sqlite')) as dst:src.backup(dst)
    shutil.copy2(root/'portal-lab/portal_wsgi.py',runtime/'backup/portal_wsgi.py')
    now=datetime.now(timezone.utc);recent_start=(now-timedelta(minutes=15)).isoformat()
    normalized=c['normalized_index'];records=c['records_index'];status=c['status_index']
    revisions='soc-managed-alert-revisions-live-20261020'
    manifest={'created_at':now.isoformat(),'root':str(root),'release':str(release),'initial_units':initial,
              'new_keys':[],'new_units':['soc-mall-normalizer-priority','soc-mall-managed'],
              'scope':scope,'revisions':revisions,'expiry_days':90}
    (runtime/'manifest.json').write_text(json.dumps(manifest,indent=2))
    ca=str(root/'es-lab/runtime/certs/ca.crt');url=c['es_url']
    with Elasticsearch(url,basic_auth=('elastic',(root/'es-lab/runtime/elastic-password').read_text().strip()),
                       ca_certs=ca,verify_certs=True,max_retries=0,request_timeout=15) as es:
        ensure_security_alerts_index(es,index_name=revisions)
        ensure_provenance_mapping(es,revisions,apply=True)
        ensure_provenance_mapping(es,scope['alerts'],apply=False)
        roles={
            'reader':[{'names':[*raw,normalized,records,status,scope['alerts']], 'privileges':['read','view_index_metadata']}],
            'normalizer':[{'names':raw,'privileges':['read','view_index_metadata']},
                          {'names':[normalized,records],'privileges':['create_doc']},
                          {'names':[status],'privileges':['index']}],
            'managed':[{'names':[*raw,normalized],'privileges':['read','view_index_metadata']},
                       {'names':[scope['alerts'],revisions],'privileges':['read','create_doc','view_index_metadata']}]
        }
        for name,indices in roles.items():
            key=es.security.create_api_key(name='lab-live-'+name+'-'+now.strftime('%Y%m%dT%H%M%S'),expiration='90d',
                role_descriptors={'lab':{'cluster':[],'indices':indices}})
            (runtime/'secrets'/(name+'.key')).write_text(key['encoded'])
            manifest['new_keys'].append({'id':key['id'],'purpose':name,'expiration':key['expiration']})
            (runtime/'manifest.json').write_text(json.dumps(manifest,indent=2))
    managed={'organizations':[c['organization_id']],'normalized_indices':[normalized],'raw_indices':raw,
             'alerts_index':scope['alerts'],'revisions_index':revisions,'max_events':20000,'max_alerts':100000,
             'late_seconds':900,'future_seconds':30}
    (runtime/'config/managed.json').write_text(json.dumps(managed))
    (runtime/'config/connection.json').write_text(json.dumps({'es_url':url,'ca_file':ca,'processing_scope':{'records':records,'status':status}}))
    for mode in ['history','recent']:
        cfg={'mode':mode,'start':c['initial_start'] if mode=='history' else recent_start,
             'state':str(root/'collection-services/state/normalizer.sqlite') if mode=='history' else str(runtime/'state/recent.sqlite'),
             'es_url':url,'ca_file':ca,'api_key_file':str(runtime/'secrets/normalizer.key'),'source_indices':raw,
             'normalized_index':normalized,'records_index':records,'status_index':status,
             'interval_seconds':5 if mode=='history' else 2,'window_minutes':60,'max_pages':10 if mode=='history' else 50,
             'receipt_lag_seconds':30 if mode=='history' else 2,'overlap_seconds':900,'burst_cycles':3}
        (runtime/'config'/(mode+'.json')).write_text(json.dumps(cfg))
    shutil.copy2(release/'deploy/lab/portal_wsgi.py',runtime/'portal_wsgi.py')
    python=root/'portal-lab/venv/bin/python';gunicorn=root/'portal-lab/venv/bin/gunicorn'
    environment=f'Environment=PYTHONPATH={release}/src\nEnvironment=SOC_LAB_ROOT={root}\nEnvironment=SOC_LAB_RELEASE={release}\n'
    def override(name,text):
        folder=units/(name+'.service.d');folder.mkdir(exist_ok=True)
        target=folder/'50-live-runtime.conf'
        if target.exists():raise ValueError('Existing runtime override must be preserved')
        target.write_text('[Service]\n'+text)
    override('soc-mall-normalizer','EnvironmentFile=\n'+environment+f'ExecStart=\nExecStart={python} -m cloud_soc.processing.scoped_service --config {runtime}/config/history.json\n')
    override('soc-mall-portal',environment+f'WorkingDirectory={runtime}\nExecStart=\nExecStart={gunicorn} --bind 127.0.0.1:18081 --workers 1 --threads 4 --timeout 45 --access-logfile {root}/portal-lab/logs/access.log --error-logfile {root}/portal-lab/logs/error.log portal_wsgi:app\n')
    override('soc-mall-app','SuccessExitStatus=143\n')
    commands={
        'soc-mall-normalizer-priority':f'{python} -m cloud_soc.processing.scoped_service --config {runtime}/config/recent.json',
        'soc-mall-managed':f'{python} -m cloud_soc.detection.managed_cli --config {runtime}/config/managed.json --library {root}/portal-lab/state/cases.sqlite --es-url {url} --ca-file {ca} --api-key-file {runtime}/secrets/managed.key --interval 2'
    }
    for name,command in commands.items():
        target=units/(name+'.service')
        if target.exists():raise ValueError('Do not replace an existing service')
        after='soc-mall-portal.service' if name=='soc-mall-managed' else 'network-online.target'
        target.write_text(f'[Unit]\nDescription=SOC lab {name}\nAfter={after}\n[Service]\nType=simple\nWorkingDirectory={runtime}\n{environment}UMask=0077\nExecStart={command}\nRestart=on-failure\nRestartSec=5\n[Install]\nWantedBy=default.target\n')
    subprocess.run(['systemctl','--user','daemon-reload'],check=True)
    print(json.dumps({'installed':True,'services_started':False,'new_keys':len(manifest['new_keys']),
                      'root':str(runtime),'original_checkpoint_preserved':True}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('--release',required=True,type=Path);p.add_argument('--apply',action='store_true');args=p.parse_args()
    if not args.apply:raise SystemExit('Explicit --apply required; no changes made')
    sys.path.insert(0,str(args.release/'src'))
    install(args.root,args.release)
