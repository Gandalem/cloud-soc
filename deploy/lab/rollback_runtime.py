"""Explicit service/config rollback; never restores over collected data or checkpoints."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess


def rollback(root):
    from elasticsearch import Elasticsearch
    root=root.resolve()
    if root!=Path('/home/kopo/soc-mall-lab'):raise ValueError('Explicit lab required')
    runtime=root/'live-runtime';manifest=json.loads((runtime/'manifest.json').read_text())
    units=Path.home()/'.config/systemd/user'
    names=['soc-mall-managed','soc-mall-normalizer-priority','soc-mall-portal','soc-mall-normalizer']
    subprocess.run(['systemctl','--user','stop',*names],check=True)
    for name in ['soc-mall-normalizer-priority','soc-mall-managed']:
        subprocess.run(['systemctl','--user','disable',name],check=True)
        path=units/(name+'.service')
        if path.exists():
            if manifest['release'] not in path.read_text():raise ValueError('Service ownership mismatch')
            path.unlink()
    for name in ['soc-mall-portal','soc-mall-normalizer','soc-mall-app']:
        path=units/(name+'.service.d')/'50-live-runtime.conf'
        if path.exists():path.unlink()
    connection=json.loads((runtime/'config/connection.json').read_text())
    with Elasticsearch(connection['es_url'],basic_auth=('elastic',(root/'es-lab/runtime/elastic-password').read_text().strip()),
                       ca_certs=connection['ca_file'],verify_certs=True,max_retries=0) as es:
        result=es.security.invalidate_api_key(ids=[row['id'] for row in manifest['new_keys']])
        if result.get('error_count'):raise RuntimeError('Key revocation incomplete; keep manifest for retry')
    subprocess.run(['systemctl','--user','daemon-reload'],check=True)
    for name,initial in manifest['initial_units'].items():
        if name in manifest['new_units']:continue
        subprocess.run(['systemctl','--user','enable' if initial['enabled']=='enabled' else 'disable',name],check=True)
        subprocess.run(['systemctl','--user','start' if initial['active']=='active' else 'stop',name],check=True)
    for file in (runtime/'secrets').glob('*.key'):file.unlink()
    manifest['rolled_back_at']=datetime.now(timezone.utc).isoformat()
    (runtime/'manifest.json').write_text(json.dumps(manifest,indent=2))
    print(json.dumps({'services_restored':True,'collected_data_and_checkpoints':'preserved','new_keys_revoked':len(manifest['new_keys'])}))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('--apply',action='store_true');args=p.parse_args()
    if not args.apply:raise SystemExit('Explicit --apply required; no changes made')
    rollback(args.root)
