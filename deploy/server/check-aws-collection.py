#!/usr/bin/env python3
"""Read-only AWS deployment metadata; no credential values or log content."""
import json, os, stat, subprocess
from pathlib import Path
if os.geteuid()!=0: raise SystemExit('sudo python3로 실행하세요')
def emit(**v): print(json.dumps(v,ensure_ascii=False))
def meta(p):
    p=Path(p)
    if p.is_symlink():emit(path=str(p),symlink=True);return False
    if not p.exists():emit(path=str(p),exists=False);return False
    s=p.stat();emit(path=str(p),exists=True,uid=s.st_uid,mode=f'{stat.S_IMODE(s.st_mode):04o}')
    return p.is_file()
def config(p):
    if not meta(p):return
    try:
        obj=json.loads(p.read_text())
        for s in obj.get('sources',[]):
            if s.get('provider')=='aws':
                emit(aws_source={k:s.get(k) for k in ('id','region','start')},account_configured=bool(s.get('account')),organization_configured=bool(s.get('organization')),profile_configured=bool(s.get('profile')))
    except Exception as e:emit(path=str(p),error_type=type(e).__name__)
root=Path('/home/lyn/cloud-soc/state/server/multicloud')
config(root/'aws-config.json')
for repo in (Path('/home/lyn/cloud-soc'),Path(__file__).resolve().parents[2]):config(repo/'config/multicloud.json')
p=root/'aws.compose.json'
if meta(p):
    try:
        obj=json.loads(p.read_text());s=obj.get('services',{}).get('aws',{})
        emit(saved_aws_service=bool(s),project=obj.get('name'))
        for f in s.get('env_file',[]):
            f=Path(f['path'] if isinstance(f,dict) else f)
            if not f.is_absolute():f=p.parent/f
            if meta(f):
                allowed={'AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_CREDENTIAL_EXPIRATION','AWS_PROFILE'}
                names=set()
                for line in f.read_text().splitlines():
                    k,sep,v=line.strip().removeprefix('export ').partition('=')
                    if sep and k in allowed and v.strip():names.add(k)
                emit(credential_file=str(f),present_names=sorted(names))
        for v in s.get('volumes',[]):
            if isinstance(v,dict) and v.get('target') in ('/state','/run/secrets/es-writer','/run/secrets/es-ca.crt'):meta(v['source'])
    except Exception as e:emit(compose_error_type=type(e).__name__)
base=['docker','--host','unix:///var/run/docker.sock']
ids=subprocess.check_output(base+['ps','-aq'],text=True).split()
objs=json.loads(subprocess.check_output(base+['inspect',*ids],text=True)) if ids else []
for o in objs:
    labels=o['Config'].get('Labels') or {}; service=labels.get('com.docker.compose.service','')
    env={s.partition('=')[0]:s.partition('=')[2] for s in o['Config'].get('Env',[])}
    image=o['Config'].get('Image','').lower()
    if service=='aws' or any(k.startswith('AWS_') for k in env) or any(t in image for t in ('filebeat','logstash','fluent','vector')):
        emit(container=o['Name'],project=labels.get('com.docker.compose.project'),service=service,state=o['State']['Status'],restarts=o['RestartCount'],aws_environment_names=sorted(k for k in env if k.startswith('AWS_')),mount_targets=[m['Destination'] for m in o.get('Mounts',[])])
for p in (Path('/home/lyn/.aws/config'),Path('/home/lyn/.aws/credentials')):meta(p)
emit(note='설정 존재/변수 이름만 확인. 자격증명 유효성·AWS 권한·수집 성공은 미검증. 변경 없음.')
