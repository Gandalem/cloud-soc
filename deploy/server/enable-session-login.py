#!/usr/bin/env python3
"""Opt in using the existing admin hash; never accepts or prints a password."""
import json,os,subprocess
from pathlib import Path
if os.geteuid()!=0:raise SystemExit('sudo python3로 실행하세요')
root=Path(__file__).resolve().parents[2];state=Path('/home/lyn/cloud-soc/state/server')
base=['docker','--host','unix:///var/run/docker.sock']
ids=subprocess.check_output(base+['ps','-q','--filter','label=com.docker.compose.project=cloud-soc-central','--filter','label=com.docker.compose.service=portal'],text=True).split()
if len(ids)!=1:raise SystemExit('실행 중인 중앙 Portal 하나가 필요합니다')
obj=json.loads(subprocess.check_output(base+['inspect',ids[0]],text=True))[0]
mount=next((m['Source'] for m in obj['Mounts'] if m['Destination']=='/data'),None)
if not mount or Path(mount).resolve()!=(state/'portal').resolve():raise SystemExit('운영 경로 불일치')
env=dict(v.split('=',1) for v in obj['Config']['Env'] if '=' in v)
if env.get('SOC_LOG_ACCESS_POLICY_FILE'):raise SystemExit('사용자별 로그 접근 정책이 있습니다. 계정 매핑을 보존하기 위해 자동 전환을 중단합니다')
if env.get('SOC_USERS_FILE'):raise SystemExit('이미 별도 세션 설정이 있습니다. 기존 설정을 보존했습니다')
uid=int(subprocess.check_output(base+['exec',ids[0],'id','-u'],text=True));gid=int(subprocess.check_output(base+['exec',ids[0],'id','-g'],text=True))
hash_file=next((m['Source'] for m in obj['Mounts'] if m['Destination']=='/run/secrets/admin_hash'),None)
if not hash_file:raise SystemExit('기존 관리자 해시 마운트 확인 불가')
secret=Path(hash_file).read_text().strip()
if not secret.startswith(('scrypt:','pbkdf2:sha256:')):raise SystemExit('지원하는 기존 관리자 해시가 아닙니다')
user=env.get('SOC_ADMIN_USER','admin');target=state/'portal/portal-users.json'
if target.is_symlink():raise SystemExit('사용자 파일 링크는 허용하지 않습니다')
expected={user:{'role':'admin','password_hash':secret}}
if target.exists():
 if target.stat().st_uid!=uid or target.stat().st_mode & 0o077 or json.loads(target.read_text())!=expected:raise SystemExit('기존 사용자 설정이 다릅니다. 보존하고 중단합니다')
else:
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:
  os.fchown(f.fileno(),uid,gid);json.dump(expected,f);f.flush();os.fsync(f.fileno())
print('기존 관리자 해시로 세션 설정 준비 완료. 아직 기동/로그인 확인 전입니다.',flush=True)
subprocess.run(['bash',str(root/'deploy/server/deploy-dashboard.sh')],check=True)
print('배포 후 /api/auth/config의 mode=session 및 새 시크릿 창의 /login을 확인하세요.')
