"""Opt-in, reversible conditional access logging for the current private lab.

No key changes, original document writes, registry resets or host reboot.
Syntax/reload are executed only when the final-review operator uses --apply.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

MARKER='# cloud-soc security-focused-v1'
CONTROL='SecAction "id:10003,phase:5,pass,nolog,noauditlog,t:none,setenv:SOC_COLLECTION_READY=1,setenv:SOC_COLLECTION_SEVERITY=%{HIGHEST_SEVERITY}"'
STATIC=r'^/(?:(?:css|js|images|fonts)/[A-Za-z0-9_/-]+\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2)|favicon\.ico)$'
EXCLUDE=("%{REQUEST_METHOD} in {'GET','HEAD'} && %{REQUEST_STATUS} in {'200','304'} && "
         "%{QUERY_STRING} == '' && req('Content-Length') in {'','0'} && req('Transfer-Encoding') == '' && "
         "reqenv('SOC_COLLECTION_READY') == '1' && reqenv('SOC_COLLECTION_SEVERITY') == '255' && "
         "%{REQUEST_URI} =~ m#"+STATIC+"#")


def candidates(proxy,after,before):
    if MARKER in proxy or MARKER in after:raise ValueError('Policy already present; do not overwrite')
    if re.search(r'^\s*SecRule\b',before+'\n'+after,re.M):raise ValueError('Unreviewed custom rule context; retain access logs')
    if 'id:10003' in before+'\n'+after or 'ctl:auditLogParts=AKZ' not in after:
        raise ValueError('Metadata/privacy rule scope mismatch')
    original='CustomLog "${WAF_LAB_ROOT}/logs/access.tsv" soc_mall_safe'
    if proxy.count(original)!=1:raise ValueError('Exact existing safe access output required')
    replacement=original+' "expr=!('+EXCLUDE+')"'
    return proxy.replace(original,MARKER+'\n    '+replacement),after.rstrip()+'\n'+MARKER+'\n'+CONTROL+'\n'


def write(path,data):
    fd,temporary=tempfile.mkstemp(prefix='.collection-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
        os.replace(temporary,path)
        d=os.open(path.parent,os.O_RDONLY)
        try:os.fsync(d)
        finally:os.close(d)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def apply(root,rollback=False):
    root=root.resolve()
    if root!=Path('/home/kopo/soc-mall-lab'):raise ValueError('Current private lab only')
    os.umask(0o077);conf=root/'waf-lab/conf';store=root/'live-runtime/collection-policy'
    files=[conf/'proxy.conf',conf/'after-crs.conf']
    for p in [*files,conf/'before-crs.conf']:
        if p.is_symlink() or p.stat().st_uid!=os.getuid() or p.stat().st_mode & 0o077:raise ValueError('Private owned configuration required')
    metadata=store/'applied.json'
    if rollback:
        saved=json.loads(metadata.read_text())
        for p in files:
            if hashlib.sha256(p.read_bytes()).hexdigest()!=saved['sha256'][p.name]:raise ValueError('Configuration changed; preserve operator edits')
        changed=[(p,(store/(p.name+'.before')).read_bytes()) for p in files]
    else:
        if metadata.exists():raise ValueError('Existing policy preserved; explicit rollback required')
        values=candidates(files[0].read_text(),files[1].read_text(),(conf/'before-crs.conf').read_text())
        store.mkdir(mode=0o700,exist_ok=True)
        for p in files:
            with (store/(p.name+'.before')).open('xb') as out:out.write(p.read_bytes())
        changed=[(p,value.encode()) for p,value in zip(files,values)]
    original={p:p.read_bytes() for p in files}
    try:
        for p,value in changed:write(p,value)
        checked=subprocess.run(['/usr/sbin/apache2','-t','-f',str(conf/'httpd.conf')],capture_output=True)
        if checked.returncode:raise RuntimeError('Apache policy syntax rejected; original configuration restored')
        pid=int(subprocess.check_output(['systemctl','--user','show','soc-mall-waf','-p','MainPID','--value'],text=True).strip())
        if pid<2:raise RuntimeError('Existing managed WAF required')
        os.kill(pid,signal.SIGUSR1)
    except Exception:
        for p,value in original.items():write(p,value)
        raise
    if rollback:
        metadata.rename(store/('rolled-back-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'.json'))
    else:
        write(metadata,json.dumps({'policy':'security-focused-v1','applied_at':datetime.now(timezone.utc).isoformat(),
             'scope':'successful query-free static GET/HEAD with final ModSecurity no-severity marker',
             'sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files}}).encode())
    print(json.dumps({'policy':'security-focused-v1','rollback':rollback,'reboot':False,'original_log_format_preserved':True}))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',action='store_true');args=parser.parse_args()
    if not args.apply:raise SystemExit('Explicit --apply required')
    apply(args.root,args.rollback)
