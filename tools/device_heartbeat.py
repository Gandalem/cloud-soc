"""Opt-in HTTPS state reporter. Reads no host logs and never changes services."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import ssl
import subprocess
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler
from urllib.error import HTTPError, URLError


def private_file(path, *, public=False):
    p=Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size>8192:
        raise ValueError('Invalid private configuration')
    if os.name!='nt' and p.stat().st_mode & (0o022 if public else 0o077):raise ValueError('Protected file permissions required')
    return p


def collector(service):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}',service):raise ValueError('Invalid service name')
    try:
        args=['sc.exe','query',service] if os.name=='nt' else ['systemctl','is-active',service]
        result=subprocess.run(args,capture_output=True,text=True,timeout=5)
        if os.name=='nt':
            state='running' if re.search(r'\bSTATE\s*:\s*4\b',result.stdout) else 'stopped' if re.search(r'\bSTATE\s*:\s*1\b',result.stdout) else 'unknown'
        else:state='running' if result.stdout.strip()=='active' else 'stopped' if result.stdout.strip() in ('inactive','failed') else 'unknown'
    except (OSError,subprocess.SubprocessError):state='unknown'
    return {'state':state}


def send(config_path,state_path,ca):
    config=json.loads(private_file(config_path).read_text(encoding='utf-8'))
    if set(config)!={'url','credential','generation','service'}:raise ValueError('Invalid configuration fields')
    url=urlsplit(config['url'])
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path!='/api/dashboard-heartbeat':
        raise ValueError('Exact HTTPS heartbeat URL required')
    if not re.fullmatch(r'[0-9a-f]{32}\.[A-Za-z0-9_-]{43}',config['credential']) or not re.fullmatch(r'[0-9a-f]{32}',config['generation']):
        raise ValueError('Invalid device credential format')
    p=Path(state_path).absolute()
    if p.is_symlink() or any(x.is_symlink() for x in p.parents):raise ValueError('Unsafe state path')
    p.parent.mkdir(parents=True,exist_ok=True)
    if not p.exists():
        fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
    if os.name!='nt' and p.stat().st_mode&0o077:raise ValueError('Private state permissions required')
    with sqlite3.connect(p) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS sequences (generation TEXT PRIMARY KEY, value INTEGER NOT NULL)')
        db.execute('BEGIN IMMEDIATE');prior=db.execute('SELECT value FROM sequences WHERE generation=?',(config['generation'],)).fetchone()
        sequence=prior[0]+1 if prior else 1
        db.execute('INSERT OR REPLACE INTO sequences VALUES (?,?)',(config['generation'],sequence));db.commit()
    body={'generation':config['generation'],'sequence':sequence,'generated_at':datetime.now(timezone.utc).isoformat(),'collector':collector(config['service'])}
    request=Request(config['url'],data=json.dumps(body).encode(),method='POST',headers={
        'Content-Type':'application/json','X-Cloud-SOC':'heartbeat','Authorization':'Bearer '+config['credential']})
    # No environment proxy, redirects, disabled verification or engine credentials.
    from urllib.request import HTTPRedirectHandler
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ssl.create_default_context(cafile=str(private_file(ca,public=True)))),NoRedirect())
    with opener.open(request,timeout=10) as response:
        data=response.read(8193)
        if len(data)>8192 or response.status!=200 or json.loads(data).get('accepted') is not True:
            raise ValueError('State report was not accepted')
    return {'accepted':True,'sequence':sequence}


def main():
    parser=argparse.ArgumentParser(description='Report collector state using a dedicated device credential')
    parser.add_argument('--config',required=True);parser.add_argument('--state',required=True);parser.add_argument('--ca',required=True)
    parser.add_argument('--interval',type=int,default=0,help='0 sends once; otherwise report every 15-300 seconds')
    args=parser.parse_args()
    if args.interval and not 15<=args.interval<=300:parser.error('Interval must be 15-300 seconds')
    previous=None
    while True:
        try:
            result=send(args.config,args.state,args.ca);accepted=True
        except (ValueError,OSError,sqlite3.Error,HTTPError,URLError):
            result={'accepted':False,'error':'state_report_failed'};accepted=False
        if not args.interval or accepted!=previous:print(json.dumps(result),flush=True)
        if not args.interval:return 0 if accepted else 1
        previous=accepted
        try:time.sleep(args.interval)
        except KeyboardInterrupt:return 0


if __name__=='__main__':raise SystemExit(main())
