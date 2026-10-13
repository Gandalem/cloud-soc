"""Central pull: pinned SSH metadata export -> strict-TLS immutable ES creates."""
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import ssl

from cloud_soc.web.metadata import INDEX, digest, scope, validate


def protected(path):
    path=Path(path)
    if not path.is_file() or path.is_symlink() or path.parent.is_symlink() or (os.name!='nt' and path.stat().st_mode&0o077):raise ValueError('unprotected_web_credential')
    return path


def ssh_export(config,after):
    args=['ssh','-F','/dev/null','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes',
        '-o','IdentityAgent=none','-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','RequestTTY=no',
        '-o','GlobalKnownHostsFile=/dev/null','-o','UserKnownHostsFile='+str(protected(config['known_hosts'])),
        '-o','ConnectTimeout=5','-o','ServerAliveInterval=5','-o','ServerAliveCountMax=1',
        '-i',str(protected(config['ssh_key'])),'ec2-user@13.208.175.237','cloud-soc-web-export']
    request=json.dumps({'schema':1,'after':after,'limit':100}).encode()
    result=subprocess.run(args,input=request,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20)
    if result.returncode or len(result.stdout)>512*1024:raise ValueError('web_export_unavailable')
    return json.loads(result.stdout)


def check_export(reply,config,after):
    if not isinstance(reply,dict) or set(reply)!={'schema','stream_id','first_seq','last_seq','rows','health'} or type(reply['schema']) is not int or reply['schema']!=1 or not isinstance(reply['stream_id'],str) or not re.fullmatch(r'[a-f0-9]{32}',reply['stream_id']):raise ValueError('invalid_export')
    if not isinstance(reply['rows'],list) or len(reply['rows'])>100:raise ValueError('invalid_export_budget')
    fields={'queued_rows','queued_bytes','malformed','evicted','source_gaps','observed'}
    if not isinstance(reply['health'],dict) or set(reply['health'])!=fields or any(type(v) is not int or not 0<=v<2**53 for v in reply['health'].values()):raise ValueError('invalid_health')
    for k in ('first_seq','last_seq'):
        if reply[k] is not None and (type(reply[k]) is not int or not 1<=reply[k]<2**53):raise ValueError('invalid_sequence')
    if (reply['first_seq'] is None)!=(reply['last_seq'] is None) or (reply['first_seq'] is not None and reply['first_seq']>reply['last_seq']):raise ValueError('invalid_bounds')
    previous=after
    for row in reply['rows']:
        if not isinstance(row,dict) or set(row)!={'seq','body'} or type(row['seq']) is not int or not previous<row['seq']<2**53 or reply['first_seq'] is None or not reply['first_seq']<=row['seq']<=reply['last_seq']:raise ValueError('invalid_sequence')
        body=validate(row['body'])
        if (body['organization']['id'],body['host']['id'],body['container']['id'],body['cloud']['region'])!=(config['organization'],config['host'],config['container'],config['region']):raise ValueError('web_scope_mismatch')
        previous=row['seq']
    return reply


def create_publisher(config):
    parsed=urllib.parse.urlsplit(config['es_url'])
    if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:raise ValueError('strict_https_required')
    context=ssl.create_default_context(cafile=str(protected(config['ca_file'])))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            raise ValueError('publisher_redirect_refused')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context),NoRedirect())
    key=protected(config['api_key_file']).read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9+/=_-]{16,4096}',key):raise ValueError('invalid_web_publisher_key')
    def publish(body):
        validate(body)
        request=urllib.request.Request(config['es_url']+'/'+INDEX+'/_create/'+body['event']['id'],method='PUT',
            headers={'Authorization':'ApiKey '+key,'Content-Type':'application/json'},data=json.dumps(body).encode())
        try:
            with opener.open(request,timeout=10) as response:
                if response.status!=201:raise ValueError('unexpected_create')
                return 'created'
        except urllib.error.HTTPError as error:
            if error.code==409:
                data=error.read(65537)
                if len(data)<=65536 and json.loads(data).get('error',{}).get('type')=='version_conflict_engine_exception':return 'existing'
            raise ValueError('web_publish_failed') from None
    return publish


def _run_once(config,*,fetch=ssh_export,publish=None):
    scope(config['organization'],config['host'],config['container'],config['region'])
    path=Path(config['state']);path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink() or (path.exists() and os.name!='nt' and path.stat().st_mode&0o077):raise ValueError('unprotected_relay_state')
    with closing(sqlite3.connect(path,timeout=0)) as db:
        if os.name!='nt':os.chmod(path,0o600)
        db.execute('CREATE TABLE IF NOT EXISTS relay (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT NOT NULL,stream TEXT NOT NULL,seq INTEGER NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS report (id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL)');db.commit();db.execute('BEGIN IMMEDIATE')
        old=db.execute('SELECT binding,stream,seq FROM relay WHERE id=1').fetchone();binding=digest(config)
        if old and old[0]!=binding:raise ValueError('relay_identity_changed')
        after=old[2] if old else 0;reply=check_export(fetch(config,after),config,after)
        if old and old[1]!=reply['stream_id']:raise ValueError('producer_stream_changed')
        db.execute('INSERT OR IGNORE INTO relay VALUES(1,?,?,?)',(binding,reply['stream_id'],after));db.commit()
        publisher=publish or create_publisher(config);counts={'created':0,'existing':0}
        gap=reply['first_seq'] is not None and after+1<reply['first_seq']
        for row in reply['rows']:
            result=publisher(row['body'])
            if result not in counts:raise ValueError('unexpected_publish_result')
            counts[result]+=1;after=row['seq'];db.execute('UPDATE relay SET seq=? WHERE id=1',(after,));db.commit()
        report={'checked_at':datetime.now(timezone.utc).isoformat(),'state':'warning' if gap or reply['health']['source_gaps'] or reply['health']['evicted'] or reply['health']['malformed'] else 'observed',
            'last_seq':after,'queue_gap_detected':gap,'counts':counts,'producer':reply['health']}
        db.execute('INSERT OR REPLACE INTO report VALUES(1,?)',(json.dumps(report),));db.commit();return report


def run_once(config,*,fetch=ssh_export,publish=None):
    try:
        return _run_once(config,fetch=fetch,publish=publish)
    except Exception:
        # Preserve the last delivered position, but never leave a fresh failure labelled healthy.
        path=Path(config['state'])
        if path.is_file() and not path.is_symlink() and not path.parent.is_symlink() and (os.name=='nt' or not path.stat().st_mode&0o077):
            with closing(sqlite3.connect(path,timeout=0)) as db:
                if db.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='report'").fetchone()[0]:
                    row=db.execute('SELECT seq FROM relay WHERE id=1').fetchone()
                    report={'checked_at':datetime.now(timezone.utc).isoformat(),'state':'failed','last_seq':row[0] if row else None,'error':'export_or_publish_unavailable'}
                    db.execute('INSERT OR REPLACE INTO report VALUES(1,?)',(json.dumps(report),));db.commit()
        raise
