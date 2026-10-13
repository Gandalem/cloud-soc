"""Atomic cursor plus a bounded metadata-only queue; Apache files are read-only."""
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid
from contextlib import closing

from cloud_soc.web.metadata import digest, project, scope, validate


def connect(path, *, readonly=False):
    path=Path(path)
    if path.is_symlink() or path.parent.is_symlink():raise ValueError('linked_web_state')
    if not readonly:
        path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.exists() and os.name!='nt' and (path.stat().st_mode&0o077):raise ValueError('unprotected_web_state')
    db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=2) if readonly else sqlite3.connect(path,timeout=2)
    if not readonly:
        if os.name!='nt':os.chmod(path,0o600)
        db.execute('PRAGMA max_page_count=16384')
        db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1),body TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS queue (seq INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE NOT NULL,body TEXT NOT NULL,bytes INTEGER NOT NULL)')
        db.commit()
    return db


def collect(path, state, config, collected_at, *, max_rows=10000, max_bytes=16*1024*1024, max_lines=1000):
    scope(config['organization'],config['host'],config['container'],config['region'])
    if type(max_rows) is not int or not 1<=max_rows<=10000 or type(max_bytes) is not int or not 4096<=max_bytes<=16*1024*1024:raise ValueError('invalid_queue_limit')
    path=Path(path)
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as current, closing(connect(state)) as db:
        info=os.fstat(current.fileno())
        if not stat.S_ISREG(info.st_mode):raise ValueError('web_source_not_regular')
        db.execute('BEGIN IMMEDIATE');row=db.execute('SELECT body FROM state WHERE id=1').fetchone()
        previous=json.loads(row[0]) if row else None
        binding=digest(config)
        if previous and previous['binding']!=binding:raise ValueError('web_source_identity_changed')
        current.seek(0);head_length=min(64,info.st_size);head_hash=digest(current.read(head_length).hex())
        if previous is None:
            saved={'binding':binding,'stream_id':uuid.uuid4().hex,'device':info.st_dev,'inode':info.st_ino,'offset':info.st_size,'generation':1,'head_length':head_length,'head_hash':head_hash,'malformed':0,'evicted':0,'source_gaps':0,'observed':0,'baseline_bytes':info.st_size}
            # Start at a known baseline, never import unapproved historical requests.
            db.execute('INSERT INTO state VALUES(1,?)',(json.dumps(saved),));db.commit();return saved
        saved=previous
        switched=(saved['device'],saved['inode'])!=(info.st_dev,info.st_ino)
        current.seek(0);same_prefix=digest(current.read(saved['head_length']).hex())==saved['head_hash']
        if switched:
            old=None
            for candidate in sorted(path.parent.glob(path.name+'*'))[:32]:
                if candidate==path or candidate.is_symlink() or candidate.suffix=='.gz':continue
                try:metadata=candidate.stat()
                except OSError:continue
                if (metadata.st_dev,metadata.st_ino)==(saved['device'],saved['inode']) and stat.S_ISREG(metadata.st_mode):old=candidate;break
            if old is not None:
                old_fd=os.open(old,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
                with os.fdopen(old_fd,'rb') as retired:
                    if (os.fstat(retired.fileno()).st_dev,os.fstat(retired.fileno()).st_ino)!=(saved['device'],saved['inode']):raise ValueError('rotation_identity_changed')
                    _read(retired,saved,db,config,collected_at,max_lines)
                    if saved['offset']<os.fstat(retired.fileno()).st_size:
                        _save(db,saved,max_rows,max_bytes);return saved
            else:saved['source_gaps']+=1
        if switched or info.st_size<saved['offset'] or not same_prefix:
            if not switched:saved['source_gaps']+=1
            saved.update(device=info.st_dev,inode=info.st_ino,offset=0,generation=saved['generation']+1,head_length=head_length,head_hash=head_hash)
        _read(current,saved,db,config,collected_at,max_lines)
        # Empty baseline: pin its prefix once data first arrives, without treating append as truncation.
        if not saved['head_length'] and info.st_size:
            saved.update(head_length=head_length,head_hash=head_hash)
        _save(db,saved,max_rows,max_bytes)
        return saved


def _read(handle,saved,db,config,collected_at,max_lines):
    handle.seek(saved['offset'])
    for _ in range(max_lines):
        offset=handle.tell();line=handle.readline(8193)
        if not line:break
        if len(line)>8192:
            while line and not line.endswith(b'\n'):line=handle.readline(8193)
            saved['malformed']+=1;saved['offset']=handle.tell();continue
        if not line.endswith(b'\n'):break
        body=project(line,organization=config['organization'],host=config['host'],container=config['container'],region=config['region'],generation=saved['generation'],device=saved['device'],inode=saved['inode'],offset=offset,collected_at=collected_at)
        if body is None:saved['malformed']+=1
        else:
            encoded=json.dumps(body,sort_keys=True,separators=(',',':'))
            db.execute('INSERT OR IGNORE INTO queue(event_id,body,bytes) VALUES(?,?,?)',(body['event']['id'],encoded,len(encoded.encode())))
            saved['observed']+=1
        saved['offset']=handle.tell()


def _save(db,saved,max_rows,max_bytes):
    count,size=db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM queue').fetchone()
    while count>max_rows or size>max_bytes:
        seq,length=db.execute('SELECT seq,bytes FROM queue ORDER BY seq LIMIT 1').fetchone()
        db.execute('DELETE FROM queue WHERE seq=?',(seq,));saved['evicted']+=1;count-=1;size-=length
    db.execute('UPDATE state SET body=? WHERE id=1',(json.dumps(saved),));db.commit()


def export(state, request):
    if not isinstance(request,dict) or set(request)!={'schema','after','limit'} or request['schema']!=1 or type(request['schema']) is not int or type(request['after']) is not int or not 0<=request['after']<2**53 or type(request['limit']) is not int or not 1<=request['limit']<=100:raise ValueError('invalid_export_request')
    with closing(connect(state,readonly=True)) as db:
        db.execute('BEGIN');row=db.execute('SELECT body FROM state WHERE id=1').fetchone()
        if row is None:raise ValueError('web_source_not_initialized')
        saved=json.loads(row[0]);bounds=db.execute('SELECT min(seq),max(seq),count(*),coalesce(sum(bytes),0) FROM queue').fetchone()
        rows=[]
        for seq,body in db.execute('SELECT seq,body FROM queue WHERE seq>? ORDER BY seq LIMIT ?',(request['after'],request['limit'])):
            body=json.loads(body);validate(body);rows.append({'seq':seq,'body':body})
        return {'schema':1,'stream_id':saved['stream_id'],'first_seq':bounds[0],'last_seq':bounds[1],'rows':rows,
            'health':{'queued_rows':bounds[2],'queued_bytes':bounds[3],'malformed':saved['malformed'],'evicted':saved['evicted'],'source_gaps':saved['source_gaps'],'observed':saved['observed']}}


def container_source(container):
    # Exact existing cgroup identity. No Docker socket or arbitrary container access.
    if not isinstance(container,str) or len(container)!=64 or any(c not in '0123456789abcdef' for c in container):raise ValueError('invalid_container')
    cgroup=Path('/sys/fs/cgroup/system.slice/docker-'+container+'.scope/cgroup.procs')
    for pid in cgroup.read_text().splitlines()[:128]:
        if not pid.isdigit():continue
        process=Path('/proc')/pid
        try:
            if container not in (process/'cgroup').read_text():continue
            root=process/'root';path=root/'var/log/apache2/access.log'
            if path.is_file() and not path.is_symlink():return path
        except OSError:continue
    raise ValueError('configured_container_log_unavailable')
