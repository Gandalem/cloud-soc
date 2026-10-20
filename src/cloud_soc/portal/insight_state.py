"""Private, bounded dashboard observations; never grants engine authority."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
import uuid

from cloud_soc.portal.agent_status import parse_time
from cloud_soc.privacy import sensitive


class InsightError(ValueError):
    def __init__(self, code, status=400):
        self.code, self.status = code, status
        super().__init__(code)


def identity(value):
    if sensitive(value) or not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value):
        raise InsightError('invalid_identifier')
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise InsightError('invalid_number')
    return value


def exact(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= set(value) or set(value) - set(required) - set(optional):
        raise InsightError('invalid_fields')


def report_state(last, now, interval, *, paused=False, revoked=False):
    if revoked:
        return 'revoked'
    if paused:
        return 'paused'
    if last is None:
        return 'awaiting_first_report'
    age = now - last
    if age < 0:
        return 'unknown'
    return 'reporting' if age <= 3 * interval else 'delayed' if age <= 6 * interval else 'report_missing'


class InsightStore:
    def __init__(self, path, *, clock=time.time):
        self.path, self.clock = Path(path).absolute(), clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for entry in (self.path, *self.path.parents):
            if entry.is_symlink():
                raise InsightError('unsafe_state_path', 503)
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        if os.name != 'nt' and self.path.stat().st_mode & 0o077:
            raise InsightError('private_state_required', 503)
        keyfile=self.path.with_name('dashboard-report-auth.key')
        if keyfile.is_symlink():raise InsightError('unsafe_state_path',503)
        if not keyfile.exists():
            fd=os.open(keyfile,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,'wb') as key:key.write(secrets.token_bytes(32));key.flush();os.fsync(key.fileno())
        if os.name!='nt' and keyfile.stat().st_mode&0o077:raise InsightError('private_state_required',503)
        self.auth_key=keyfile.read_bytes()
        if len(self.auth_key)!=32:raise InsightError('invalid_state_key',503)
        self.auth_epoch=hashlib.sha256(self.auth_key).hexdigest()
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS insight_devices (
                  id TEXT PRIMARY KEY, organization TEXT NOT NULL, label TEXT NOT NULL,
                  credential_hash TEXT NOT NULL, generation TEXT NOT NULL, expires INTEGER NOT NULL,
                  interval INTEGER NOT NULL, paused INTEGER NOT NULL DEFAULT 0, revoked INTEGER NOT NULL DEFAULT 0,
                  version INTEGER NOT NULL, created INTEGER NOT NULL, credential_epoch TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS insight_reports (
                  device TEXT PRIMARY KEY REFERENCES insight_devices(id), generation TEXT NOT NULL,
                  sequence INTEGER NOT NULL, fingerprint TEXT NOT NULL, received INTEGER NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS insight_requests (
                  request_id TEXT PRIMARY KEY, actor TEXT NOT NULL, fingerprint TEXT NOT NULL,
                  device TEXT NOT NULL, at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS insight_audit (
                  seq INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, reference TEXT NOT NULL, at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS insight_records (
                  kind TEXT NOT NULL, id TEXT NOT NULL, organization TEXT NOT NULL,
                  fingerprint TEXT NOT NULL, body TEXT NOT NULL, actor TEXT NOT NULL, at INTEGER NOT NULL,
                  PRIMARY KEY(kind,id,organization));
            ''')
            if 'credential_epoch' not in {r[1] for r in db.execute('PRAGMA table_info(insight_devices)')}:
                db.execute("ALTER TABLE insight_devices ADD COLUMN credential_epoch TEXT NOT NULL DEFAULT ''")

    def token_hash(self,token):return hmac.new(self.auth_key,token.encode(),'sha256').hexdigest()

    @contextmanager
    def connect(self):
        if self.path.is_symlink():
            raise InsightError('unsafe_state_path', 503)
        try:db = sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,timeout=5)
        except sqlite3.Error:raise InsightError('state_unavailable',503) from None
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('PRAGMA synchronous=FULL')
            yield db
            db.commit()
        except sqlite3.Error:
            db.rollback()
            raise InsightError('state_unavailable',503) from None
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def budget(self, db):
        if self.path.stat().st_size > 128 * 1024 * 1024 or db.execute('SELECT count(*) FROM insight_audit').fetchone()[0] >= 100000:
            raise InsightError('state_capacity', 409)

    def audit(self, db, actor, action, ref):
        db.execute('INSERT INTO insight_audit(actor,action,reference,at) VALUES (?,?,?,?)',
                   (actor, action, ref, int(self.clock())))

    def register(self, body, actor):
        exact(body, ('request_id', 'organization', 'label', 'interval', 'days'))
        identity(body['request_id']);identity(body['organization'])
        if not isinstance(body['label'], str) or not 1 <= len(body['label']) <= 80 or any(ord(c)<32 for c in body['label']) or sensitive(body['label']):
            raise InsightError('invalid_label')
        integer(body['interval'], 15, 300);integer(body['days'], 1, 90)
        digest = fingerprint(body)
        token = secrets.token_urlsafe(32)
        device, generation = uuid.uuid4().hex, uuid.uuid4().hex
        now = int(self.clock())
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');self.budget(db)
            prior = db.execute('SELECT * FROM insight_requests WHERE request_id=?', (body['request_id'],)).fetchone()
            if prior:
                if prior['actor'] != actor or prior['fingerprint'] != digest:
                    raise InsightError('request_conflict', 409)
                raise InsightError('credential_already_delivered_rotate_required', 409)
            if db.execute('SELECT count(*) FROM insight_devices').fetchone()[0] >= 2000:
                raise InsightError('device_capacity', 409)
            db.execute('INSERT INTO insight_devices VALUES (?,?,?,?,?,?,?,0,0,1,?,?)',
                       (device, body['organization'], body['label'], self.token_hash(token),
                        generation, now + body['days']*86400, body['interval'], now, self.auth_epoch))
            db.execute('INSERT INTO insight_requests VALUES (?,?,?,?,?)', (body['request_id'], actor, digest, device, now))
            self.audit(db, actor, 'register_device', device)
        return {'id':device,'credential':device+'.'+token,'generation':generation,'version':1,
                'interval':body['interval'],'expires':now+body['days']*86400,'delivery':'one_time'}

    def change_device(self, device, body, actor):
        identity(device);exact(body, ('action', 'version'), ('days',))
        integer(body['version'], 1, 2**31-1)
        if body['action'] not in ('pause','resume','revoke','rotate'):
            raise InsightError('invalid_action')
        if body['action']=='rotate':integer(body.get('days'),1,90)
        elif 'days' in body:raise InsightError('invalid_fields')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');self.budget(db)
            row=db.execute('SELECT * FROM insight_devices WHERE id=?',(device,)).fetchone()
            if not row:raise InsightError('device_missing',404)
            if row['version']!=body['version']:raise InsightError('revision_conflict',409)
            if row['revoked']:raise InsightError('device_revoked',409)
            result={'id':device,'version':row['version']+1}
            if body['action']=='rotate':
                token=secrets.token_urlsafe(32);generation=uuid.uuid4().hex;expires=int(self.clock())+body['days']*86400
                db.execute('UPDATE insight_devices SET credential_hash=?,generation=?,expires=?,credential_epoch=?,version=version+1 WHERE id=?',
                           (self.token_hash(token),generation,expires,self.auth_epoch,device))
                db.execute('DELETE FROM insight_reports WHERE device=?',(device,))
                result.update(credential=device+'.'+token,generation=generation,expires=expires,delivery='one_time')
            else:
                db.execute('UPDATE insight_devices SET paused=?,revoked=?,version=version+1 WHERE id=?',
                           (int(body['action']=='pause'),int(body['action']=='revoke'),device))
            self.audit(db,actor,body['action']+'_device',device)
        return result

    def heartbeat(self, credential, body):
        if not isinstance(credential,str) or not re.fullmatch(r'[0-9a-f]{32}\.[A-Za-z0-9_-]{43}',credential):
            raise InsightError('device_authentication_failed',401)
        device,token=credential.split('.')
        exact(body,('generation','sequence','generated_at','collector'))
        identity(body['generation']);integer(body['sequence'],1,2**53-1)
        generated=parse_time(body['generated_at']);now=int(self.clock())
        if generated is None or not -60 <= now-generated.timestamp() <= 90:
            raise InsightError('stale_or_future_report',409)
        exact(body['collector'],('state',),('queue_events','output_failed'))
        if body['collector']['state'] not in ('running','stopped','error','unknown'):raise InsightError('invalid_collector_state')
        for k in ('queue_events','output_failed'):
            if k in body['collector']:integer(body['collector'][k],0,2**53-1)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');self.budget(db)
            row=db.execute('SELECT * FROM insight_devices WHERE id=?',(device,)).fetchone()
            if (not row or row['credential_epoch']!=self.auth_epoch or not hmac.compare_digest(row['credential_hash'],self.token_hash(token))
                    or row['revoked'] or row['paused'] or row['expires']<=now or row['generation']!=body['generation']):
                raise InsightError('device_authentication_failed',401)
            old=db.execute('SELECT * FROM insight_reports WHERE device=?',(device,)).fetchone();digest=fingerprint(body)
            if old and old['generation']==body['generation'] and body['sequence']<=old['sequence']:
                if old['sequence']==body['sequence'] and hmac.compare_digest(old['fingerprint'],digest):
                    return {'accepted':True,'duplicate':True,'received_at':old['received']}
                raise InsightError('report_sequence_conflict',409)
            db.execute('INSERT OR REPLACE INTO insight_reports VALUES (?,?,?,?,?,?)',
                       (device,body['generation'],body['sequence'],digest,now,canonical(body)))
        return {'accepted':True,'duplicate':False,'received_at':now}

    def fleet(self):
        now=int(self.clock());rows=[];counts={}
        with self.connect() as db:
            records=db.execute('SELECT d.*,r.received,r.body FROM insight_devices d LEFT JOIN insight_reports r ON d.id=r.device ORDER BY d.created,d.id').fetchall()
        for d in records:
            status=report_state(d['received'],now,d['interval'],paused=d['paused'],revoked=d['revoked'])
            if d['credential_epoch']!=self.auth_epoch and status not in ('paused','revoked'):status='credential_reset_required'
            if d['expires']<=now and status not in ('revoked','paused'):status='credential_expired'
            counts[status]=counts.get(status,0)+1
            report=json.loads(d['body']) if d['body'] else None
            rows.append({k:d[k] for k in ('id','organization','label','version','interval','expires')} | {
                'state':status,'reported_at':d['received'],'collector':report['collector'] if report else None})
        return {'state':'ok','total':len(rows),'counts':counts,'rows':rows,'basis':'registered_fleet_server_received_reports',
                'checked_at':now,'identity':'credential_bound_report_not_host_attestation'}

    def put_record(self, kind, body, actor, validator):
        validator(body)
        if len(canonical(body).encode())>262144:raise InsightError('record_too_large',413)
        digest=fingerprint(body)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');self.budget(db)
            old=db.execute('SELECT fingerprint FROM insight_records WHERE kind=? AND id=? AND organization=?',
                           (kind,body['id'],body['organization'])).fetchone()
            if old:
                if old['fingerprint']!=digest:raise InsightError('record_conflict',409)
                return {'id':body['id'],'duplicate':True}
            if db.execute('SELECT count(*) FROM insight_records').fetchone()[0]>=20000:raise InsightError('record_capacity',409)
            db.execute('INSERT INTO insight_records VALUES (?,?,?,?,?,?,?)',
                       (kind,body['id'],body['organization'],digest,canonical(body),actor,int(self.clock())))
            self.audit(db,actor,'append_'+kind,body['id'])
        return {'id':body['id'],'duplicate':False}

    def records(self, kind, organizations):
        with self.connect() as db:
            if organizations is None:
                rows=db.execute('SELECT body,actor,at FROM insight_records WHERE kind=? ORDER BY at,id LIMIT 1001',(kind,)).fetchall()
            elif not organizations:return []
            else:
                placeholders=','.join('?' for _ in organizations)
                rows=db.execute('SELECT body,actor,at FROM insight_records WHERE kind=? AND organization IN ('+placeholders+') ORDER BY at,id LIMIT 1001',
                                (kind,*organizations)).fetchall()
        if len(rows)>1000:raise InsightError('record_query_capacity',413)
        return [{'body':json.loads(r['body']),'actor':r['actor'],'recorded_at':r['at']} for r in rows]
