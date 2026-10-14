"""Private encrypted webhook and independent durable notification outbox."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

from cryptography.fernet import Fernet

from cloud_soc.notifications.messages import connection_test
from cloud_soc.notifications.transport import SlackError, validate_url

LEVELS = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


def private(path, directory=False):
    p = Path(path)
    info = p.lstat()
    if p.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400 or (not directory and info.st_nlink != 1):
        raise SlackError('notification_storage_unsafe', 503)
    if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
        raise SlackError('notification_storage_unsafe', 503)
    if os.name != 'nt' and stat.S_IMODE(info.st_mode) & 0o077:
        raise SlackError('notification_storage_unsafe', 503)


def create_private(path, content=b''):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(content);stream.flush();os.fsync(stream.fileno())


class SlackStore:
    def __init__(self, directory, *, clock=time.time):
        self.directory = Path(directory)
        self.path = self.directory / 'slack.sqlite'
        self.clock = clock

    @contextmanager
    def connect(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        private(self.directory, True)
        if self.directory.parent.is_symlink():
            raise SlackError('notification_storage_unsafe', 503)
        try:
            create_private(self.path)
        except FileExistsError:
            pass
        private(self.path)
        db = sqlite3.connect(self.path, timeout=6)
        db.row_factory = sqlite3.Row
        try:
            if db.execute('pragma user_version').fetchone()[0] not in (0, 1):
                raise SlackError('notification_schema_unsupported', 503)
            db.execute('pragma journal_mode=WAL');db.execute('pragma synchronous=FULL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL,
                  generation TEXT NOT NULL, secret TEXT, enabled INTEGER NOT NULL, minimum TEXT NOT NULL, changed REAL NOT NULL);
                INSERT OR IGNORE INTO config VALUES(1,0,'unconfigured',NULL,0,'high',0);
                CREATE TABLE IF NOT EXISTS cursors(scope TEXT PRIMARY KEY, generation TEXT NOT NULL, uuid TEXT NOT NULL, seq INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY, generation TEXT NOT NULL, kind TEXT NOT NULL,
                  source_id TEXT NOT NULL, revision INTEGER NOT NULL, state TEXT NOT NULL, severity TEXT NOT NULL,
                  payload TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL, next_try REAL NOT NULL,
                  code TEXT NOT NULL, updated REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS outbox_ready ON outbox(status,next_try);
                CREATE TABLE IF NOT EXISTS manual_retries(id INTEGER PRIMARY KEY, notification_id TEXT NOT NULL,
                  requested REAL NOT NULL, actor TEXT NOT NULL, previous_attempts INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS manual_retry_notification ON manual_retries(notification_id);
                CREATE TABLE IF NOT EXISTS control(id INTEGER PRIMARY KEY CHECK(id=1), next_send REAL NOT NULL,
                  test_after REAL NOT NULL, test_window REAL NOT NULL, test_count INTEGER NOT NULL,
                  heartbeat REAL, state TEXT NOT NULL, code TEXT NOT NULL);
                INSERT OR IGNORE INTO control VALUES(1,0,0,0,0,NULL,'not_started','');
                PRAGMA user_version=1;
            ''')
            with db:
                yield db
        finally:
            db.close()

    def cipher(self, *, create=True):
        path = self.directory / 'slack.key'
        if not create and not path.exists():
            raise SlackError('notification_key_unavailable', 503)
        try:
            create_private(path, Fernet.generate_key())
        except FileExistsError:
            pass
        private(path)
        try:
            return Fernet(path.read_bytes())
        except Exception:
            raise SlackError('notification_key_unavailable', 503) from None

    def status(self):
        with self.connect() as db:
            row = db.execute('select * from config where id=1').fetchone()
            worker = dict(db.execute('select heartbeat,state,code from control where id=1').fetchone())
            counts = {r[0]: r[1] for r in db.execute('select status,count(*) from outbox group by status')}
            test = db.execute("select id,status,code,updated from outbox where kind='test' order by updated desc limit 1").fetchone()
            return {'configured': row['secret'] is not None, 'enabled': bool(row['enabled']), 'minimum_severity': row['minimum'],
                    'revision': row['revision'], 'worker': worker, 'deliveries': counts,
                    'last_test': dict(test) if test else None, 'history_policy': 'new_after_activation',
                    'delivery_policy': 'ambiguous_post_is_held_for_review'}

    def save(self, value, *, check_address):
        if (not isinstance(value, dict) or set(value) - {'revision', 'webhook_url', 'enabled', 'minimum_severity'}
                or type(value.get('revision')) is not int or type(value.get('enabled')) is not bool
                or not isinstance(value.get('minimum_severity'), str) or value['minimum_severity'] not in LEVELS):
            raise SlackError('invalid_slack_settings')
        url = value.get('webhook_url')
        if url is not None:
            validate_url(url);check_address()
        with self.connect() as db:
            db.execute('begin immediate')
            old = db.execute('select * from config where id=1').fetchone()
            if value['revision'] != old['revision']:
                raise SlackError('slack_settings_changed', 409)
            secret = self.cipher().encrypt(url.encode()).decode() if url is not None else old['secret']
            if value['enabled'] and not secret:
                raise SlackError('slack_webhook_required')
            now = self.clock()
            db.execute('update config set revision=revision+1,generation=?,secret=?,enabled=?,minimum=?,changed=? where id=1',
                       (uuid.uuid4().hex, secret, int(value['enabled']), value['minimum_severity'], now))
            db.execute("update outbox set status='cancelled',code='configuration_changed',updated=? where status in ('queued','retry','inflight')", (now,))
            db.execute('delete from cursors')
        return self.status()

    def delete(self, revision):
        with self.connect() as db:
            db.execute('begin immediate')
            if type(revision) is not int or db.execute('select revision from config where id=1').fetchone()[0] != revision:
                raise SlackError('slack_settings_changed', 409)
            now = self.clock()
            db.execute("update config set revision=revision+1,generation=?,secret=NULL,enabled=0,changed=? where id=1", (uuid.uuid4().hex, now))
            db.execute("update outbox set status='cancelled',code='webhook_deleted',updated=? where status in ('queued','retry','inflight')", (now,))
            db.execute('delete from cursors')
        return self.status()

    def test(self):
        with self.connect() as db:
            db.execute('begin immediate')
            cfg = db.execute('select * from config where id=1').fetchone()
            if not cfg['secret']:
                raise SlackError('slack_webhook_required')
            row = db.execute('select * from control where id=1').fetchone();now = self.clock()
            if row['test_after'] > now or row['test_window'] + 900 > now and row['test_count'] >= 5:
                raise SlackError('slack_test_rate_limited', 429)
            reset = row['test_window'] + 900 <= now
            db.execute('update control set test_after=?,test_window=?,test_count=? where id=1',
                       (now+30, now if reset else row['test_window'], 1 if reset else row['test_count']+1))
            identifier = uuid.uuid4().hex
            self.enqueue(db, cfg, identifier, 'test', identifier, 1, 'test', 'high',
                         connection_test())
        return {'test_id': identifier, 'status': 'queued'}

    def enqueue(self, db, cfg, identifier, kind, source_id, revision, state, severity, payload):
        key = identifier if kind == 'test' else hashlib.sha256(identifier.encode()).hexdigest()
        if db.execute('select 1 from outbox where id=?', (key,)).fetchone():
            return
        if kind != 'test':
            latest = db.execute('select max(revision) from outbox where kind=? and source_id=?', (kind, source_id)).fetchone()[0]
            if latest is not None and revision <= latest:
                return
        if db.execute('select count(*) from outbox').fetchone()[0] >= 100000:
            raise SlackError('notification_capacity_reached', 503)
        db.execute('insert or ignore into outbox values(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (key, cfg['generation'], kind, source_id, revision, state, severity, json.dumps(payload), 'queued', 0, self.clock(), '', self.clock()))

    def unconfirmed(self, offset=0):
        if type(offset) is not int or not 0 <= offset <= 100000:
            raise SlackError('invalid_slack_settings')
        with self.connect() as db:
            cfg = db.execute('select * from config where id=1').fetchone()
            total = db.execute("select count(*) from outbox where status='unknown'").fetchone()[0]
            rows = db.execute("""select id,kind,source_id,revision,state,severity,attempts,code,updated,generation
                from outbox where status='unknown' order by updated desc,id limit 20 offset ?""", (offset,)).fetchall()
            items = []
            for row in rows:
                item = dict(row)
                item['can_retry'] = bool(cfg['secret'] and item.pop('generation') == cfg['generation']
                                         and (cfg['enabled'] or row['kind'] == 'test'))
                item.pop('generation', None)
                item['manual_retries'] = db.execute('select count(*) from manual_retries where notification_id=?', (row['id'],)).fetchone()[0]
                items.append(item)
            return {'items': items, 'total': total, 'offset': offset, 'next_offset': offset+20 if offset+20 < total else None}

    def retry_unconfirmed(self, value, *, actor):
        if (not isinstance(value, dict) or set(value) != {'revision', 'notification_id', 'accept_duplicate_risk'}
                or value['accept_duplicate_risk'] is not True or type(value['revision']) is not int
                or not isinstance(value['notification_id'], str)
                or not re.fullmatch(r'(?:[0-9a-f]{32}|[0-9a-f]{64})', value['notification_id'])):
            raise SlackError('slack_duplicate_risk_confirmation_required')
        with self.connect() as db:
            db.execute('begin immediate')
            cfg = db.execute('select * from config where id=1').fetchone()
            if cfg['revision'] != value['revision']:
                raise SlackError('slack_settings_changed', 409)
            row = db.execute('select * from outbox where id=?', (value['notification_id'],)).fetchone()
            if (not row or row['status'] != 'unknown' or cfg['generation'] != row['generation']
                    or not cfg['secret'] or not cfg['enabled'] and row['kind'] != 'test'):
                raise SlackError('slack_manual_retry_unavailable', 409)
            control = db.execute('select * from control where id=1').fetchone();now = self.clock()
            if control['test_after'] > now or control['test_window']+900 > now and control['test_count'] >= 5:
                raise SlackError('slack_manual_retry_rate_limited', 429)
            reset = control['test_window']+900 <= now
            db.execute('update control set test_after=?,test_window=?,test_count=? where id=1',
                       (now+30, now if reset else control['test_window'], 1 if reset else control['test_count']+1))
            db.execute('insert into manual_retries(notification_id,requested,actor,previous_attempts) values(?,?,?,?)',
                       (row['id'], now, str(actor)[:128], row['attempts']))
            db.execute("update outbox set status='queued',attempts=0,next_try=?,code='manual_retry_requested',updated=? where id=?", (now,now,row['id']))
        return {'notification_id': row['id'], 'status': 'queued', 'duplicate_risk_acknowledged': True}

    def recover(self):
        with self.connect() as db:
            db.execute("update outbox set status='unknown',code='delivery_unconfirmed',updated=? where status='inflight'", (self.clock(),))

    def heartbeat(self, state, code=''):
        with self.connect() as db:
            db.execute('update control set heartbeat=?,state=?,code=? where id=1', (self.clock(), state, code))
