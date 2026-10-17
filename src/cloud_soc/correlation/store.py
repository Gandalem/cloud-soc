"""Small SQLite projection ledger, following the existing CaseStore transaction pattern.

No raw/normalized/alert ES writes, case creation, network calls or service startup.
"""
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import stat
from uuid import uuid4

from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.correlation.security_mall import correlate, require, select_alert, select_event, VERSION


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))


class CorrelationStore:
    """One trusted site/collector binding per independent private database.

    Ingest is a trusted processing API, not a browser route. Read calls require
    the existing server-created LogPrincipal; caller input must never create it.
    """
    def __init__(self, path, scope):
        self.path, self.scope = Path(path), scope
        require(not any(p.is_symlink() for p in (self.path, *self.path.parents)), 'store_symlink_forbidden')
        require(self.path.parent.is_dir(), 'private_store_directory_required')
        if os.name == 'posix':
            info = self.path.parent.stat()
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private_store_directory_required')
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        info = self.path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'store_file_invalid')
        if os.name == 'posix':
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private_store_file_required')
        if info.st_size:
            # A mistaken Portal/H2/other database path must not receive our schema.
            probe = sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
            try:
                tables = {row[0] for row in probe.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require(tables in ({'binding', 'events', 'observations', 'alerts'},
                                   {'binding', 'events', 'observations', 'alerts', 'revision_state'}),
                        'foreign_store_database')
                prior = probe.execute('SELECT value FROM binding WHERE id=1').fetchone()
                require(prior is not None and prior[0] == encode({'version': VERSION, 'scope': asdict(scope)}),
                        'store_binding_mismatch')
            except sqlite3.DatabaseError:
                raise ValueError('store_database_invalid') from None
            finally:
                probe.close()
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY CHECK(id=1), value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(id),
                    raw_id TEXT NOT NULL, document TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS observations_raw ON observations(raw_id);
                CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, document TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS revision_state (
                    id INTEGER PRIMARY KEY CHECK(id=1), publisher TEXT NOT NULL, sequence INTEGER NOT NULL);
            ''')
            db.execute('BEGIN IMMEDIATE')
            binding = encode({'version': VERSION, 'scope': asdict(scope)})
            row = db.execute('SELECT value FROM binding WHERE id=1').fetchone()
            require(row is None or row[0] == binding, 'store_binding_mismatch')
            db.execute('INSERT OR IGNORE INTO binding VALUES(1,?)', (binding,))
            db.execute('INSERT OR IGNORE INTO revision_state VALUES(1,?,0)', (uuid4().hex,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, events=(), alerts=()):
        """Validate the whole bounded batch before atomic merge; any conflict rolls back."""
        events, alerts = list(events), list(alerts)
        require(len(events) + len(alerts) <= self.scope.max_events, 'correlation_batch_limit')
        selected = [select_event(hit, self.scope) for hit in events]
        alert_rows = [select_alert(hit, self.scope) for hit in alerts]
        require(sum(len(alert['evidence']) for alert in alert_rows) <= self.scope.max_events,
                'correlation_evidence_limit')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            before = db.total_changes
            for event, observation in selected:
                identifier, serialized = event['key'], encode(event)
                old = db.execute('SELECT document FROM events WHERE id=?', (identifier,)).fetchone()
                require(old is None or old[0] == serialized, 'event_identity_conflict')
                db.execute('INSERT OR IGNORE INTO events VALUES(?,?)', (identifier, serialized))
                norm_key, raw_key = encode(observation['normalized']), encode(observation['raw'])
                others = db.execute('SELECT event_id FROM observations WHERE raw_id=?', (raw_key,)).fetchall()
                require(all(item[0] == identifier for item in others), 'raw_identity_conflict')
                old = db.execute('SELECT event_id,document FROM observations WHERE id=?', (norm_key,)).fetchone()
                require(old is None or old == (identifier, encode(observation)), 'normalized_identity_conflict')
                db.execute('INSERT OR IGNORE INTO observations VALUES(?,?,?,?)',
                           (norm_key, identifier, raw_key, encode(observation)))
            for alert in alert_rows:
                identifier, serialized = encode(alert['alert']), encode(alert)
                old = db.execute('SELECT document FROM alerts WHERE id=?', (identifier,)).fetchone()
                require(old is None or old[0] == serialized, 'alert_identity_conflict')
                db.execute('INSERT OR IGNORE INTO alerts VALUES(?,?)', (identifier, serialized))
            # Fixed SQL literals keep table names independent of any caller input.
            counts = (
                db.execute('SELECT count(*) FROM events').fetchone()[0],
                db.execute('SELECT count(*) FROM observations').fetchone()[0],
                db.execute('SELECT count(*) FROM alerts').fetchone()[0],
            )
            require(all(value <= self.scope.max_events for value in counts), 'correlation_capacity_limit')
            # Bound persisted alert fan-out as well as single-batch input.
            require(sum(len(json.loads(value)['evidence']) for (value,) in db.execute('SELECT document FROM alerts'))
                    <= self.scope.max_events, 'correlation_evidence_limit')
            if db.total_changes != before:
                db.execute('UPDATE revision_state SET sequence=sequence+1 WHERE id=1')

    def snapshot(self, principal):
        # Cross-organization and empty-site results share exactly the same shape.
        if not self.scope.visible(principal):
            return {'requests': [], 'alert_links': []}
        with self.connect() as db:
            db.execute('BEGIN')
            events = {key: json.loads(value) for key, value in db.execute('SELECT id,document FROM events')}
            for event in events.values():
                event['observations'] = []
            for key, value in db.execute('SELECT event_id,document FROM observations ORDER BY id'):
                events[key]['observations'].append(json.loads(value))
            alerts = [json.loads(value) for (value,) in db.execute('SELECT document FROM alerts')]
            publisher, sequence = db.execute('SELECT publisher,sequence FROM revision_state WHERE id=1').fetchone()
        # All links are recomputed from one consistent ledger snapshot, including
        # late evidence: no stale materialized bundles or dangling alert links.
        result = correlate(self.scope, list(events.values()), alerts)
        result['revision_order'] = {'publisher_id': publisher, 'sequence': sequence, 'binding_id': self.binding_id}
        return result

    def request(self, identifier, principal):
        result = self.snapshot(principal)
        for request in result['requests']:
            if request['id'] == identifier:
                return request
        raise LookupError('correlation_not_found')

    def evidence(self, identifier, principal):
        """Only references: protected raw contents still require existing Operations.evidence."""
        request = self.request(identifier, principal)
        return [observation for event in request['events'] for observation in event['observations']]

    @property
    def binding_id(self):
        return event_fingerprint({'version': VERSION, 'scope': asdict(self.scope)})
