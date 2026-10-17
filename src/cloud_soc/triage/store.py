"""Atomic replacement of a bounded investigation queue; no ES/case/alert writes."""
from contextlib import contextmanager
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import stat

from cloud_soc.correlation.security_mall import require
from cloud_soc.correlation.store import encode
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.triage.engine import evaluate, time_range
from cloud_soc.triage.policy import Policy, VERSION


class TriageStore:
    """Private local processor API; only read endpoints accept server LogPrincipal.

    A source publisher is pinned on first apply. It cannot be changed by a new
    snapshot, backup reset or caller flag; a rebind needs separate reviewed setup.
    """
    def __init__(self, path, scope, policy=None):
        self.path, self.scope, self.policy = Path(path), scope, policy or Policy()
        require(self.path.parent.is_dir() and not any(p.is_symlink() for p in (self.path, *self.path.parents)),
                'private_triage_path_required')
        if os.name == 'posix':
            info = self.path.parent.stat()
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private_triage_path_required')
        if not self.path.exists():
            os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
        info = self.path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'triage_file_invalid')
        if os.name == 'posix':
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'private_triage_file_required')
        binding = encode({'version': VERSION, 'scope': asdict(scope), 'policy_id': self.policy.identity})
        if info.st_size:
            probe = sqlite3.connect(self.path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
            try:
                tables = {r[0] for r in probe.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                require(tables == {'settings', 'frames'}, 'foreign_triage_database')
                row = probe.execute("SELECT value FROM settings WHERE key='binding'").fetchone()
                require(row is not None and row[0] == binding, 'triage_store_binding_mismatch')
            except sqlite3.DatabaseError:
                raise ValueError('triage_database_invalid') from None
            finally:
                probe.close()
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS frames(id TEXT PRIMARY KEY, sequence INTEGER NOT NULL,
                    revision TEXT NOT NULL, document TEXT NOT NULL);
            ''')
            db.execute('BEGIN IMMEDIATE')
            row = db.execute("SELECT value FROM settings WHERE key='binding'").fetchone()
            require(row is None or row[0] == binding, 'triage_store_binding_mismatch')
            db.execute("INSERT OR IGNORE INTO settings VALUES('binding',?)", (binding,))

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def frame_id(self, start, end):
        return event_fingerprint([VERSION, self.scope.identity, time_range(start, end, self.policy)])

    def replace(self, snapshot, start, end):
        """Trusted 7-A consumer only: never accept revisions/order from a browser."""
        result = evaluate(snapshot, self.scope, start, end, self.policy)
        frame = self.frame_id(start, end)
        order = result['revision_order'];revision = result['correlation_revision']
        serialized = encode(result)
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            publisher = db.execute("SELECT value FROM settings WHERE key='publisher'").fetchone()
            require(publisher is None or publisher[0] == order['publisher_id'], 'triage_publisher_changed')
            db.execute("INSERT OR IGNORE INTO settings VALUES('publisher',?)", (order['publisher_id'],))
            prior = db.execute('SELECT sequence,revision,document FROM frames WHERE id=?', (frame,)).fetchone()
            if prior:
                require(order['sequence'] >= prior[0], 'triage_stale_revision')
                if order['sequence'] == prior[0]:
                    require((revision, serialized) == prior[1:], 'triage_revision_conflict')
                    return {'applied': False, 'frame_id': frame, 'sequence': order['sequence']}
            db.execute('INSERT INTO frames VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                       'sequence=excluded.sequence,revision=excluded.revision,document=excluded.document',
                       (frame, order['sequence'], revision, serialized))
            require(db.execute('SELECT count(*) FROM frames').fetchone()[0] <= self.policy.max_queue_frames,
                    'triage_frame_capacity')
        return {'applied': True, 'frame_id': frame, 'sequence': order['sequence']}

    def queue(self, start, end, principal):
        if not self.scope.visible(principal):
            return {'items': []}
        frame = self.frame_id(start, end)
        with self.connect() as db:
            row = db.execute('SELECT document FROM frames WHERE id=?', (frame,)).fetchone()
        return json.loads(row[0]) if row else {'items': []}

    def item(self, identifier, start, end, principal):
        for item in self.queue(start, end, principal)['items']:
            if item['id'] == identifier:
                return item
        raise LookupError('triage_not_found')
