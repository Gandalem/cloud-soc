"""Shared, bounded failure budgets for the legacy Basic-auth entry point."""
from contextlib import closing
import hashlib
import math
import os
from pathlib import Path
import secrets
import sqlite3
import time

from werkzeug.security import check_password_hash, generate_password_hash


class BasicAuthGuard:
    def __init__(self, path, policy, *, clock=time.time):
        self.path, self.policy, self.clock = Path(path), policy, clock
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise ValueError('Unsafe Basic authentication state')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
        except FileExistsError:
            if os.name != 'nt' and self.path.stat().st_mode & 0o077:
                raise ValueError('Basic authentication state must be private')
        self.dummy_hash = generate_password_hash(secrets.token_urlsafe(32))
        with closing(sqlite3.connect(self.path, timeout=5)) as db:
            db.execute('CREATE TABLE IF NOT EXISTS failures (bucket TEXT PRIMARY KEY, attempts INTEGER NOT NULL, until REAL NOT NULL)')
            db.commit()

    def authenticate(self, username, password, peer):
        """Return (principal, retry_after). Never trust forwarded peer headers."""
        now = self.clock()
        known = isinstance(username, str) and (username == self.policy.admin_user or username in self.policy.users)
        account = username if known else '__unknown__'
        account_bucket = 'account:' + hashlib.sha256(account.encode()).hexdigest()
        peer_bucket = 'peer:' + hashlib.sha256((peer or '__missing__').encode()).hexdigest()
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            # Password checking and failure recording are one cross-process lock.
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM failures WHERE until <= ?', (now,))
            if (not db.execute('SELECT 1 FROM failures WHERE bucket=?', (peer_bucket,)).fetchone()
                    and db.execute("SELECT count(*) FROM failures WHERE bucket LIKE 'peer:%'").fetchone()[0] >= 256):
                peer_bucket = 'peer:overflow'
            buckets = ((account_bucket, 5), (peer_bucket, 10), ('global', 20))
            waits = []
            for bucket, limit in buckets:
                row = db.execute('SELECT attempts,until FROM failures WHERE bucket=?', (bucket,)).fetchone()
                if row and row[0] >= limit:
                    waits.append(math.ceil(row[1] - now))
            if waits:
                return None, max(1, max(waits))
            valid_shape = isinstance(username, str) and len(username) <= 64 and isinstance(password, str) and len(password) <= 1024
            principal = self.policy.authenticate(username, password) if valid_shape and known else None
            if valid_shape and not known:
                check_password_hash(self.dummy_hash, password)
            if principal is None:
                for bucket, _ in buckets:
                    db.execute('INSERT INTO failures VALUES (?,1,?) ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1',
                               (bucket, now + 300))
            # Successful requests do not reset other clients' failure budgets.
            return principal, 0
