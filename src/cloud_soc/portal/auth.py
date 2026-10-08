"""Opt-in single-workspace RBAC and revocable server-side sessions."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from werkzeug.security import check_password_hash, generate_password_hash

ROLES = {"admin", "analyst", "viewer"}
COOKIE = "soc_session"
PUBLIC = {"login_page", "auth_asset", "login"}
READ_ENDPOINTS = {
    "index", "static_file", "auth_me", "logout", "case_list", "case_link", "case_detail",
    "agent_status", "collection_health", "logs", "log_detail", "log_access", "operations_summary", "alert_detail",
    "detection_history", "reprocessing_history", "healthz",
}
CASE_WRITES = {"case_create", "case_update"}


def load_users(filename):
    path = Path(filename)
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("User configuration must be private (chmod 600)")
    users = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(users, dict) or not 1 <= len(users) <= 100:
        raise ValueError("Invalid users configuration")
    for name, row in users.items():
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name) or not isinstance(row, dict)
                or set(row) != {"role", "password_hash"} or row["role"] not in ROLES
                or not isinstance(row["password_hash"], str)
                or not row["password_hash"].startswith(("scrypt:", "pbkdf2:sha256:"))):
            raise ValueError("Invalid user entry")
    if not any(row["role"] == "admin" for row in users.values()):
        raise ValueError("An administrator is required")
    return users


def permitted(endpoint, method, role, filename=None):
    if role == "admin":
        return True
    if endpoint == "static_file":
        return filename not in {"agents.html", "agents.js", "app.js", "demo-data.js"}
    if endpoint in READ_ENDPOINTS and method in {"GET", "HEAD", "OPTIONS"}:
        return True
    if endpoint == "logout":
        return True
    if endpoint == "log_source" and method == "POST":
        return True
    return role == "analyst" and endpoint in CASE_WRITES


class Sessions:
    def __init__(self, path, users, *, ttl=3600):
        self.path, self.users, self.ttl = Path(path), users, ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Same cost for unknown users as the default password hash scheme.
        self.dummy_hash = generate_password_hash(secrets.token_urlsafe(32))
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY, user TEXT NOT NULL, revision TEXT NOT NULL,
                    csrf TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS login_attempts (
                    identity TEXT PRIMARY KEY, attempts INTEGER NOT NULL, until REAL NOT NULL);
            """)
        if os.name != "nt":
            self.path.chmod(0o600)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def revision(self, user):
        return hashlib.sha256(json.dumps(self.users[user], sort_keys=True).encode()).hexdigest()

    def login(self, user, password):
        if (not isinstance(user, str) or not isinstance(password, str)
                or len(user) > 64 or not 1 <= len(password) <= 1024):
            return None
        now = time.time()
        # Unknown usernames share a single bucket to bound storage growth.
        identity = user if user in self.users else "__unknown__"
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM sessions WHERE expires <= ?", (now,))
            db.execute("DELETE FROM login_attempts WHERE until <= ?", (now,))
            attempt = db.execute("SELECT * FROM login_attempts WHERE identity=?", (identity,)).fetchone()
            if attempt and attempt["attempts"] >= 5:
                return None
            valid = check_password_hash(self.users.get(user, {}).get("password_hash", self.dummy_hash), password)
            if not valid or user not in self.users:
                db.execute("INSERT INTO login_attempts VALUES (?,1,?) ON CONFLICT(identity) DO UPDATE SET attempts=attempts+1",
                           (identity, now + 300))
                return None
            db.execute("DELETE FROM login_attempts WHERE identity=?", (identity,))
            # Bound active sessions per user, retaining the ten most recent.
            db.execute("DELETE FROM sessions WHERE user=? AND token NOT IN (SELECT token FROM sessions WHERE user=? ORDER BY expires DESC LIMIT 9)", (user, user))
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            db.execute("INSERT INTO sessions VALUES (?,?,?,?,?)",
                       (hashlib.sha256(token.encode()).hexdigest(), user, self.revision(user), csrf, now + self.ttl))
            return token

    def get(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        with self.connect() as db:
            row = db.execute("SELECT * FROM sessions WHERE token=? AND expires>?",
                             (hashlib.sha256(token.encode()).hexdigest(), time.time())).fetchone()
        if not row or row["user"] not in self.users or row["revision"] != self.revision(row["user"]):
            return None
        return {"user": row["user"], "role": self.users[row["user"]]["role"], "csrf": row["csrf"]}

    def logout(self, token):
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE token=?", (hashlib.sha256(token.encode()).hexdigest(),))
