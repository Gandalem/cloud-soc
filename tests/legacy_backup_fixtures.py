"""Frozen format 2/3/4 SQLite contracts; no current app/writer/schema imports.

Every call creates an independent closed synthetic database set. Historical
manifests are assembled independently so writer and reader cannot mask each other.
"""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

STAMP = '2020-01-01T00:00:00+00:00'
SCHEMA_V2 = {
    'packages.sqlite3': """
        CREATE TABLE packages (id TEXT PRIMARY KEY, name TEXT NOT NULL, os TEXT NOT NULL,
            spec TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL, archive BLOB NOT NULL, UNIQUE(name, os));
        CREATE TABLE issued_keys (id TEXT PRIMARY KEY, package_id TEXT NOT NULL, created_at TEXT NOT NULL);
    """,
    'cases.sqlite': """
        CREATE TABLE cases (id TEXT PRIMARY KEY, title TEXT NOT NULL, organization TEXT NOT NULL,
            priority TEXT NOT NULL, status TEXT NOT NULL, owner TEXT, verdict TEXT NOT NULL,
            version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE case_alerts (alert_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
            linked_at TEXT NOT NULL, snapshot TEXT NOT NULL);
        CREATE INDEX case_alerts_case ON case_alerts(case_id);
        CREATE TABLE case_history (seq INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL REFERENCES cases(id), actor TEXT NOT NULL, at TEXT NOT NULL,
            version INTEGER NOT NULL, action TEXT NOT NULL, changes TEXT NOT NULL, note TEXT NOT NULL);
        CREATE INDEX case_history_case ON case_history(case_id, seq);
        CREATE TABLE case_requests (token TEXT PRIMARY KEY, actor TEXT NOT NULL,
            fingerprint TEXT NOT NULL, response TEXT NOT NULL);
        CREATE INDEX cases_queue ON cases(created_at DESC, id DESC);
    """,
    'log-access.sqlite': """
        CREATE TABLE source_access (seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL,
            role TEXT NOT NULL, purpose TEXT NOT NULL, reference_sha256 TEXT NOT NULL,
            outcome TEXT NOT NULL, policy_version TEXT NOT NULL);
    """,
}
DASHBOARD_V3 = 'CREATE TABLE dashboards (actor TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL);'
COLLECTION_V4 = 'CREATE TABLE dashboard_collections (actor TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL);'


def legacy_layout(actor):
    return {'name': actor + ' legacy', 'period': 60 if actor == 'other' else 1440,
            'theme': 'dark' if actor == 'other' else 'light',
            'widgets': [{'id': 'overview', 'size': 'wide'}, {'id': 'alerts', 'size': 'normal'}]}


def collection(actor):
    identifier = 'stored-board-' + actor
    return {'default_id': identifier, 'dashboards': [{'id': identifier, 'favorite': True,
            'layout': {'name': actor + ' collection', 'period': 1440, 'theme': 'dark', 'widgets': []}}]}


def legacy_source(root, version):
    if version not in (2, 3, 4):
        raise ValueError('Only frozen legacy formats are supported')
    root = Path(root)
    root.mkdir(mode=0o700)
    schemas = dict(SCHEMA_V2)
    if version >= 3:
        schemas['dashboards.sqlite'] = DASHBOARD_V3 + (COLLECTION_V4 if version == 4 else '')
    for name, sql in schemas.items():
        with closing(sqlite3.connect(root / name)) as db:
            db.executescript(sql)
        (root / name).chmod(0o600)
    with closing(sqlite3.connect(root / 'packages.sqlite3')) as db, db:
        db.execute('INSERT INTO packages VALUES (?,?,?,?,?,?,?,?)',
                   ('package-one', 'Synthetic package', 'linux', '{}', 'synthetic.zip', 'a' * 64, STAMP, b'synthetic-archive'))
        db.execute('INSERT INTO issued_keys VALUES (?,?,?)', ('synthetic-key-id', 'package-one', STAMP))
    with closing(sqlite3.connect(root / 'cases.sqlite')) as db, db:
        db.execute('INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?)',
                   ('case-one', 'Synthetic case', 'synthetic', 'high', 'new', None, 'unreviewed', 1, STAMP, STAMP))
        db.execute('INSERT INTO case_alerts VALUES (?,?,?,?)', ('alert-one', 'case-one', STAMP, '{"organization":"synthetic"}'))
        db.execute('INSERT INTO case_history VALUES (?,?,?,?,?,?,?,?)',
                   (1, 'case-one', 'operator', STAMP, 1, 'create', '{}', 'Synthetic review'))
        db.execute('INSERT INTO case_requests VALUES (?,?,?,?)', ('request-one', 'operator', 'b' * 64, '{"id":"case-one"}'))
    with closing(sqlite3.connect(root / 'log-access.sqlite')) as db, db:
        db.execute('INSERT INTO source_access VALUES (?,?,?,?,?,?,?,?)',
                   (1, STAMP, 'investigate', 'investigator', 'investigation', 'c' * 64, 'granted', 'policy-v1'))
    if version >= 3:
        with closing(sqlite3.connect(root / 'dashboards.sqlite')) as db, db:
            for actor in ('view', 'other'):
                db.execute('INSERT INTO dashboards VALUES (?,?,?)', (actor, 7, json.dumps(legacy_layout(actor))))
                if version == 4:
                    db.execute('INSERT INTO dashboard_collections VALUES (?,?,?)', (actor, 9, json.dumps(collection(actor))))
    return root


def database_snapshot(path):
    # Read-only and before any Store constructor can create missing schema.
    with closing(sqlite3.connect(Path(path).absolute().as_uri() + '?mode=ro', uri=True)) as db:
        tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        return {table: {'columns': db.execute('PRAGMA table_info("' + table + '")').fetchall(),
                        'rows': db.execute('SELECT * FROM "' + table + '" ORDER BY rowid').fetchall()}
                for table in tables}


def snapshot(root, names):
    return {name: database_snapshot(Path(root) / name) for name in sorted(names)}


def legacy_artifact(source, target, version):
    target = Path(target)
    target.mkdir(mode=0o700)
    names = sorted(SCHEMA_V2) + (['dashboards.sqlite'] if version >= 3 else [])
    report = {'format': version, 'kind': 'portal-sqlite-backup', 'created_at': STAMP,
              'consistency': 'per_database', 'missing': [], 'files': []}
    for name in names:
        destination = target / name
        shutil.copyfile(Path(source) / name, destination)
        destination.chmod(0o600)
        data = destination.read_bytes()
        counts = {table: len(value['rows']) for table, value in database_snapshot(destination).items()}
        report['files'].append({'name': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'counts': counts})
    manifest = target / 'manifest.json'
    manifest.write_text(json.dumps(report), encoding='utf-8')
    manifest.chmod(0o600)
    return report
