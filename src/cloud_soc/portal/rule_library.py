"""Versioned rule authoring and durable desired/observed worker state.

Approval is immutable. Edits never mutate an approved release or its worker state.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

from cloud_soc.detection.authoring import (AuthoringError, FIELDS, GROUPS, MAX_RULES, capabilities,
    compile_rule, example, normalize, parse_import, summary)
from cloud_soc.detection.profiles import catalog
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.rule_management import RuleError, require


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def stamp():
    return datetime.now(timezone.utc).isoformat()


def aware(value):
    require(isinstance(value, str) and len(value) <= 64, 'time_invalid')
    try:
        result = datetime.fromisoformat(value.replace('Z', '+00:00'))
        require(result.utcoffset() is not None, 'time_zone_required')
        return result.astimezone(timezone.utc)
    except ValueError:
        raise RuleError('time_invalid') from None


class RuleLibrary:
    def __init__(self, path, organizations):
        self.path = Path(path)
        self.organizations = tuple(sorted(set(organizations)))
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS managed_rules (
                    id TEXT PRIMARY KEY, organization TEXT NOT NULL, rule_key TEXT NOT NULL,
                    version INTEGER NOT NULL, status TEXT NOT NULL, definition TEXT NOT NULL,
                    content_hash TEXT NOT NULL, generation INTEGER NOT NULL DEFAULT 0,
                    desired TEXT NOT NULL DEFAULT 'stopped', observed INTEGER NOT NULL DEFAULT 0,
                    observed_state TEXT NOT NULL DEFAULT 'not_started', observed_at TEXT,
                    created_at TEXT NOT NULL, UNIQUE(organization,rule_key));
                CREATE TABLE IF NOT EXISTS managed_versions (
                    rule_id TEXT NOT NULL, version INTEGER NOT NULL, definition TEXT NOT NULL,
                    engine_rule TEXT NOT NULL, content_hash TEXT NOT NULL, actor TEXT NOT NULL,
                    approved_at TEXT NOT NULL, PRIMARY KEY(rule_id,version));
                CREATE TABLE IF NOT EXISTS managed_releases (
                    rule_id TEXT NOT NULL, generation INTEGER NOT NULL, action TEXT NOT NULL,
                    version INTEGER NOT NULL, engine_rule TEXT NOT NULL, effective_from TEXT,
                    actor TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(rule_id,generation));
                CREATE TABLE IF NOT EXISTS managed_audit (
                    seq INTEGER PRIMARY KEY, rule_id TEXT NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, at TEXT NOT NULL, version INTEGER NOT NULL,
                    content_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS managed_batches (
                    request_id TEXT PRIMARY KEY, actor TEXT NOT NULL, content_hash TEXT NOT NULL,
                    result TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        require(not self.path.is_symlink(), 'unsafe_rule_store')
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def scope(self, principal):
        require(isinstance(principal, LogPrincipal) and principal.role == 'admin', 'admin_required', 403)
        return [o for o in self.organizations if principal.organizations is None or o in principal.organizations]

    def row(self, db, identifier, principal):
        orgs = self.scope(principal)
        require(isinstance(identifier, str) and re.fullmatch('[0-9a-f]{32}', identifier), 'rule_missing', 404)
        row = db.execute('SELECT * FROM managed_rules WHERE id=?', (identifier,)).fetchone()
        require(row is not None and row['organization'] in orgs, 'rule_missing', 404)
        return row

    @staticmethod
    def project(row):
        value = dict(row)
        value['definition'] = json.loads(value['definition'])
        value['summary'] = summary(value['definition'])
        fresh = value['observed_at'] and (datetime.now(timezone.utc) - aware(value['observed_at'])).total_seconds() <= 60
        value['active'] = bool(fresh and value['desired'] == 'running' and value['observed_state'] == 'running'
                               and value['observed'] == value['generation'])
        value['runtime_state'] = ('running' if value['active'] else 'stale' if value['desired'] == 'running' and
                                 value['observed_state'] == 'running' and not fresh else
                                 'failed' if value['observed_state'] == 'failed' else
                                 'pending' if value['observed'] != value['generation'] else value['observed_state'])
        return value

    def audit(self, db, row, actor, action):
        db.execute('INSERT INTO managed_audit(rule_id,actor,action,at,version,content_hash) VALUES(?,?,?,?,?,?)',
                   (row['id'], actor, action, stamp(), row['version'], row['content_hash']))

    def listing(self, principal):
        orgs = self.scope(principal)
        with self.connect() as db:
            rows = db.execute("SELECT * FROM managed_rules WHERE status<>'deleted' ORDER BY created_at DESC,id").fetchall()
            releases = {(r['rule_id'], r['generation']): dict(r) for r in db.execute(
                'SELECT rule_id,generation,version,action FROM managed_releases')}
        builtins = []
        for rule in catalog():
            builtins.append({'key': rule['id'], 'name': rule['name'], 'kind': rule.get('type', 'threshold'),
                             'severity': rule.get('severity', 'medium'), 'conditions': rule['conditions'],
                             'group_by': rule['group_by'], 'count': rule['threshold']['count'],
                             'window_seconds': rule['time_window']['seconds'], 'definition': self.builtin_form(rule)})
        projected = []
        for r in rows:
            if r['organization'] not in orgs:
                continue
            item = self.project(r)
            item['requested_version'] = releases.get((r['id'], r['generation']), {}).get('version')
            item['observed_version'] = releases.get((r['id'], r['observed']), {}).get('version')
            projected.append(item)
        return {'rules': projected,
                'organizations': orgs, 'capabilities': capabilities(),
                'builtin': builtins}

    @staticmethod
    def builtin_form(rule):
        template = {'AUTH-001': 'ssh_failures', 'WEB-ACCESS-01': 'access_denied',
                    'WEB-AUTH-01': 'login_sequence', 'WEB-SITE-404-001': 'web_errors',
                    'WEB-SITE-WAF-001': 'waf_sqli'}.get(rule['id'])
        if template is None:
            return None
        d = example(template)
        if rule['id'] == 'WEB-AUTH-01':
            d['source'] = 'mall'
        d.update(name=rule['name'], description=rule.get('alert', {}).get('message', ''),
                 severity=rule.get('severity', 'medium'), count=rule['threshold']['count'],
                 window_seconds=rule['time_window']['seconds'],
                 cooldown_seconds=rule.get('cooldown', {}).get('seconds', 0),
                 success_seconds=rule.get('success_window', {}).get('seconds', 0),
                 group_by=[f for f in rule['group_by'] if f in GROUPS])
        d['conditions'] = [dict(c) for c in rule['conditions'] if c['field'] in FIELDS and
                           not (d['kind'] == 'sequence' and c['field'] == 'event.outcome')]
        return normalize(d)

    def detail(self, identifier, principal):
        with self.connect() as db:
            result = self.project(self.row(db, identifier, principal))
            release = db.execute('SELECT version,effective_from FROM managed_releases WHERE rule_id=? AND generation=?',
                                 (identifier, result['generation'])).fetchone()
            observed = db.execute('SELECT version FROM managed_releases WHERE rule_id=? AND generation=?',
                                  (identifier, result['observed'])).fetchone()
            result['requested_version'] = release['version'] if release else None
            result['observed_version'] = observed['version'] if observed else None
            result['effective_from'] = release['effective_from'] if release else None
            result['history'] = [dict(r) for r in db.execute(
                'SELECT actor,action,at,version,content_hash FROM managed_audit WHERE rule_id=? ORDER BY seq', (identifier,))]
            result['versions'] = [dict(r) for r in db.execute(
                'SELECT version,content_hash,actor,approved_at FROM managed_versions WHERE rule_id=? ORDER BY version', (identifier,))]
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='managed_input_issues'").fetchone():
                result['input_issues'] = [dict(r) for r in db.execute(
                    'SELECT reason,count(*) AS count FROM managed_input_issues WHERE rule_id=? GROUP BY reason', (identifier,))]
            return result

    def checked(self, definition, organization):
        try:
            d = normalize(definition)
            reserved = {r['id'] for r in catalog()}
            require(d['key'] not in reserved, 'rule_key_reserved', 409)
            compile_rule(d, organization)
            return d
        except AuthoringError as error:
            raise RuleError(error.code) from None
        except ValueError:
            raise RuleError('engine_rule_invalid') from None

    def insert(self, db, organization, definition, principal):
        require(organization in self.scope(principal), 'rule_missing', 404)
        d = self.checked(definition, organization)
        require(not db.execute('SELECT 1 FROM managed_rules WHERE organization=? AND rule_key=?',
                               (organization, d['key'])).fetchone(), 'rule_key_unavailable', 409)
        require(db.execute('SELECT count(*) FROM managed_rules').fetchone()[0] < 2000, 'rule_capacity', 429)
        identifier = uuid4().hex
        db.execute('INSERT INTO managed_rules(id,organization,rule_key,version,status,definition,content_hash,created_at) '
                   'VALUES(?,?,?,?,?,?,?,?)', (identifier, organization, d['key'], 1, 'draft', encoded(d), digest(d), stamp()))
        self.audit(db, self.row(db, identifier, principal), principal.username, 'created')
        return identifier

    def create(self, body, principal):
        require(isinstance(body, dict) and set(body) == {'organization', 'definition'}, 'request_invalid')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            identifier = self.insert(db, body['organization'], body['definition'], principal)
        return self.detail(identifier, principal)

    @staticmethod
    def token(row, body):
        require(type(body.get('version')) is int and body['version'] == row['version'] and
                body.get('content_hash') == row['content_hash'], 'rule_changed', 409)
        require(digest(json.loads(row['definition'])) == row['content_hash'], 'rule_integrity_failed', 409)

    def action(self, identifier, action, body, principal):
        self.scope(principal)
        require(action in ('edit', 'approve', 'apply', 'stop', 'delete'), 'action_invalid')
        require(isinstance(body, dict) and {'version', 'content_hash'} <= set(body) and
                set(body) <= {'version', 'content_hash', 'definition', 'effective_from'}, 'request_invalid')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = self.row(db, identifier, principal)
            self.token(row, body)
            require(row['version'] < 10000, 'rule_history_capacity', 429)
            require(row['status'] not in ('deleted', 'delete_pending'), 'rule_deleted', 409)
            version, status, definition, content_hash = row['version'], row['status'], row['definition'], row['content_hash']
            if action == 'edit':
                d = self.checked(body.get('definition'), row['organization'])
                require(d['key'] == row['rule_key'], 'rule_key_immutable', 409)
                version += 1
                status, definition, content_hash = 'draft', encoded(d), digest(d)
            elif action == 'approve':
                require(status == 'draft', 'draft_required', 409)
                d = self.checked(json.loads(definition), row['organization'])
                db.execute('INSERT INTO managed_versions VALUES(?,?,?,?,?,?,?)',
                           (identifier, version + 1, definition, encoded(compile_rule(d, row['organization'])),
                            content_hash, principal.username, stamp()))
                status = 'approved'
            else:
                if action == 'apply':
                    require(status == 'approved', 'approval_required', 409)
                    start = aware(body.get('effective_from')).isoformat()
                    require(aware(start) <= datetime.now(timezone.utc), 'start_in_future')
                    approved = db.execute('SELECT engine_rule,version FROM managed_versions WHERE rule_id=? '
                                          'AND content_hash=? ORDER BY version DESC LIMIT 1',
                                          (identifier, content_hash)).fetchone()
                    require(approved is not None, 'approved_version_missing', 409)
                    engine_rule = approved['engine_rule']
                else:
                    start, engine_rule = None, '{}'
                generation = row['generation'] + 1
                desired = 'running' if action == 'apply' else 'deleted' if action == 'delete' else 'stopped'
                db.execute('INSERT INTO managed_releases VALUES(?,?,?,?,?,?,?,?)',
                           (identifier, generation, desired, approved['version'] if action == 'apply' else version,
                            engine_rule, start, principal.username, stamp()))
                # Stopped/unassigned rules can be removed immediately. Once released, require the worker ack.
                if action == 'delete':
                    status = 'deleted' if row['generation'] == 0 else 'delete_pending'
                db.execute('UPDATE managed_rules SET generation=?,desired=? WHERE id=?', (generation, desired, identifier))
            # Increment action version for concurrency even if the definition is unchanged.
            if action != 'edit':
                version += 1
            db.execute('UPDATE managed_rules SET version=?,status=?,definition=?,content_hash=? WHERE id=?',
                       (version, status, definition, content_hash, identifier))
            self.audit(db, self.row(db, identifier, principal), principal.username, action)
        return self.detail(identifier, principal)

    def import_rules(self, body, principal, *, preview=False):
        require(isinstance(body, dict) and {'organization', 'format', 'content', 'request_id'} <= set(body)
                and set(body) <= {'organization', 'format', 'content', 'request_id', 'selected_rows'}, 'request_invalid')
        require(body['organization'] in self.scope(principal), 'rule_missing', 404)
        require(isinstance(body['request_id'], str) and re.fullmatch('[A-Za-z0-9_-]{8,100}', body['request_id']), 'request_id_invalid')
        try:
            rows = parse_import(body['format'], body['content'])
        except AuthoringError as error:
            raise RuleError(error.code) from None
        request_hash = digest(body)
        selected = body.get('selected_rows', list(range(1, len(rows) + 1)))
        require(isinstance(selected, list) and selected and all(type(n) is int and 1 <= n <= len(rows) for n in selected)
                and len(set(selected)) == len(selected), 'selected_rows_invalid')
        results, normalized, seen = [], [], set()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM managed_batches WHERE request_id=?', (body['request_id'],)).fetchone()
            if old:
                require(old['actor'] == principal.username and old['content_hash'] == request_hash, 'request_id_conflict', 409)
                return json.loads(old['result'])
            for number, item in enumerate(rows, 1):
                if number not in selected:
                    continue
                try:
                    d = self.checked(item, body['organization'])
                    require(d['key'] not in seen, 'duplicate_import_key', 409)
                    seen.add(d['key'])
                    require(not db.execute('SELECT 1 FROM managed_rules WHERE organization=? AND rule_key=?',
                                           (body['organization'], d['key'])).fetchone(), 'rule_key_unavailable', 409)
                    normalized.append(d)
                    results.append({'row': number, 'key': d['key'], 'summary': summary(d), 'valid': True})
                except RuleError as error:
                    results.append({'row': number, 'valid': False, 'code': error.code})
            valid = all(r['valid'] for r in results)
            result = {'valid': valid, 'items': results, 'created': []}
            if preview:
                return result
            require(valid, 'import_rows_invalid', 409)
            require(len(normalized) <= MAX_RULES, 'import_capacity')
            result['created'] = [self.insert(db, body['organization'], d, principal) for d in normalized]
            db.execute('INSERT INTO managed_batches VALUES(?,?,?,?)',
                       (body['request_id'], principal.username, request_hash, encoded(result)))
        return result

    def export(self, principal):
        data = self.listing(principal)
        return {'schema_version': 1, 'rules': [r['definition'] for r in data['rules']]}

    def desired_releases(self, organizations):
        with self.connect() as db:
            rows = db.execute('SELECT m.*,r.action,r.engine_rule,r.effective_from FROM managed_rules m '
                              'JOIN managed_releases r ON r.rule_id=m.id AND r.generation=m.generation '
                              "WHERE m.status<>'deleted'").fetchall()
            return [dict(row) for row in rows if row['organization'] in organizations]

    def acknowledge(self, identifier, generation, state):
        require(state in ('running', 'stopped', 'deleted', 'failed'), 'worker_state_invalid')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM managed_rules WHERE id=?', (identifier,)).fetchone()
            require(row is not None and row['generation'] == generation, 'release_changed', 409)
            require(state == 'failed' or state == row['desired'], 'worker_state_mismatch', 409)
            db.execute('UPDATE managed_rules SET observed=?,observed_state=?,observed_at=? WHERE id=?',
                       (generation, state, stamp(), identifier))
            if state == 'deleted':
                db.execute("UPDATE managed_rules SET status='deleted' WHERE id=?", (identifier,))
