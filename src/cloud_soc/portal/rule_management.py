"""Manual drafts for the existing YAML engine. Approval never deploys a rule."""
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from uuid import uuid4

import yaml
from cloud_soc.detection.profiles import catalog
from cloud_soc.detection.rule_loader import SUPPORTED_OPERATORS, validate_rule
from cloud_soc.portal.cases import clean
from cloud_soc.portal.log_access import LogPrincipal

FIELDS = frozenset({'organization.id', 'service.name', 'host.id', 'source.ip', 'event.id',
    'event.category', 'event.action', 'event.outcome', 'network.protocol', 'http.request.method',
    'http.response.status_code', 'cloud_soc.detail.adapter', 'cloud_soc.security_mall.resource_type',
    'cloud_soc.security_mall.authorization_reason', 'cloud_soc.security_mall.account_id',
    'cloud_soc.security_mall.account_key_id'})
GROUPS = FIELDS - {'event.category', 'event.action', 'event.outcome', 'http.request.method',
    'http.response.status_code', 'network.protocol', 'cloud_soc.detail.adapter',
    'cloud_soc.security_mall.resource_type', 'cloud_soc.security_mall.authorization_reason'}
ROOT_FIELDS = {'id', 'name', 'description', 'type', 'enabled', 'severity', 'conditions',
               'group_by', 'threshold', 'time_window', 'cooldown', 'alert'}


class RuleError(Exception):
    def __init__(self, code, status=400):
        super().__init__('규칙 입력·권한·상태를 확인하세요. 검증 성공은 실제 탐지 성공이 아닙니다.')
        self.code, self.status = code, status


def require(value, code='invalid_rule', status=400):
    if not value:
        raise RuleError(code, status)


def safe_text(value, limit, *, empty=False):
    try:
        return clean(value, limit, empty=empty)
    except Exception:
        raise RuleError('invalid_rule_text') from None


class UniqueLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            require(isinstance(key, str) and key not in result, 'duplicate_or_invalid_yaml_key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def validate_draft(text, organization, reserved):
    """A bounded subset of the real engine schema, with an explicit tenant guard."""
    try:
        depth = 0
        for number, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader)):
            require(number < 2048, 'yaml_too_complex')
            require(not isinstance(event, yaml.AliasEvent) and not getattr(event, 'anchor', None)
                    and not getattr(event, 'tag', None), 'yaml_alias_or_tag_forbidden')
            if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
                depth += 1
            elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
                depth -= 1
            require(depth <= 12, 'yaml_too_complex')
        # UniqueLoader inherits SafeLoader's constructors and rejects duplicate keys.
        # Own its lifecycle explicitly; no generic yaml.load on untrusted drafts.
        loader = UniqueLoader(text)
        try:
            document = loader.get_single_data()
        finally:
            loader.dispose()
        require(isinstance(document, dict) and set(document) == {'rules'} and
                isinstance(document['rules'], list) and len(document['rules']) == 1, 'one_rule_required')
        rule = document['rules'][0]
        require(isinstance(rule, dict) and set(rule) <= ROOT_FIELDS and
                ROOT_FIELDS - {'cooldown'} <= set(rule), 'rule_fields_invalid')
        require(isinstance(rule['id'], str) and re.fullmatch('[A-Z][A-Z0-9-]{2,63}', rule['id']), 'rule_id_invalid')
        require(rule['id'] not in reserved, 'rule_id_unavailable', 409)
        require(rule['type'] in ('threshold', 'single'), 'mvp_rule_type_unsupported')
        for key in ('name', 'description'):
            safe_text(rule[key], 1000)
        require(type(rule['enabled']) is bool and rule['enabled'], 'enabled_must_be_explicit')
        require(rule['severity'] in ('low', 'medium', 'high', 'critical'), 'severity_invalid')
        for name, key, low, high in (('threshold', 'count', 1, 10000), ('time_window', 'seconds', 1, 3600),
                                     ('cooldown', 'seconds', 0, 86400)):
            value = rule.get(name, {'seconds': 0})
            require(isinstance(value, dict) and set(value) == {key} and type(value[key]) is int
                    and low <= value[key] <= high, 'rule_bounds_invalid')
        groups = rule['group_by']
        require(isinstance(groups, list) and 1 <= len(groups) <= 8 and
                all(isinstance(k, str) and k in GROUPS for k in groups) and len(set(groups)) == len(groups)
                and 'organization.id' in groups, 'group_scope_invalid')
        conditions = rule['conditions']
        require(isinstance(conditions, list) and 1 <= len(conditions) <= 16, 'conditions_invalid')
        for c in conditions:
            require(isinstance(c, dict) and set(c) == {'field', 'operator', 'value'} and
                    isinstance(c['field'], str) and c['field'] in FIELDS and
                    isinstance(c['operator'], str) and c['operator'] in SUPPORTED_OPERATORS, 'condition_unsupported')
            value = c['value']
            if c['operator'] == 'exists':
                require(type(value) is bool, 'condition_type_invalid')
            else:
                values = value if c['operator'] == 'in' else [value]
                require(isinstance(values, list) and 1 <= len(values) <= 16, 'condition_type_invalid')
                for v in values:
                    if c['field'] == 'http.response.status_code':
                        require(type(v) is int and 100 <= v <= 599, 'condition_type_invalid')
                    else:
                        require(isinstance(v, str), 'condition_type_invalid')
                        safe_text(v, 128)
                require(c['operator'] != 'greater_than' or c['field'] == 'http.response.status_code',
                        'condition_type_invalid')
        require(any(c == {'field': 'organization.id', 'operator': 'equals', 'value': organization}
                    for c in conditions), 'organization_guard_required')
        alert = rule['alert']
        require(isinstance(alert, dict) and set(alert) == {'title', 'message', 'category', 'tags'}, 'alert_fields_invalid')
        for name in ('title', 'message'):
            safe_text(alert[name], 1000)
        require(alert['category'] in ('authentication', 'iam', 'web', 'network', 'intrusion_detection'), 'alert_category_invalid')
        require(isinstance(alert['tags'], list) and len(alert['tags']) <= 10 and
                all(isinstance(v, str) and re.fullmatch('[a-zA-Z0-9_-]{1,40}', v) for v in alert['tags']), 'alert_tags_invalid')
        # The actual engine validator is authoritative for engine-specific semantics/defaults.
        validate_rule(deepcopy(rule))
        return rule
    except RuleError:
        raise
    except (yaml.YAMLError, TypeError, ValueError, KeyError, RecursionError):
        raise RuleError('yaml_or_engine_schema_invalid') from None


class RuleDraftStore:
    """Two workflow/audit tables in the existing Portal cases.sqlite, no new DB.

    Approved YAML is only exported. The fixed detector profile is never rewritten.
    """
    def __init__(self, path, organizations):
        self.path = Path(path)
        self.organizations = tuple(sorted(set(organizations)))
        require(not self.path.is_symlink(), 'unsafe_rule_store')
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS rule_drafts(
                    id TEXT PRIMARY KEY, organization TEXT NOT NULL, yaml TEXT NOT NULL, intent TEXT NOT NULL,
                    content_hash TEXT NOT NULL, status TEXT NOT NULL, application_state TEXT NOT NULL,
                    version INTEGER NOT NULL, rule_id TEXT, validation TEXT NOT NULL,
                    created_at TEXT NOT NULL, approved_by TEXT, approved_at TEXT);
                CREATE UNIQUE INDEX IF NOT EXISTS rule_approved_id ON rule_drafts(rule_id) WHERE status='approved';
                CREATE TABLE IF NOT EXISTS rule_history(
                    seq INTEGER PRIMARY KEY, draft_id TEXT NOT NULL, actor TEXT NOT NULL, at TEXT NOT NULL,
                    action TEXT NOT NULL, version INTEGER NOT NULL, rule_id TEXT, content_hash TEXT NOT NULL,
                    result TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        require(not self.path.is_symlink(), 'unsafe_rule_store')
        db = sqlite3.connect(self.path, timeout=5);db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def scope(self, principal):
        require(isinstance(principal, LogPrincipal) and principal.role == 'admin', 'admin_required', 403)
        return [o for o in self.organizations if principal.organizations is None or o in principal.organizations]

    def get(self, db, identifier, principal):
        organizations = self.scope(principal)
        require(isinstance(identifier, str) and re.fullmatch('[0-9a-f]{32}', identifier), 'rule_draft_missing', 404)
        row = db.execute('SELECT * FROM rule_drafts WHERE id=?', (identifier,)).fetchone()
        require(row is not None and row['organization'] in organizations, 'rule_draft_missing', 404)
        return row

    @staticmethod
    def project(row):
        result = dict(row);result['validation'] = json.loads(result['validation'])
        result['active'] = False
        return result

    def history(self, db, identifier):
        return [dict(row) for row in db.execute('SELECT actor,at,action,version,rule_id,content_hash,result '
                                               'FROM rule_history WHERE draft_id=? ORDER BY seq', (identifier,))]

    def record(self, db, row, principal, action):
        db.execute('INSERT INTO rule_history(draft_id,actor,at,action,version,rule_id,content_hash,result) VALUES(?,?,?,?,?,?,?,?)',
            (row['id'], principal.username, datetime.now(timezone.utc).isoformat(), action,
             row['version'], row['rule_id'], row['content_hash'], json.dumps({'status':row['status'],
              'application_state':row['application_state'], 'validation':json.loads(row['validation'])})))

    def detail(self, identifier, principal):
        with self.connect() as db:
            row = self.get(db, identifier, principal)
            return dict(self.project(row), history=self.history(db, identifier))

    def listing(self, principal):
        orgs = self.scope(principal)
        with self.connect() as db:
            rows = db.execute('SELECT id,organization,status,application_state,version,rule_id,created_at '
                              'FROM rule_drafts ORDER BY created_at DESC,id').fetchall()
        return {'drafts': [dict(r) for r in rows if r['organization'] in orgs], 'organizations': orgs,
                'ai': 'not_connected', 'application': 'manual_deployment_required',
                'supported_types': ['threshold', 'single'], 'fields': sorted(FIELDS),
                'operators': sorted(SUPPORTED_OPERATORS)}

    def create(self, body, principal):
        orgs = self.scope(principal)
        require(isinstance(body, dict) and set(body) == {'organization', 'yaml', 'intent'}, 'draft_fields_invalid')
        require(body['organization'] in orgs, 'rule_draft_missing', 404)
        text = body['yaml'];safe_text(text, 4096)
        intent = safe_text(body['intent'], 1024, empty=True)
        require(len(text.encode()) <= 4096 and len(intent.encode()) <= 1024, 'draft_size_invalid')
        identifier = uuid4().hex;stamp = datetime.now(timezone.utc).isoformat()
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            require(db.execute('SELECT count(*) FROM rule_drafts').fetchone()[0] < 200, 'draft_capacity_reached', 429)
            db.execute('INSERT INTO rule_drafts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (identifier, body['organization'], text, intent, hashlib.sha256(text.encode()).hexdigest(),
                 'draft', 'not_approved', 1, None, '{}', stamp, None, None))
            self.record(db, self.get(db, identifier, principal), principal, 'created')
        return self.detail(identifier, principal)

    def validate(self, row, db):
        try:
            from cloud_soc.detection.profiles import APPLICATION_IDS
            reserved = {r['id'] for r in catalog(include_applications=False)} | set(APPLICATION_IDS)
        except Exception:
            raise RuleError('rule_catalog_unavailable', 503) from None
        reserved.update(r[0] for r in db.execute("SELECT rule_id FROM rule_drafts WHERE status='approved' AND id<>?", (row['id'],)))
        require(hashlib.sha256(row['yaml'].encode()).hexdigest() == row['content_hash'], 'draft_integrity_failed', 409)
        return validate_draft(row['yaml'], row['organization'], reserved)

    def action(self, identifier, action, body, principal):
        self.scope(principal)
        require(action in ('validate', 'approve', 'reject', 'apply'), 'rule_action_invalid')
        require(isinstance(body, dict) and set(body) == {'version', 'content_hash'} and type(body['version']) is int,
                'rule_action_input_invalid')
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE');row = self.get(db, identifier, principal)
            require((body['version'], body['content_hash']) == (row['version'], row['content_hash']), 'rule_draft_changed', 409)
            status, application, validation, rule_id = row['status'], row['application_state'], row['validation'], row['rule_id']
            approved_by, approved_at = row['approved_by'], row['approved_at']
            if action == 'validate':
                require(status in ('draft', 'validated'), 'rule_state_conflict', 409)
                try:
                    rule_id = self.validate(row, db)['id'];status = 'validated'
                    validation = json.dumps({'valid': True, 'engine_schema': True, 'detection_verified': False})
                except RuleError as error:
                    if error.status == 503:
                        raise
                    status, rule_id = 'draft', None
                    validation = json.dumps({'valid': False, 'code': error.code, 'detection_verified': False})
            elif action == 'approve':
                require(status == 'validated' and json.loads(validation).get('valid') is True, 'validation_required', 409)
                rule_id = self.validate(row, db)['id']
                status, application = 'approved', 'awaiting_application'
                approved_by, approved_at = principal.username, datetime.now(timezone.utc).isoformat()
            elif action == 'reject':
                require(status in ('draft', 'validated'), 'rule_state_conflict', 409)
                status = 'rejected'
            else:
                require(status == 'approved', 'approval_required', 409)
                self.validate(row, db)
                require(application == 'awaiting_application', 'application_already_pending', 409)
                application = 'pending_deployment'
            db.execute('UPDATE rule_drafts SET status=?,application_state=?,validation=?,rule_id=?,version=version+1,'
                       'approved_by=?,approved_at=? WHERE id=?',
                       (status, application, validation, rule_id, approved_by, approved_at, identifier))
            self.record(db, self.get(db, identifier, principal), principal, action)
        return self.detail(identifier, principal)

    def export(self, identifier, principal):
        with self.connect() as db:
            row = self.get(db, identifier, principal)
            require(row['status'] == 'approved', 'approval_required', 409)
            self.validate(row, db)
            return row['yaml']
