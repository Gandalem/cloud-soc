"""Round-trip CSV editing for managed rules and built-in deployment proposals."""
import csv
import io
import json
import math
from uuid import uuid4

from cloud_soc.detection.authoring import AuthoringError, MAX_FILE_BYTES, MAX_RULES
from cloud_soc.detection.profiles import catalog
from cloud_soc.detection.rule_loader import validate_rule
from cloud_soc.portal.rule_library import digest, encoded, stamp
from cloud_soc.portal.rule_management import RuleError, require

COLUMNS = ('scope', 'organization', 'rule_id', 'base_version', 'base_hash', 'definition_json')


def decode(content):
    require(isinstance(content, str) and len(content.encode('utf-8')) <= MAX_FILE_BYTES,
            'file_size_invalid')
    try:
        reader = csv.DictReader(io.StringIO(content.lstrip('\ufeff')), strict=True)
        require(tuple(reader.fieldnames or ()) == COLUMNS, 'csv_columns_invalid')
        rows = []
        for row in reader:
            require(None not in row and all(value is not None for value in row.values()), 'csv_row_invalid')
            rows.append(row)
            require(len(rows) <= MAX_RULES, 'import_capacity')
    except csv.Error:
        raise RuleError('csv_row_invalid') from None
    require(rows, 'import_capacity')
    return rows


def definition(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'duplicate_json_key')
            result[key] = value
        return result

    def reject_constant(_value):
        raise RuleError('csv_value_invalid')

    try:
        def finite(value):
            number = float(value)
            require(math.isfinite(number), 'csv_value_invalid')
            return number

        result = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant, parse_float=finite)
    except (ValueError, RecursionError, OverflowError) as error:
        if isinstance(error, RuleError):
            raise
        raise RuleError('csv_value_invalid') from None
    require(isinstance(result, dict), 'csv_value_invalid')
    return result


def organization_value(value):
    # Excel strips the CSV quoting, so the JSON quotes are part of the field value.
    try:
        organization = json.loads(value)
    except (ValueError, RecursionError):
        raise RuleError('csv_row_invalid') from None
    require(isinstance(organization, str), 'csv_row_invalid')
    return organization


def diff(previous, candidate):
    return [{'field': field, 'before': previous.get(field), 'after': candidate.get(field)}
            for field in sorted(previous.keys() | candidate.keys())
            if field not in previous or field not in candidate or encoded(previous[field]) != encoded(candidate[field])]


class RuleCsv:
    def __init__(self, library):
        self.library = library
        with library.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS builtin_rule_csv (
                id TEXT PRIMARY KEY, rule_key TEXT NOT NULL, base_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL, definition TEXT NOT NULL,
                status TEXT NOT NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL,
                approved_by TEXT, approved_at TEXT, requested_by TEXT, requested_at TEXT,
                UNIQUE(rule_key, base_hash, content_hash))''')

    @staticmethod
    def builtins():
        return {rule['id']: rule for rule in catalog()}

    def export(self, principal, identifier=None):
        orgs = self.library.scope(principal)
        stream = io.StringIO(newline='')
        writer = csv.writer(stream)
        writer.writerow(COLUMNS)
        with self.library.connect() as db:
            if identifier and len(identifier) == 32:
                managed = [self.library.row(db, identifier, principal)]
            elif not identifier:
                managed = db.execute("SELECT * FROM managed_rules WHERE status NOT IN ('deleted','delete_pending') "
                                     "ORDER BY organization, rule_key").fetchall()
            else:
                managed = []
            for row in managed:
                if row['organization'] in orgs and row['status'] not in ('deleted', 'delete_pending'):
                    # Prevent formula evaluation by spreadsheet apps and preserve the exact organization ID.
                    writer.writerow(('managed', json.dumps(row['organization'], ensure_ascii=False),
                                     row['rule_key'], row['version'],
                                     row['content_hash'], row['definition']))
        if principal.organizations is None:
            for key, rule in sorted(self.builtins().items()):
                if not identifier or key == identifier:
                    writer.writerow(('builtin', '', key, '', digest(rule), encoded(rule)))
        result = stream.getvalue()
        rows = decode('\ufeff' + result)
        require(not identifier or len(rows) == 1, 'rule_missing', 404)
        return result

    def compare(self, db, row, proposed, principal, builtins):
        key, org = row['rule_id'], row['organization']
        if row['scope'] == 'managed':
            org = organization_value(org)
            require(org in self.library.scope(principal), 'rule_missing', 404)
            saved = db.execute('SELECT * FROM managed_rules WHERE organization=? AND rule_key=?',
                               (org, key)).fetchone()
            require(saved and saved['status'] not in ('deleted', 'delete_pending'), 'rule_missing', 404)
            require(str(saved['version']) == row['base_version'], 'rule_changed', 409)
            self.library.token(saved, {'version': saved['version'], 'content_hash': row['base_hash']})
            candidate = self.library.checked(proposed, org)
            require(candidate['key'] == key, 'rule_key_immutable', 409)
            return saved, json.loads(saved['definition']), candidate

        require(row['scope'] == 'builtin' and not org and not row['base_version'], 'csv_row_invalid')
        require(principal.organizations is None and key in builtins, 'rule_missing', 404)
        previous = builtins[key]
        require(row['base_hash'] == digest(previous), 'rule_changed', 409)
        # Release selection and the engine algorithm remain owned by the built-in profile.
        for field in ('id', 'type', 'enabled', 'metadata_profile'):
            require(previous.get(field) == proposed.get(field), 'builtin_identity_changed')
        require(set(proposed) == set(previous), 'builtin_fields_changed')
        try:
            validate_rule(proposed)
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            raise RuleError('engine_rule_invalid') from None
        return None, previous, proposed

    def upload(self, body, principal, *, preview):
        self.library.scope(principal)
        require(isinstance(body, dict) and set(body) == ({'content'} if preview else {'content', 'selected_rows'}),
                'request_invalid')
        rows = decode(body['content'])
        selected = list(range(1, len(rows) + 1)) if preview else body['selected_rows']
        require(isinstance(selected, list) and selected and
                all(type(n) is int and 1 <= n <= len(rows) for n in selected)
                and len(selected) == len(set(selected)), 'selected_rows_invalid')
        results, seen, staged = [], set(), []
        builtins = self.builtins()
        with self.library.connect() as db:
            db.execute('BEGIN' if preview else 'BEGIN IMMEDIATE')
            for number in selected:
                row = rows[number - 1]
                item = {key: row[key] for key in ('scope', 'organization', 'rule_id')}
                item['row'] = number
                try:
                    if row['scope'] == 'managed':
                        item['organization'] = organization_value(row['organization'])
                    identity = tuple(item[key] for key in ('scope', 'organization', 'rule_id'))
                    require(identity not in seen, 'duplicate_import_key', 409)
                    seen.add(identity)
                    saved, previous, candidate = self.compare(db, row, definition(row['definition_json']),
                                                               principal, builtins)
                    changes = diff(previous, candidate)
                    item.update(valid=True, changes=changes)
                    if changes:
                        staged.append((row, saved, candidate))
                except (RuleError, AuthoringError) as error:
                    item.update(valid=False, code=error.code)
                results.append(item)
            if preview:
                return {'items': results}
            require(all(item['valid'] for item in results), 'import_rows_invalid', 409)
            saved_count = 0
            for row, saved, candidate in staged:
                if saved is not None:
                    self.library.save_edit(db, saved, candidate, principal)
                    saved_count += 1
                else:
                    inserted = db.execute('INSERT OR IGNORE INTO builtin_rule_csv '
                               '(id,rule_key,base_hash,content_hash,definition,status,created_by,created_at) '
                               'VALUES (?,?,?,?,?,?,?,?)', (uuid4().hex, row['rule_id'], row['base_hash'],
                                digest(candidate), encoded(candidate), 'draft', principal.username, stamp()))
                    saved_count += inserted.rowcount
        return {'saved': saved_count}

    def proposals(self, principal):
        self.library.scope(principal)
        if principal.organizations is not None:
            return []
        builtins = self.builtins()
        with self.library.connect() as db:
            rows = db.execute('SELECT * FROM builtin_rule_csv ORDER BY created_at DESC, id LIMIT 100').fetchall()
        return [{**{key: row[key] for key in row.keys() if key != 'definition'},
                 'changes': diff(builtins[row['rule_key']], json.loads(row['definition']))
                 if row['rule_key'] in builtins and digest(builtins[row['rule_key']]) == row['base_hash'] else None}
                for row in rows]

    def transition(self, identifier, action, body, principal):
        self.library.scope(principal)
        require(principal.organizations is None, 'admin_required', 403)
        require(action in ('approve', 'apply'), 'action_invalid')
        require(isinstance(body, dict) and set(body) == {'content_hash'}, 'request_invalid')
        builtins = self.builtins()
        with self.library.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM builtin_rule_csv WHERE id=?', (identifier,)).fetchone()
            require(row, 'rule_missing', 404)
            rule = builtins.get(row['rule_key'])
            require(rule and digest(rule) == row['base_hash'] and
                    digest(json.loads(row['definition'])) == row['content_hash'] == body['content_hash'],
                    'rule_changed', 409)
            if action == 'approve':
                require(row['status'] == 'draft', 'draft_required', 409)
                db.execute("UPDATE builtin_rule_csv SET status='approved',approved_by=?,approved_at=? WHERE id=?",
                           (principal.username, stamp(), identifier))
            else:
                require(row['status'] == 'approved', 'approval_required', 409)
                db.execute("UPDATE builtin_rule_csv SET status='pending_deployment',requested_by=?,requested_at=? WHERE id=?",
                           (principal.username, stamp(), identifier))
        return {'status': 'approved' if action == 'approve' else 'pending_deployment'}

    def release(self, identifier, principal):
        self.library.scope(principal)
        require(principal.organizations is None, 'admin_required', 403)
        with self.library.connect() as db:
            row = db.execute("SELECT * FROM builtin_rule_csv WHERE id=? AND status='pending_deployment'",
                             (identifier,)).fetchone()
            require(row, 'rule_missing', 404)
            current = self.builtins().get(row['rule_key'])
            candidate = json.loads(row['definition'])
            require(current and digest(current) == row['base_hash'] and digest(candidate) == row['content_hash'],
                    'rule_changed', 409)
            return {'schema_version': 1, 'proposal_id': row['id'], 'rule_id': row['rule_key'],
                    'base_hash': row['base_hash'], 'content_hash': row['content_hash'],
                    'approved_by': row['approved_by'], 'approved_at': row['approved_at'],
                    'requested_by': row['requested_by'], 'requested_at': row['requested_at'],
                    'rule': candidate}
