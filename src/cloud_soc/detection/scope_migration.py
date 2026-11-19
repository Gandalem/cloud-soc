"""One bounded identity transition for the approved service-logon scope change."""
from copy import deepcopy
import json

from cloud_soc.detection.engine import (
    SERVICE_LOGON_SCOPE_RULES, event_fingerprint, rule_applies_to_event, rule_revision,
)


def previous_identity(payload):
    previous = deepcopy(payload)
    rules = previous['rules']
    versions = []
    for rule in rules:
        if rule['id'] in SERVICE_LOGON_SCOPE_RULES:
            engine = 'metadata-cardinality-v1' if rule['type'] == 'cardinality' else 'behavior-v1'
            versions.append(event_fingerprint({'engine': engine, 'rule': rule}))
        else:
            versions.append(rule_revision(rule))
    previous['versions' if 'versions' in previous else 'rule_versions'] = versions
    return event_fingerprint(previous)


def migrate(db, saved, payload, stamp, *, table='runtime'):
    if table == 'runtime':
        update = 'UPDATE runtime SET body=? WHERE id=1'
    elif table == 'review_state':
        update = 'UPDATE review_state SET body=? WHERE id=1'
    else:
        raise ValueError('Unsupported detector state table')
    identity = event_fingerprint(payload)
    if saved['identity'] == identity:
        return saved
    old_identity = previous_identity(payload)
    if (old_identity == identity or saved['identity'] != old_identity
            or saved.get('scope_identity') not in (None, identity)):
        raise ValueError('rule_or_scope_changed_requires_new_state')
    result = deepcopy(saved)
    for position, rule in enumerate(payload['rules']):
        if rule['id'] not in SERVICE_LOGON_SCOPE_RULES:
            continue
        groups = (result.get('groups', {}) if position == 0
                  else result.get('rule_groups', {}).get(rule['id'], {}))
        for group in groups.values():
            group['window'] = [event for event in group['window'] if rule_applies_to_event(event, rule)]
    # The original identity also lets the previous image read this database on rollback.
    # New code verifies the additional scope identity before using the same scan cursor.
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='input_scan'").fetchone():
        row = db.execute('SELECT body FROM input_scan WHERE id=1').fetchone()
        if row:
            meta = json.loads(row[0])
            if meta['identity'] != old_identity:
                raise ValueError('input_scan_scope_changed')
    db.execute('CREATE TABLE IF NOT EXISTS scope_migrations '
               '(identity TEXT PRIMARY KEY, previous_identity TEXT NOT NULL, applied_at TEXT NOT NULL)')
    db.execute('INSERT OR IGNORE INTO scope_migrations VALUES(?,?,?)', (identity, old_identity, stamp))
    result['scope_identity'] = identity
    db.execute(update, (json.dumps(result),))
    return result
