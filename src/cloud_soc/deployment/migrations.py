"""Additive versioned prerequisites; never replace an existing password or key."""
import base64
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import fnmatch
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from cloud_soc.deployment.contract import WORKERS, digest, stamp, validate_rules


def atomic_json(path, value, *, uid=None):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Unsafe runtime metadata path')
    fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.next', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, sort_keys=True);stream.flush();os.fsync(stream.fileno())
        if uid is not None and os.name == 'posix':
            os.chown(temporary, uid, uid)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def additive_grants(current, required):
    """Preserve grants and refuse extending restricted data/field scopes."""
    allowed = {'cluster', 'indices', 'applications', 'run_as', 'metadata', 'description', 'global',
               'remote_indices', 'remote_cluster', 'restriction', 'transient_metadata'}
    if not isinstance(current, dict) or set(current) - allowed:
        raise ValueError('Unsupported role; manual review required')
    result = {k: deepcopy(v) for k, v in current.items() if k != 'transient_metadata'}
    entries = result.setdefault('indices', [])
    for grant in required.get('indices', []):
        missing = []
        for name in grant['names']:
            matched = [e for e in entries if any(fnmatch.fnmatchcase(name, pattern) for pattern in e['names'])]
            if any('query' in e or 'field_security' in e for e in matched):
                raise ValueError('Restricted index scope cannot be expanded automatically')
            if not all(any(p in e['privileges'] or 'all' in e['privileges'] for e in matched) for p in grant['privileges']):
                missing.append(name)
        if missing:
            entries.append({'names': missing, 'privileges': list(grant['privileges'])})
    cluster = result.setdefault('cluster', [])
    for p in required.get('cluster', []):
        if p not in cluster and 'all' not in cluster:
            cluster.append(p)
    return result


def key_id(encoded):
    try:
        value = base64.b64decode(encoded, validate=True).decode()
        identifier, secret = value.split(':', 1)
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', identifier) or not secret:
            raise ValueError()
        return identifier
    except (ValueError, UnicodeError):
        raise ValueError('Invalid protected API key; no replacement issued') from None


def state_compatible(row, path):
    """Read-only validation of scope identity before a copied database is used."""
    if not path.exists():
        return
    from cloud_soc.detection.worker import approved_rules
    from cloud_soc.detection.engine import event_fingerprint, rule_revision
    from cloud_soc.processing.contract import NORMALIZED
    o = row['options']
    with closing(sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True)) as db:
        if db.execute('pragma integrity_check').fetchall() != [('ok',)]:
            raise ValueError('State integrity failed')
        if row['module'] == 'cloud_soc.processing':
            start = db.execute('select initial_start from config where id=1').fetchone()
            if start and stamp(start[0]) != stamp(o['--start']):
                raise ValueError('Normalizer initial start changed')
            ssh = db.execute("select start from adapter_config where name='linux_ssh_v2'").fetchone()
            if ssh and ('--linux-ssh-v2-start' not in o or stamp(ssh[0]) != stamp(o['--linux-ssh-v2-start'])):
                raise ValueError('SSH adapter floor changed')
            return
        selection = {'rule_ids': o['--rules'].split(',')} if '--rules' in o else (
            {'additional_rule_ids': o['--additional-rules'].split(',')} if '--additional-rules' in o else {})
        rules = approved_rules(**selection)
        if '--retrospective' in o:
            expected = event_fingerprint({'contract': 'retrospective-v1', 'rules': rules,
                'versions': [rule_revision(r) for r in rules], 'start': stamp(o['--start']).isoformat(),
                'source': o['--es-url'], 'lateness': int(o.get('--lateness-seconds', 900)), 'index': NORMALIZED})
        else:
            expected = event_fingerprint({'rules': rules, 'start': stamp(o['--start']).isoformat(),
                'lateness': int(o.get('--lateness-seconds', 900)), 'index': NORMALIZED, 'source': o['--es-url'],
                'legacy_exclusion': bool(o.get('--accept-legacy-exclusion')), 'runtime_contract': 2,
                'rule_versions': [rule_revision(r) for r in rules]})
        query = 'select body from review_state where id=1' if '--retrospective' in o else 'select body from runtime where id=1'
        saved = db.execute(query).fetchone()
        if saved and json.loads(saved[0])['identity'] != expected:
            raise ValueError('State identity mismatch; database was not reset')


def validate_notification_role(descriptors):
    """Accept ES's empty canonical defaults without accepting any extra authority or restriction."""
    from cloud_soc.notifications.worker import READ_ROLE
    if not isinstance(descriptors, dict) or set(descriptors) != {'cloud_soc_notifications'}:
        raise ValueError('Unexpected notification role scope')
    role = descriptors['cloud_soc_notifications']
    allowed = {'cluster', 'indices', 'applications', 'run_as', 'metadata', 'transient_metadata'}
    if (not isinstance(role, dict) or set(role) - allowed or role.get('cluster', []) != []
            or role.get('applications', []) != [] or role.get('run_as', []) != [] or role.get('metadata', {}) != {}
            or role.get('transient_metadata', {}) not in ({}, {'enabled': True})):
        raise ValueError('Unexpected notification role authority')
    entries = role.get('indices')
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        raise ValueError('Unexpected notification index scope')
    grant = entries[0];expected = READ_ROLE['indices'][0]
    if (set(grant) - {'names', 'privileges', 'allow_restricted_indices'}
            or grant.get('allow_restricted_indices', False) is not False
            or not isinstance(grant.get('names'), list) or not isinstance(grant.get('privileges'), list)
            or sorted(grant['names']) != sorted(expected['names']) or sorted(grant['privileges']) != sorted(expected['privileges'])):
        raise ValueError('Unexpected notification index privileges')


def notification_prerequisites(client, directory, *, key_client=None, notification_directory=None):
    from cloud_soc.notifications.worker import READ_ROLE
    from cloud_soc.notifications.store import SlackStore, private
    key = Path(directory) / 'keys/slack-notifier.key'
    created = None
    if key.exists():
        private(key)
        encoded = key.read_text().strip()
        found = client.security.get_api_key(id=key_id(encoded)).body['api_keys']
        if (len(found) != 1 or found[0]['invalidated']
                or found[0].get('expiration', float('inf')) <= datetime.now(timezone.utc).timestamp()*1000):
            raise ValueError('Notification key is invalid or has unexpected grants; no rotation performed')
        validate_notification_role(found[0].get('role_descriptors'))
    else:
        result = client.security.create_api_key(name='cloud-soc-notifications-v2', expiration='90d',
            role_descriptors={'cloud_soc_notifications': READ_ROLE}).body
        created = result['id'];encoded = result['encoded']
    try:
        if not key.exists():
            fd = os.open(key, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as stream:
                stream.write(encoded+'\n');stream.flush();os.fsync(stream.fileno())
            if os.name == 'posix':
                os.chown(key, 1000, 1000)
        if key_client:
            with key_client(encoded) as scoped:
                if not scoped.security.has_privileges(body={'cluster': [], 'index': READ_ROLE['indices']}).body['has_all_requested']:
                    raise ValueError('Notification effective read privileges missing')
        if notification_directory is not None:
            folder = Path(notification_directory)
            if folder.is_symlink():
                raise ValueError('Unsafe notification state')
            # Docker may create this new bind directory as root:0755. Existing state must already be private.
            if not (folder / 'slack.sqlite').exists():
                folder.mkdir(mode=0o700, parents=True, exist_ok=True);folder.chmod(0o700)
            SlackStore(folder).status()
            if os.name == 'posix':
                for path in [folder, *folder.iterdir()]:
                    private(path, directory=path.is_dir());os.chown(path, 1000, 1000)
    except Exception:
        if created and not key.exists():
            client.security.invalidate_api_key(ids=[created])
        raise


def prerequisites(client, value, contract, directory, existing_keys, *, key_client=None, notification_directory=None):
    """Idempotently reconcile mappings, bounded roles and existing key descriptors."""
    from cloud_soc.processing.setup import prepare, ROLE
    from cloud_soc.detection.setup import prepare as detection_prepare, prepare_early, detector_role
    from cloud_soc.portal.status_setup import reader_role
    validate_rules(value)
    directory = Path(directory);directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger_path = directory / 'migrations.json'
    ledger = json.loads(ledger_path.read_text()) if ledger_path.exists() else {'version': 0, 'migrations': {}}
    if ledger['version'] > value['version'] or set(ledger['migrations']) - set(value['migrations']):
        raise ValueError('Future migration ledger; downgrade refused')
    for name, row in contract['workers'].items():
        state_compatible(row, directory / 'state' / name / row['state_file'])
    backup = directory / 'security-before.json'
    if not backup.exists():
        roles = client.security.get_role(name='cloud_soc_agent_monitor,cloud_soc_normalizer').body
        atomic_json(backup, {'roles': roles})
    step = value['migrations'][0]
    ledger['migrations'][step] = {'state': 'applying', 'policy_sha256': digest(value)}
    atomic_json(ledger_path, ledger)
    try:
        prepare(client, update_role=False);detection_prepare(client);prepare_early(client)
        for name, role in [('cloud_soc_agent_monitor', reader_role()), ('cloud_soc_normalizer', ROLE)]:
            response = client.security.get_role(name=name).body
            old = response.get(name, {'cluster': [], 'indices': []})
            updated = additive_grants(old, role)
            if updated != {k: v for k, v in old.items() if k != 'transient_metadata'}:
                client.security.put_role(name=name, body=updated)
        keys = directory / 'keys';keys.mkdir(mode=0o700, exist_ok=True)
        cache = {}
        for name in WORKERS:
            p = keys / (name + '.key')
            if p.is_symlink():
                raise ValueError('Unsafe API key file')
            normalizer = name.startswith('normalizer')
            kind = 'normalizer' if normalizer else 'detector'
            encoded = p.read_text().strip() if p.exists() else existing_keys.get(name, cache.get(kind))
            required = ROLE if normalizer else detector_role(early=True)
            created = None
            if encoded:
                identifier = key_id(encoded)
                found = client.security.get_api_key(id=identifier).body['api_keys']
                if len(found) != 1 or found[0]['invalidated'] or (found[0].get('expiration') is not None and found[0]['expiration'] <= int(datetime.now(timezone.utc).timestamp() * 1000)):
                    raise ValueError('Existing worker key expired/revoked; explicit renewal required')
                record = found[0];descriptors = deepcopy(record.get('role_descriptors', {}))
                if not descriptors:
                    raise ValueError('Inherited/unbounded API key cannot be silently adopted')
                flattened = {'cluster': [], 'indices': []}
                for descriptor in descriptors.values():
                    flattened['indices'] += descriptor.get('indices', [])
                    flattened['cluster'] += descriptor.get('cluster', [])
                merged = additive_grants(flattened, required)
                extra = merged['indices'][len(flattened['indices']):]
                key_backup = directory / ('key-before-' + identifier + '.json')
                if not key_backup.exists():
                    atomic_json(key_backup, record)
                if extra:
                    if 'cloud_soc_runtime' in descriptors:
                        raise ValueError('Unexpected runtime key descriptor drift')
                    descriptors['cloud_soc_runtime'] = {'cluster': [], 'indices': extra}
                    client.security.update_api_key(id=identifier, role_descriptors=descriptors)
            else:
                result = client.security.create_api_key(name='cloud-soc-runtime-v1-' + kind,
                    expiration='90d', role_descriptors={'cloud_soc_runtime': required}).body
                created = result['id'];encoded = result['encoded']
            try:
                if not p.exists():
                    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'w') as stream:
                        stream.write(encoded + '\n');stream.flush();os.fsync(stream.fileno())
                    if os.name == 'posix':
                        os.chown(p, 1000, 1000)
                if key_client:
                    with key_client(encoded) as scoped:
                        requested = {'cluster': [], 'index': required['indices']}
                        if not scoped.security.has_privileges(body=requested).body['has_all_requested']:
                            raise ValueError('Effective worker privileges missing (limited_by or ownership)')
            except Exception:
                if created:
                    client.security.invalidate_api_key(ids=[created])
                raise
            cache[kind] = encoded
        ledger['migrations'][step]['state'] = 'applied'
        ledger['migrations'][value['migrations'][1]] = {'state': 'applied', 'policy_sha256': digest(value)}
        if value['version'] == 2:
            step = value['migrations'][2]
            ledger['migrations'][step] = {'state': 'applying', 'policy_sha256': digest(value)}
            atomic_json(ledger_path, ledger)
            notification_prerequisites(client, directory, key_client=key_client, notification_directory=notification_directory)
            ledger['migrations'][step]['state'] = 'applied'
        ledger['version'] = value['version']
        atomic_json(ledger_path, ledger)
        return {'version': value['version'], 'migrations': list(value['migrations']), 'worker_keys': len(WORKERS), 'existing_keys_replaced': False}
    except Exception as error:
        ledger['migrations'][step]['state'] = 'failed'
        ledger['migrations'][step]['error_type'] = type(error).__name__
        atomic_json(ledger_path, ledger)
        raise


def main():
    import sys
    from elasticsearch import Elasticsearch
    data = json.load(sys.stdin)
    with Elasticsearch('https://elasticsearch:9200', basic_auth=('elastic', data['password']),
                       ca_certs='/run/certs/ca.crt', request_timeout=60, max_retries=0) as client:
        def scoped(encoded):
            return Elasticsearch('https://elasticsearch:9200', api_key=encoded, ca_certs='/run/certs/ca.crt', request_timeout=30)
        print(json.dumps(prerequisites(client, data['policy'], data['contract'], '/deployment', data['existing_keys'], key_client=scoped,
                                      notification_directory='/notifications')))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('runtime_migration_failed; protected ledger retained; credentials omitted') from None
