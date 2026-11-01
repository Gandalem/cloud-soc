"""One-shot Elasticsearch configuration. Executed only by connect.py in Docker."""
import json
import os
from pathlib import Path
import time

from elasticsearch import Elasticsearch, NotFoundError
from cloud_soc.multicloud.storage import install

ROLE = 'cloud_soc_multicloud_dashboard_v1'
WRITER = {'cluster': [], 'indices': [{'names': ['soc-multicloud-*'], 'privileges': ['create_doc', 'auto_configure']}]}
READER = {'cluster': [], 'indices': [{'names': ['soc-multicloud-*'], 'privileges': ['read', 'view_index_metadata']}]}
OUT = Path('/output')


def save(name, value, uid=0):
    path = OUT / name
    if name=='writer-api-key':
        from cloud_soc.secret_store import write_new
        write_new(path,value,uid=uid)
        return
    tmp = OUT / ('.' + name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(tmp, uid, uid)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def same_grants(actual, expected):
    if actual.get('cluster', []) != expected['cluster']:
        return False
    if any(actual.get(k) for k in ('applications', 'run_as', 'remote_indices', 'remote_cluster', 'global')):
        return False
    entries = actual.get('indices', [])
    if len(entries) != 1:
        return False
    index = entries[0]
    return (index.get('names') == expected['indices'][0]['names']
            and sorted(index.get('privileges', [])) == sorted(expected['indices'][0]['privileges'])
            and not index.get('query') and not index.get('field_security')
            and not index.get('allow_restricted_indices', False))


def main():
    password = Path('/run/setup/elastic-password').read_text().strip()
    with Elasticsearch('https://elasticsearch:9200', ca_certs='/run/setup/ca.crt',
                       basic_auth=('elastic', password), request_timeout=30, max_retries=0) as es:
        users = es.security.get_user(username='cloud_soc_agent_monitor').body
        user = users.get('cloud_soc_agent_monitor')
        if not user or not user.get('enabled'):
            raise ValueError('enabled_native_monitor_user_required')
        manifest_path, key_path = OUT / 'writer.json', OUT / 'writer-api-key'
        if manifest_path.exists() != key_path.exists():
            raise ValueError('incomplete_writer_files_preserved_manual_recovery_required')
        try:
            role = es.security.get_role(name=ROLE).body[ROLE]
        except NotFoundError:
            role = None
        expected_role = {**READER, 'metadata': {'cloud_soc_multicloud': 1}}
        if role and (role.get('metadata') != expected_role['metadata'] or not same_grants(role, READER)):
            raise ValueError('dedicated_role_collision')
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            records = es.security.get_api_key(id=manifest['id']).body.get('api_keys', [])
            if len(records) != 1:
                raise ValueError('writer_key_missing')
            record = records[0]
            if record.get('invalidated') or record.get('expiration', 0) <= int(time.time()*1000):
                raise ValueError('writer_key_expired_or_invalidated_no_automatic_replacement')
            if (record.get('metadata') != {'cloud_soc_multicloud': 1}
                    or set(record.get('role_descriptors', {})) != {'writer'}
                    or not same_grants(record['role_descriptors']['writer'], WRITER)):
                raise ValueError('writer_key_scope_mismatch')
        backup = OUT / 'monitor-before.json'
        if not backup.exists():
            save(backup.name, json.dumps({'username': 'cloud_soc_agent_monitor', 'user': user}, indent=2))
        install(es)
        es.security.put_role(name=ROLE, **expected_role)
        roles = list(user['roles'])
        if ROLE not in roles:
            roles.append(ROLE)
            es.security.put_user(username='cloud_soc_agent_monitor', roles=roles,
                full_name=user.get('full_name'), email=user.get('email'),
                metadata=user.get('metadata', {}), enabled=user['enabled'])
        created = False
        if not manifest_path.exists():
            issued = es.security.create_api_key(name='cloud-soc-multicloud-writer', expiration='90d',
                role_descriptors={'writer': WRITER}, metadata={'cloud_soc_multicloud': 1}).body
            try:
                save('writer-api-key', issued['encoded'], 10001)
                save('writer.json', json.dumps({'id': issued['id'], 'expiration': issued['expiration']}, indent=2))
            except Exception:
                es.security.invalidate_api_key(ids=[issued['id']])
                raise
            created = True
        print(json.dumps({'configured': True, 'index_template': 'soc-multicloud-v1',
            'portal_reader': 'cloud_soc_agent_monitor', 'reader_role_added': ROLE,
            'writer_key_created': created, 'writer_key_expiration_days_on_creation': 90,
            'existing_passwords_changed': False, 'existing_keys_replaced': False,
            'collector_started': False, 'live_ingestion_verified': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'configured': False, 'error_type': type(exc).__name__,
                          'reason': str(exc) if isinstance(exc, ValueError) else 'elasticsearch_setup_failed',
                          'note': 'Prior successful additive steps may remain; no rollback or deletion performed.'}))
        raise SystemExit(1)
