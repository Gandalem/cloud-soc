"""Read-only prerequisite differences; an unsafe scope fails before worker shutdown."""
from datetime import datetime, timezone
import json
from pathlib import Path

from cloud_soc.deployment.contract import WORKERS, digest, validate_rules
from cloud_soc.deployment.migrations import additive_grants, key_id, state_compatible


def inspect(client, value, contract, keys, states, notification_key=None):
    from cloud_soc.processing.setup import ROLE
    from cloud_soc.detection.setup import detector_role
    from cloud_soc.portal.status_setup import reader_role
    validate_rules(value)
    result = {'role_additions': {}, 'key_additions': {}, 'key_identifiers': {}, 'state_identity_verified': [], 'issues': []}
    security = {}
    for name, required in [('cloud_soc_agent_monitor', reader_role()), ('cloud_soc_normalizer', ROLE)]:
        old = client.security.get_role(name=name).body.get(name, {'cluster': [], 'indices': []})
        updated = additive_grants(old, required)
        security[name] = old
        result['role_additions'][name] = updated['indices'][len(old.get('indices', [])):]
    for name, encoded in keys.items():
        identifier = key_id(encoded)
        found = client.security.get_api_key(id=identifier).body['api_keys']
        if len(found) != 1 or found[0]['invalidated'] or (found[0].get('expiration') is not None and found[0]['expiration'] <= int(datetime.now(timezone.utc).timestamp()*1000)):
            raise ValueError('Existing key invalid; renewal must be explicit')
        record = found[0];security[identifier] = record
        grants = {'cluster': [], 'indices': []}
        for role in record.get('role_descriptors', {}).values():
            grants['indices'] += role.get('indices', []);grants['cluster'] += role.get('cluster', [])
        if not record.get('role_descriptors'):
            raise ValueError('Unbounded key requires explicit adoption')
        required = ROLE if name.startswith('normalizer') else detector_role(early=True)
        merged = additive_grants(grants, required)
        result['key_additions'][name] = merged['indices'][len(grants['indices']):]
        result['key_identifiers'][name] = identifier
    for name, path in states.items():
        state_compatible(contract['workers'][name], Path(path))
        result['state_identity_verified'].append(name)
    from cloud_soc.deployment.migrations import validate_notification_role
    result['notification_key'] = 'will_create_read_only_key'
    if notification_key:
        found = client.security.get_api_key(id=key_id(notification_key)).body['api_keys']
        if (len(found) != 1 or found[0]['invalidated']
                or found[0].get('expiration', float('inf')) <= datetime.now(timezone.utc).timestamp()*1000):
            raise ValueError('Unexpected notification key or privileges')
        validate_notification_role(found[0].get('role_descriptors'))
        security['notification_key'] = found[0]
        result['notification_key'] = 'existing_read_only_key_verified'
    # Required namespaces and mappings are reviewed without creating anything.
    names = ['soc-normalized-v1', 'soc-processing-v1', 'soc-pipeline-status', 'soc-detection-runs-v1',
             'soc-detection-exclusions-v1', 'soc-alert-notices-v1', 'security-alerts']
    result['missing_indices'] = []
    mappings = {}
    for name in names:
        if not client.indices.exists(index=name):
            result['missing_indices'].append(name)
        else:
            found = client.indices.get_mapping(index=name)
            if set(found) != {name}:
                raise ValueError('Concrete index expected, no alias adoption')
            mappings[name] = found[name]['mappings']
            if name not in ('soc-alert-notices-v1', 'security-alerts') and mappings[name].get('_meta', {}).get('contract') != name:
                raise ValueError('Existing mapping requires explicit migration')
    result['security_sha256'] = digest(security)
    result['mapping_sha256'] = digest(mappings)
    result['required_workers'] = list(WORKERS)
    return result


def main():
    import sys
    from elasticsearch import Elasticsearch
    data = json.load(sys.stdin)
    with Elasticsearch('https://elasticsearch:9200', basic_auth=('elastic', data['password']),
                       ca_certs='/run/certs/ca.crt', request_timeout=30, max_retries=0) as c:
        print(json.dumps(inspect(c, data['policy'], data['contract'], data['keys'], data['states'], data.get('notification_key'))))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('runtime_preflight_failed; no server mutation; protected details omitted') from None
