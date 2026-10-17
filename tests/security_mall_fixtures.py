"""Synthetic Mall events built through the existing 3-A normalizer."""
from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5
from cloud_soc.processing.contract import normalize, NORMALIZED

BASE = datetime(2026, 10, 1, tzinfo=timezone.utc)


def mall(number, seconds=None, *, outcome='failure', action='login', reason='not_owner',
         organization='mall-org', account='a' * 64, key='lab-v1', ip='192.0.2.10',
         service='security-mall', host='mall-host'):
    stamp = (BASE + timedelta(seconds=number if seconds is None else seconds)).isoformat().replace('+00:00', 'Z')
    audit = {'schema_version': 1, '@timestamp': stamp,
        'event_id': str(uuid5(NAMESPACE_URL, 'mall-fixture/' + action + '/' + str(number))),
        'service_name': service, 'event_action': action, 'event_outcome': outcome,
        'source_ip': ip, 'account_id': account, 'account_key_id': key}
    if action == 'order_view':
        audit.update(resource_type='order', authorization_reason=reason)
    source = {'@timestamp': stamp, 'organization': {'id': organization}, 'host': {'id': host},
        'labels': {'log_source': 'security_mall_audit'}, 'security_mall': {'audit': audit},
        'event': {'ingested': (BASE + timedelta(seconds=10)).isoformat()}}
    identifier, record, event = normalize({'_index': 'soc-host-raw-mall-fixture',
        '_id': audit['event_id'], '_source': source}, (BASE + timedelta(seconds=10)).isoformat())
    assert record['status'] == 'normalized'
    event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': identifier}
    return event
