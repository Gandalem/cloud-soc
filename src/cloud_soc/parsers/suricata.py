"""Bounded EVE metadata adapter. Raw bodies and claims of identity stay untrusted."""
import hashlib
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address

VERSION = 'suricata-eve-v1'
ADAPTER = 'suricata_eve_v1'


def parse_suricata(message):
    if not isinstance(message, str) or len(message.encode('utf-8')) > 262144:
        raise ValueError('invalid_eve')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_key')
            result[key] = value
        return result
    value = json.loads(message, object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_number')))
    if not isinstance(value, dict):
        raise ValueError('invalid_eve')
    kind = value.get('event_type')
    if not isinstance(kind, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', kind):
        raise ValueError('invalid_type')
    stamp = value.get('timestamp')
    if not isinstance(stamp, str) or len(stamp) > 64:
        raise ValueError('invalid_time')
    stamp = re.sub(r'([+-][0-9]{2})([0-9]{2})$', r'\1:\2', stamp)
    occurred = datetime.fromisoformat(stamp.replace('Z', '+00:00'))
    if occurred.tzinfo is None:
        raise ValueError('timezone_required')
    result = {'occurred': occurred.astimezone(timezone.utc), 'event_type': kind}
    for raw, name in (('src_ip', 'source'), ('dest_ip', 'destination')):
        if raw in value:
            item = value[raw]
            if not isinstance(item, str) or '%' in item:
                raise ValueError('invalid_ip')
            result[name] = {'ip': str(ip_address(item))}
        port = value.get('src_port' if name == 'source' else 'dest_port')
        if port is not None:
            if name not in result or type(port) is not int or not 0 <= port <= 65535:
                raise ValueError('invalid_port')
            result[name]['port'] = port
    proto = value.get('proto')
    if proto is not None:
        if not isinstance(proto, str) or proto.upper() not in {'TCP', 'UDP', 'ICMP', 'ICMPV6', 'SCTP'}:
            raise ValueError('invalid_transport')
        result['transport'] = proto.lower()
    if kind == 'alert':
        alert = value.get('alert')
        if not isinstance(alert, dict) or 'source' not in result or 'destination' not in result:
            raise ValueError('invalid_alert')
        sid = alert.get('signature_id')
        if type(sid) is not int or not 0 <= sid <= 4294967295:
            raise ValueError('invalid_signature_id')
        result['signature_id'] = sid
        severity = alert.get('severity')
        if severity is not None:
            if type(severity) is not int or not 1 <= severity <= 3:
                raise ValueError('invalid_severity')
            result['severity'] = severity
    return result


def normalize_suricata(source, reference, processed_at, received, organization):
    from cloud_soc.portal.agent_status import iso
    from cloud_soc.portal.log_contract import field
    from cloud_soc.portal.security_detail import text
    from cloud_soc.privacy import REDACTED
    identifier = hashlib.sha256(json.dumps([VERSION, reference], sort_keys=True).encode()).hexdigest()
    record = {'@timestamp': processed_at, 'version': VERSION, 'adapter': ADAPTER,
              'status': 'invalid', 'reason': 'suricata_metadata_invalid', 'raw': reference,
              'event': {'ingested': iso(received)}}
    try:
        data = parse_suricata(source.get('message'))
    except (ValueError, TypeError, OverflowError, RecursionError):
        return identifier, record, None
    host_id = field(source, 'host.id')
    if (not isinstance(host_id, str) or not 0 < len(host_id) <= 128
            or host_id.strip() != host_id or text(host_id) in (None, REDACTED)
            or text(host_id) != host_id):
        record['reason'] = 'suricata_host_invalid'
        return identifier, record, None
    alert = data['event_type'] == 'alert'
    detail = {'adapter': ADAPTER, 'status': 'recognized',
              'fields': {'category': 'intrusion_detection' if alert else 'network',
                         'action': data['event_type'], 'outcome': 'unknown'},
              'missing': [], 'limitations': ['metadata_only', 'sensor_alert_not_attack_confirmation',
                                              'payload_and_signature_text_excluded']}
    event = {'@timestamp': iso(data['occurred']), 'organization': {'id': organization},
             'host': {'id': host_id}, 'observer': {'type': 'ids', 'vendor': 'OISF', 'product': 'Suricata'},
             'event': {'kind': 'alert' if alert else 'event', 'dataset': 'suricata.eve',
                       'category': [detail['fields']['category']], 'action': data['event_type'],
                       'outcome': 'unknown', 'ingested': iso(received)},
             'cloud_soc': {'normalized_at': processed_at, 'normalizer_version': VERSION,
                           'parse_status': 'recognized', 'detail': detail,
                           'provenance': {'schema_version': 1, 'raw': reference,
                                          'time': {'basis': 'suricata_timestamp', 'year_inferred': False}}}}
    for name in ('source', 'destination'):
        if name in data:
            event[name] = data[name]
    if 'transport' in data:
        event['network'] = {'transport': data['transport']}
    if alert:
        event['rule'] = {'id': str(data['signature_id'])}
        event['event']['code'] = str(data['signature_id'])
        if 'severity' in data:
            event['suricata'] = {'eve': {'alert': {'severity': data['severity']}}}
    record.update(status='normalized', reason='recognized',
                  normalized={'index': 'soc-normalized-v1', 'id': identifier})
    return identifier, record, event
