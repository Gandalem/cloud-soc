"""Pure, bounded projections of native service logs; original bytes stay in AWS."""

from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import re

from cloud_soc.aws.cloudtrail import _object, _reject_constant, iso, safe, timestamp
from cloud_soc.privacy import REDACTED

SOURCE = 'aws_service_logs'
ADAPTER = 'aws_service_logs_v1'
VERSION = 'aws-service-logs-v1'
KINDS = {
    'route53_resolver': ('route53resolver', 'network', 'dns_query'),
    'securityhub': ('securityhub', 'intrusion_detection', 'security_finding'),
    'rds_general': ('rds', 'database', 'mysql_general_log'),
    'rds_error': ('rds', 'database', 'mysql_error_log'),
    'cloudfront': ('cloudfront', 'web', 'http_access'),
    'network_firewall_alert': ('network-firewall', 'intrusion_detection', 'firewall_alert'),
    'network_firewall_flow': ('network-firewall', 'network', 'firewall_flow'),
}
STRINGS = ('kind', 'resource_id', 'log_group', 'log_stream', 'event_id', 'original_sha256',
           'time_basis', 'cloudwatch_at', 'cloudwatch_ingested_at', 'query_name', 'query_type',
           'rcode', 'finding_id', 'finding_region', 'severity', 'compliance', 'workflow',
           'record_state', 'command', 'statement_type', 'error_code', 'error_level',
           'request_id', 'result_type', 'firewall_action', 'flow_id')
NUMBERS = ('signature_id', 'signature_severity', 'line_count')
READ_FIELDS = tuple('aws.service_logs.' + key for key in ('schema', *STRINGS, *NUMBERS, 'resource_ids'))


def required(value):
    result = safe(value)
    if result in (None, REDACTED):
        raise ValueError('invalid_service_metadata')
    return result


def integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('invalid_service_number')
    return value


def port(value):
    # Native Resolver logs observed in AWS encode srcport as a decimal string.
    if isinstance(value, str) and re.fullmatch(r'[0-9]{1,5}', value):
        value = int(value)
    return integer(value, 0, 65535)


def ip(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('invalid_service_address')
    return str(ip_address(value))


def load(message):
    value = json.loads(message, object_pairs_hook=_object, parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError('invalid_service_json')
    return value


def epoch_ms(value):
    integer(value, 0, 253402300799999)
    return datetime.fromtimestamp(value / 1000, timezone.utc)


def select_enum(value, choices):
    if value not in choices:
        raise ValueError('invalid_service_enum')
    return value


def project(envelope, *, account, organization, region, group, kind, resource_id):
    """Return all child documents; no raw strings/SQL/HTTP headers are persisted."""
    try:
        return _project(envelope, account=account, organization=organization, region=region,
                        group=group, kind=kind, resource_id=resource_id)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError, RecursionError, OSError):
        raise ValueError('invalid_service_log_event') from None


def _project(envelope, *, account, organization, region, group, kind, resource_id):
    message = envelope['message']
    if not isinstance(message, str) or not message or len(message.encode('utf-8')) > 1024 * 1024:
        raise ValueError()
    event_id, stream = required(envelope['eventId']), required(envelope['logStreamName'])
    cw_time = epoch_ms(envelope['timestamp'])
    cw_ingested = epoch_ms(envelope['ingestionTime'])
    service, category, action = KINDS[kind]
    base = {'schema': 1, 'kind': kind, 'resource_id': resource_id, 'log_group': group,
            'log_stream': stream, 'event_id': event_id,
            'original_sha256': hashlib.sha256(message.encode('utf-8')).hexdigest(),
            'cloudwatch_at': iso(cw_time), 'cloudwatch_ingested_at': iso(cw_ingested),
            'time_basis': 'native_event_timestamp'}
    occurred, outcome, extra, records = cw_time, 'unknown', {}, []
    if kind.startswith('rds_'):
        base['line_count'] = len(message.splitlines())
        native_time = re.match(r'^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d))', message)
        if native_time:
            occurred = timestamp(native_time[1])
        else:
            base['time_basis'] = 'cloudwatch_event_timestamp_not_statement_time'
        if kind == 'rds_general':
            command = re.search(r'\b\d+\s+(Connect|Quit|Query|Prepare|Execute|Close stmt|Init DB|Ping|Change user)\b', message)
            if command:
                base['command'] = command[1]
                verb = re.match(r'\s+(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|GRANT|REVOKE|SET|SHOW|USE|COMMIT|ROLLBACK)\b', message[command.end():], re.I)
                if command[1] in ('Query', 'Prepare', 'Execute') and verb:
                    base['statement_type'] = verb[1].upper()
        else:
            level = re.search(r'\[(System|Warning|ERROR|Note)\]', message)
            code = re.search(r'\bMY-\d{6}\b', message)
            if level:
                base['error_level'] = level[1]
            if code:
                base['error_code'] = code[0]
        # A query/error log record does not establish query success or an attack.
    else:
        value = load(message)
        if kind == 'route53_resolver':
            if value['account_id'] != account or value['region'] != region or value.get('vpc_id', value.get('resource_id')) != resource_id:
                raise ValueError()
            if not re.fullmatch(r'1\.\d+', value['version']):
                raise ValueError()
            occurred = timestamp(value['query_timestamp'])
            base.update(query_name=required(value['query_name']), query_type=required(value['query_type']), rcode=required(value['rcode']))
            outcome = 'success' if base['rcode'] == 'NOERROR' else 'failure'
            extra = {'source': {'ip': ip(value['srcaddr'])}, 'network': {'transport': select_enum(value['transport'].lower(), ('tcp', 'udp'))}}
            extra['source']['port'] = port(value['srcport'])
            extra['dns'] = {'question': {'name': base['query_name'], 'type': base['query_type']}, 'response_code': base['rcode']}
        elif kind == 'securityhub':
            if (value['source'] != 'aws.securityhub' or value['detail-type'] != 'Security Hub Findings - Imported'
                    or value['account'] != account or value['region'] != region):
                raise ValueError()
            timestamp(value['time'])
            findings = value['detail']['findings']
            if not isinstance(findings, list) or not 1 <= len(findings) <= 100:
                raise ValueError()
            seen = set()
            for finding in findings:
                if finding['AwsAccountId'] != account:
                    raise ValueError()
                child = {**base, 'finding_id': required(finding['Id']),
                         'finding_region': required(finding.get('Region', region)),
                         'severity': select_enum(finding['Severity']['Label'], ('INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
                         'record_state': select_enum(finding['RecordState'], ('ACTIVE', 'ARCHIVED')),
                         'workflow': select_enum(finding['Workflow']['Status'], ('NEW', 'NOTIFIED', 'RESOLVED', 'SUPPRESSED'))}
                if child['finding_id'] in seen:
                    raise ValueError()
                seen.add(child['finding_id'])
                if 'Compliance' in finding and 'Status' in finding['Compliance']:
                    child['compliance'] = select_enum(finding['Compliance']['Status'], ('PASSED', 'WARNING', 'FAILED', 'NOT_AVAILABLE'))
                resources = finding.get('Resources', [])
                if not isinstance(resources, list) or len(resources) > 32:
                    raise ValueError()
                child['resource_ids'] = [required(r['Id']) for r in resources]
                records.append((timestamp(finding.get('UpdatedAt', value['time'])), 'unknown', {}, child))
        elif kind == 'cloudfront':
            occurred = timestamp(value['date'] + 'T' + value['time'] + 'Z')
            status = value['sc-status']
            status = int(status) if isinstance(status, str) and re.fullmatch(r'\d{3}', status) else status
            integer(status, 0, 599)
            method = select_enum(value['cs-method'], ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE'))
            base.update(request_id=required(value['x-edge-request-id']), result_type=required(value['x-edge-result-type']))
            outcome = 'failure' if status >= 400 else 'success' if 200 <= status < 400 else 'unknown'
            extra = {'source': {'ip': ip(value['c-ip'])}, 'http': {'request': {'method': method, 'id': base['request_id']}, 'response': {'status_code': status}}}
        elif kind.startswith('network_firewall_'):
            if value['firewall_name'] != resource_id or not value['availability_zone'].startswith(region):
                raise ValueError()
            event = value['event']
            event_type = 'alert' if kind.endswith('alert') else 'netflow'
            if event['event_type'] != event_type:
                raise ValueError()
            occurred = timestamp(event['timestamp'])
            base['flow_id'] = str(integer(event['flow_id'], 0, 2**64 - 1))
            extra = {'source': {'ip': ip(event['src_ip'])}, 'destination': {'ip': ip(event['dest_ip'])},
                     'network': {'transport': select_enum(event['proto'].lower(), ('tcp', 'udp', 'icmp', 'icmpv6'))}}
            for endpoint, key in (('source', 'src_port'), ('destination', 'dest_port')):
                if key in event:
                    extra[endpoint]['port'] = integer(event[key], 0, 65535)
            if event_type == 'alert':
                alert = event['alert']
                base.update(signature_id=integer(alert['signature_id'], 0, 2**32 - 1),
                            signature_severity=integer(alert['severity'], 1, 255),
                            firewall_action=select_enum(alert['action'], ('allowed', 'blocked')))
            else:
                netflow = event['netflow']
                extra['network'].update(bytes=integer(netflow['bytes'], 0, 2**63 - 1), packets=integer(netflow['pkts'], 0, 2**63 - 1))
    if kind != 'securityhub':
        records.append((occurred, outcome, extra, base))
    documents = []
    for occurred, outcome, extra, metadata in records:
        identity = [SOURCE, organization, account, region, group, stream, event_id, metadata.get('finding_id')]
        identifier = hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()
        document = {'@timestamp': iso(occurred), 'organization': {'id': organization},
                    'event': {'id': identifier, 'kind': 'event', 'dataset': 'aws.' + kind, 'category': [category], 'action': action, 'outcome': outcome},
                    'cloud': {'provider': 'aws', 'account': {'id': account}, 'region': region, 'service': {'name': service}},
                    'service': {'name': service}, 'agent': {'type': 'aws-cloudwatch', 'id': 'aws-' + account + '-' + region},
                    'labels': {'log_source': SOURCE, 'privacy_policy': VERSION}, 'aws': {'service_logs': metadata}, **extra}
        documents.append(('soc-cloud-aws-' + occurred.strftime('%Y.%m.%d'), identifier, document))
    return documents


def detail(source):
    """Interpret only our selected projection, never any original message."""
    try:
        metadata = source['aws']['service_logs']
        kind = metadata['kind']
        if type(metadata['schema']) is not int or metadata['schema'] != 1 or kind not in KINDS:
            raise ValueError()
        if source['cloud']['provider'] != 'aws' or source['event']['dataset'] != 'aws.' + kind:
            raise ValueError()
        if (not re.fullmatch(r'[0-9]{12}', source['cloud']['account']['id'])
                or not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]', source['cloud']['region'])
                or not re.fullmatch(r'[0-9a-f]{64}', source['event']['id'])
                or source['cloud']['service']['name'] != KINDS[kind][0]):
            raise ValueError()
        fields = {key: required(value) for key, value in metadata.items() if key in STRINGS}
        for key in ('resource_id', 'log_group', 'log_stream', 'event_id', 'original_sha256', 'time_basis', 'cloudwatch_at', 'cloudwatch_ingested_at'):
            required(fields[key])
        if not re.fullmatch(r'[0-9a-f]{64}', fields['original_sha256']):
            raise ValueError()
        for key in ('cloudwatch_at', 'cloudwatch_ingested_at'):
            timestamp(fields[key])
        required_by_kind = {'route53_resolver': ('query_name', 'query_type', 'rcode'),
                            'securityhub': ('finding_id', 'severity', 'workflow', 'record_state'),
                            'cloudfront': ('request_id', 'result_type'),
                            'network_firewall_alert': ('firewall_action', 'flow_id'),
                            'network_firewall_flow': ('flow_id',)}
        for key in required_by_kind.get(kind, ()):
            required(fields[key])
        for key in NUMBERS:
            if key in metadata:
                fields[key] = integer(metadata[key], 0, 2**32 - 1)
        if 'resource_ids' in metadata:
            ids = metadata['resource_ids']
            if not isinstance(ids, list) or len(ids) > 32:
                raise ValueError()
            fields['resource_ids'] = [required(v) for v in ids]
        fields.update(category=KINDS[kind][1], action=KINDS[kind][2], outcome=source['event']['outcome'],
                      service_name=KINDS[kind][0])
        if fields['outcome'] not in ('success', 'failure', 'unknown'):
            raise ValueError()
        for endpoint in ('source', 'destination'):
            if endpoint in source and 'ip' in source[endpoint]:
                fields[endpoint + '_ip'] = ip(source[endpoint]['ip'])
                if 'port' in source[endpoint]:
                    fields[endpoint + '_port'] = integer(source[endpoint]['port'], 0, 65535)
        if kind == 'cloudfront':
            fields['http_status'] = integer(source['http']['response']['status_code'], 0, 599)
            fields['http_method'] = required(source['http']['request']['method'])
        network = source.get('network', {})
        if 'transport' in network:
            fields['transport'] = select_enum(network['transport'], ('tcp', 'udp', 'icmp', 'icmpv6'))
        for key in ('bytes', 'packets'):
            if key in network:
                fields['network_' + key] = integer(network[key], 0, 2**63 - 1)
        return fields
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError('invalid_service_projection') from None
