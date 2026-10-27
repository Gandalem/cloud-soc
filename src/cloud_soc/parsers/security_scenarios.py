"""Allowlisted metadata from explicitly configured security audit exporters.

Exporters supply structured observations, never arbitrary native-log text.
Organization and host identity belong to the collector envelope, not the payload.
"""
from ipaddress import ip_address

from cloud_soc.portal.log_contract import field
from cloud_soc.portal.privacy import display, REDACTED

ADAPTER = 'security_scenarios_v1'
SOURCE = 'security_scenario'
VERSION = 'security-scenarios-v1'
# kind: category, permitted actions, mandatory metadata, Korean label
SCENARIOS = {
    'server_file': ('file', ('modified', 'deleted', 'permissions_changed'),
                    ('object_path', 'actor', 'critical_asset'), '중요 파일 변경'),
    'server_persistence': ('configuration', ('created', 'modified'),
                           ('object_name', 'object_type', 'actor'), '서비스·예약 작업 변경'),
    'server_defense': ('configuration', ('stopped', 'disabled', 'policy_changed'),
                       ('object_name', 'actor'), '보안 기능·정책 변경'),
    'app_role': ('iam', ('granted', 'revoked', 'changed'),
                 ('actor', 'target_user', 'role_before', 'role_after'), '앱 권한 변경'),
    'app_export': ('web', ('queried', 'exported', 'downloaded'),
                   ('actor', 'resource_type', 'record_count'), '대량 조회·내보내기'),
    'app_upload': ('web', ('uploaded',),
                   ('actor', 'object_name', 'risk_reason'), '위험 파일 업로드'),
    'network_dns': ('network', ('query',),
                    ('source_ip', 'dns_name', 'dns_rcode'), '의심 DNS 질의'),
    'network_firewall': ('network', ('denied', 'dropped', 'rejected'),
                         ('source_ip', 'destination_ip', 'destination_port'), '방화벽 통신 차단'),
    'network_ids': ('network', ('alert',),
                    ('source_ip', 'destination_ip', 'signature_id', 'signature_name'), 'IDS 침입 징후'),
}
TEXT_FIELDS = {
    'actor', 'target_user', 'object_path', 'object_name', 'object_type',
    'role_before', 'role_after', 'resource_type', 'risk_reason', 'dns_name',
    'dns_rcode', 'signature_id', 'signature_name', 'transport',
}
NUMBER_FIELDS = {'record_count': 2**63 - 1, 'bytes': 2**63 - 1,
                 'destination_port': 65535, 'source_port': 65535}
PAYLOAD_FIELDS = ('schema', 'kind', 'action', 'outcome', 'critical_asset',
                  *sorted(TEXT_FIELDS), *NUMBER_FIELDS, 'source_ip', 'destination_ip')
READ_FIELDS = tuple('security_scenario.' + name for name in PAYLOAD_FIELDS)


def parse(source):
    payload = field(source, 'security_scenario')
    if not isinstance(payload, dict) or payload.get('schema') != VERSION:
        raise ValueError('scenario_schema_invalid')
    kind = payload.get('kind')
    if not isinstance(kind, str) or kind not in SCENARIOS:
        raise ValueError('scenario_kind_invalid')
    category, actions, required, _ = SCENARIOS[kind]
    action = payload.get('action')
    if action not in actions:
        raise ValueError('scenario_action_invalid')
    values = {'category': category, 'action': action, 'scenario_kind': kind,
              'outcome': payload.get('outcome', 'unknown')}
    if values['outcome'] not in ('success', 'failure', 'unknown'):
        raise ValueError('scenario_outcome_invalid')
    for name in TEXT_FIELDS:
        if name not in payload:
            continue
        raw = payload[name]
        if (not isinstance(raw, str) or not 0 < len(raw) <= 512
                or raw != raw.strip() or any(ord(c) < 32 for c in raw)):
            raise ValueError('scenario_text_invalid')
        value = display(raw)
        if not value or value == REDACTED or value != raw:
            raise ValueError('scenario_text_restricted')
        values[name] = value
    for name, maximum in NUMBER_FIELDS.items():
        if name in payload:
            value = payload[name]
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError('scenario_number_invalid')
            values[name] = value
    for name in ('source_ip', 'destination_ip'):
        if name in payload:
            value = payload[name]
            if not isinstance(value, str) or '%' in value:
                raise ValueError('scenario_ip_invalid')
            values[name] = str(ip_address(value))
    if 'critical_asset' in payload:
        if type(payload['critical_asset']) is not bool:
            raise ValueError('scenario_critical_asset_invalid')
        values['critical_asset'] = payload['critical_asset']
    if any(name not in values for name in required):
        raise ValueError('scenario_required_metadata_missing')
    if kind.startswith('app_'):
        service = field(source, 'service.name')
        if not isinstance(service, str) or not service or display(service) != service:
            raise ValueError('scenario_service_missing')
    if kind == 'server_persistence' and values['object_type'] not in ('service', 'scheduled_task', 'cron', 'systemd_timer'):
        raise ValueError('scenario_persistence_type_invalid')
    if kind == 'app_upload' and values['risk_reason'] not in ('executable_extension', 'mime_mismatch', 'malware_verdict'):
        raise ValueError('scenario_upload_reason_invalid')
    if 'transport' in values and values['transport'] not in ('tcp', 'udp', 'icmp'):
        raise ValueError('scenario_transport_invalid')
    if kind == 'network_dns':
        values['dns_name_length'] = len(values['dns_name'])
    return values
