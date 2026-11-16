"""Join existing processing records and project common fields for every intake row."""

import hashlib
import json

from elasticsearch import ApiError, TransportError

from cloud_soc.multicloud.adapter import VERSION as MULTICLOUD
from cloud_soc.parsers.linux_operational import VERSION as LINUX, SUDO_SESSION_VERSION
from cloud_soc.parsers.linux_audit import ADAPTER as LINUX_AUDIT_ADAPTER, VERSION as LINUX_AUDIT
from cloud_soc.parsers.linux_audit import AUDITD_VERSION
from cloud_soc.parsers.eks_audit import VERSION as EKS_VERSION
from cloud_soc.parsers.linux_priority import VERSION as LINUX_PRIORITY
from cloud_soc.parsers.linux_security import SSH_INVALID_USER_VERSION
from cloud_soc.parsers.security_mall import VERSION as MALL
from cloud_soc.parsers.security_mall_edge import VERSION as EDGE
from cloud_soc.parsers.suricata import ADAPTER as SURICATA, EVENT_TYPE, EVE_PATH, VERSION as EVE, processing_id
from cloud_soc.parsers.windows_operational import ADAPTER as WINDOWS_ADAPTER, VERSION as WINDOWS
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import field
from cloud_soc.portal.owasp import normalized_signals, signals
from cloud_soc.portal.security_detail import address, text
from cloud_soc.processing.contract import BACKFILL_NORMALIZED, BACKFILL_RECORDS, NORMALIZED, RECORDS, VERSION as INTAKE
from cloud_soc.web.metadata import VERSION as WEB
from cloud_soc.web.modsecurity import VERSION as WAF
from cloud_soc.web.scope import LEGACY_VERSION, NORMALIZER_VERSION

VERSIONS = {
    'windows_event': (WINDOWS,),
    'linux_file': (SSH_INVALID_USER_VERSION, SUDO_SESSION_VERSION, LINUX_PRIORITY, LINUX, 'linux-unclassified-v1'),
    'linux_journald': (LINUX_AUDIT, SSH_INVALID_USER_VERSION, SUDO_SESSION_VERSION, LINUX_PRIORITY, LINUX, 'linux-unclassified-v1'),
    'eks_audit': (EKS_VERSION,),
    'linux_auditd': (AUDITD_VERSION,),
    'multicloud_audit': (MULTICLOUD,),
    'security_scenario': ('security-scenarios-v1',),
    'security_mall_audit': (MALL,),
    'security_mall_edge': (EDGE,),
    'generic_modsecurity': (WAF,),
    'generic_web_access': (NORMALIZER_VERSION, LEGACY_VERSION),
    'web_access_metadata': (WEB,),
}
RECORD_FIELDS = ['raw.index', 'raw.id', 'status', 'version', 'reason', 'adapter',
                 'normalized.index', 'normalized.id', 'recovery.version', 'recovery.assessment',
                 'recovery.matched_rules']
EVENT_FIELDS = ['@timestamp', 'organization.id', 'event.dataset', 'event.action', 'event.outcome',
                'event.category', 'event.kind', 'source.ip', 'destination.ip', 'user.name',
                'cloud_soc.provenance.raw.index', 'cloud_soc.provenance.raw.id',
                'cloud_soc.detail.adapter', 'cloud_soc.detail.fields.authorization_reason',
                'cloud_soc.detail.fields.sqli', 'cloud_soc.detail.fields.injection_signal', 'cloud_soc.parse_status',
                'cloud_soc.detail.fields.audit_id', 'cloud_soc.detail.fields.audit_stage',
                'cloud_soc.detail.fields.audit_record_type', 'cloud_soc.detail.fields.http_status',
                'cloud_soc.detail.fields.resource', 'cloud_soc.detail.fields.authorization_decision',
                'cloud_soc.detail.fields.log_level']
REASONS = {
    'missing_scope_or_time', 'adapter_not_supported', 'source_scope_mismatch',
    'linux_time_invalid', 'linux_timezone_missing', 'ssh_time_invalid', 'ssh_timezone_missing',
    'suricata_metadata_invalid', 'suricata_host_invalid', 'multicloud_metadata_invalid',
    'security_scenario_scope_or_metadata_invalid', 'web_collector_host_invalid',
    'application_security_metadata_invalid',
}


def lookup(client, index, ids, fields):
    """Missing entries and failed or mismatched responses have distinct meanings."""
    try:
        response = client.mget(index=index, docs=[{'_id': key, '_source': fields} for key in ids])
    except (ApiError, TransportError):
        return {}
    body = getattr(response, 'body', response)
    docs = body.get('docs') if isinstance(body, dict) else None
    if not isinstance(docs, list) or len(docs) != len(ids):
        return {}
    matches = {}
    for key, doc in zip(ids, docs, strict=True):
        if not isinstance(doc, dict) or doc.get('_index') != index or doc.get('_id') != key or 'error' in doc:
            continue
        if doc.get('found') is False:
            matches[key] = None
        elif doc.get('found') is True and isinstance(doc.get('_source'), dict):
            matches[key] = doc['_source']
    return matches


def common_event(row, status, reason=None, event=None):
    fields = row['interpretation']['fields']
    types = row['log_type']
    categories = field(event, 'event.category')
    outcome = field(event, 'event.outcome') or fields.get('outcome') or row['outcome']
    action = text(field(event, 'event.action') or fields.get('action') or row['action'])
    quality = row['parse_status']
    if event is not None:
        quality = field(event, 'cloud_soc.parse_status')
    adapter = text(field(event, 'cloud_soc.detail.adapter')) or row['interpretation']['adapter']
    interpretation = {'recognized': 'interpreted', 'partial': 'partial', 'invalid': 'invalid'}.get(quality, 'metadata')
    if adapter == 'linux_unclassified_v1':
        interpretation = 'metadata'
    stamp = parse_time(field(event, '@timestamp'))
    evidence = types['basis']
    if event is not None and (adapter != row['interpretation']['adapter'] or adapter == SURICATA):
        evidence = 'normalized_document'
    owasp = []
    if interpretation in ('interpreted', 'partial'):
        owasp = normalized_signals(event) if event is not None else signals(adapter, fields, action, outcome)
    return {
        'type': fields.get('event_type') or types['code'], 'basis': evidence,
        'category': text(categories[0]) if isinstance(categories, list) and categories else types['code'],
        'dataset': text(field(event, 'event.dataset')) or row['dataset'],
        'kind': 'alert' if field(event, 'event.kind') == 'alert' else 'event' if event is not None else None,
        'action': action, 'outcome': outcome if outcome in ('success', 'failure', 'unknown') else 'unknown',
        'actor': text(field(event, 'user.name') or fields.get('actor') or row['user'] or row['actor_id']),
        'source_ip': address(field(event, 'source.ip') or fields.get('source_ip')) or row['source_ip'],
        'destination_ip': address(field(event, 'destination.ip') or fields.get('destination_ip')) or row['destination_ip'],
        'event_at': iso(stamp) if stamp else row['event_at'],
        'interpretation': interpretation, 'status': status, 'reason': reason,
        'adapter': adapter or 'intake_metadata_v1',
        'owasp': owasp,
        **{name: value for name in ('audit_id', 'audit_stage', 'audit_record_type', 'http_status',
                                     'resource', 'authorization_decision', 'log_level')
           if (value := field(event, 'cloud_soc.detail.fields.' + name)) is not None
           and (type(value) is int or isinstance(value, str) and text(value) == value and len(value) <= 128)},
    }


def processing_candidates(source, ref, source_kind):
    suricata = (ref['index'].startswith('soc-host-raw-')
                and field(source, 'labels.log_source') == 'linux_file'
                and field(source, 'log.file.path') == EVE_PATH)
    versions = (EVE,) if suricata else VERSIONS.get(source_kind, ())
    if field(source, 'log.file.path') == '/var/log/cloud-soc/alb/alb-access.log':
        versions = (LINUX_PRIORITY, *versions)
    keys = {(processing_id(ref) if version == EVE
             else hashlib.sha256(json.dumps([version, ref], sort_keys=True).encode()).hexdigest()): version
            for version in (*versions, INTAKE)}
    return suricata, keys


def enrich(client, hits, rows):
    candidates, groups = {}, []
    for hit, row in zip(hits, rows, strict=True):
        source, ref = hit['_source'], row['reference']
        suricata, keys = processing_candidates(source, ref, row['source_kind'])
        if suricata:
            row['log_type'] = {'code': 'suricata_eve', 'label': 'Suricata EVE', 'basis': 'source_path'}
        candidates.update(keys)
        groups.append((row, field(source, 'organization.id'), suricata, keys))
    if not groups:
        return

    records = lookup(client, RECORDS, list(candidates), RECORD_FIELDS)
    fallback_ids = []
    for _, _, _, keys in groups:
        if not any(field(records.get(key), 'status') == 'normalized' for key in keys):
            fallback_ids.extend(keys)
    history = lookup(client, BACKFILL_RECORDS, list(dict.fromkeys(fallback_ids)), RECORD_FIELDS) if fallback_ids else {}
    pending = {}
    resolved = []
    for row, organization, suricata, keys in groups:
        status = 'unrecorded' if all(key in records and records[key] is None for key in keys) else 'unavailable'
        reason = None
        valid = [(key, record, target) for source_records, target in (
                     (records, NORMALIZED), (history, BACKFILL_NORMALIZED))
                 for key, version in keys.items() if isinstance(record := source_records.get(key), dict)
                 and record.get('raw') == row['reference'] and record.get('version') == version
                 and (not suricata or version == INTAKE or record.get('adapter') == SURICATA)]
        for key, record, target in valid:
            if (record.get('status') == 'normalized'
                    and record.get('normalized') == {'index': target, 'id': key}):
                pending.setdefault(key, (record, target))
        for _, record, _ in valid:
            if record.get('status') in ('invalid', 'unsupported'):
                status = record['status']
                reason = record.get('reason')
                if status == 'unsupported' and row['interpretation']['adapter'] in (WINDOWS_ADAPTER, LINUX_AUDIT_ADAPTER):
                    status, reason = 'not_reprocessed', None
                break
        resolved.append((row, organization, suricata, keys, status, reason))

    events = {}
    for target in (NORMALIZED, BACKFILL_NORMALIZED):
        ids = [key for key, (_, index) in pending.items() if index == target]
        if ids:
            events.update(lookup(client, target, ids, EVENT_FIELDS))
    for row, organization, suricata, keys, status, reason in resolved:
        event = None
        for key in keys:
            if key not in pending:
                continue
            status, reason = 'unavailable', None
            candidate = events.get(key)
            adapter = field(candidate, 'cloud_soc.detail.adapter')
            action = field(candidate, 'event.action')
            if (isinstance(organization, str) and organization
                    and field(candidate, 'organization.id') == organization
                    and field(candidate, 'cloud_soc.provenance.raw') == row['reference']
                    and adapter == pending[key][0].get('adapter') and isinstance(adapter, str)
                    and field(candidate, 'cloud_soc.parse_status') in ('recognized', 'partial')
                    and (not suricata or (adapter == SURICATA and field(candidate, 'event.dataset') == 'suricata.eve'
                                         and isinstance(action, str) and EVENT_TYPE.fullmatch(action)))):
                status, event = 'normalized', candidate
                if row['os_basis'] == 'input.type':
                    attach_recovery(row, pending[key][0].get('recovery'))
                break
        if suricata:
            action = field(event, 'event.action')
            row['suricata'] = {'status': status, 'event_type': action}
            if event is not None:
                row['parse_status'] = 'recognized'
                row['interpretation'] = {'status': 'recognized', 'adapter': SURICATA, 'fields': {'action': action}}
        row['normalization'] = common_event(row, status, reason if isinstance(reason, str) and reason in REASONS else None, event)
        if suricata and event is not None:
            row['normalization']['type'] = action


def attach_recovery(row, recovery):
    versions = {'aws_cloudtrail': 'cloudwatch-cloudtrail-recovery-v1',
                'aws_vpc_flowlogs': 'cloudwatch-vpc-recovery-v1', 'aws_waf': 'cloudwatch-waf-recovery-v1'}
    if not isinstance(recovery, dict) or recovery.get('version') != versions.get(row['source_kind']):
        return
    assessment = recovery.get('assessment')
    if assessment not in ('evaluated', 'not_evaluable', 'not_applicable', 'routed_live'):
        return
    result = {'normalization': 'completed', 'assessment': assessment}
    rules = recovery.get('matched_rules')
    if isinstance(rules, list):
        result['matched_rules'] = [rule for rule in rules if rule in (
            'AWS-VPC-MGMT-ACCEPT-001', 'AWS-WAF-INJECTION-BLOCK-001')]
    row['cloudwatch_assessment'] = result
