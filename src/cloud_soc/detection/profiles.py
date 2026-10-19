"""Fixed rule inventory and explicit selections; defaults never enable candidates."""
from copy import deepcopy
from cloud_soc.detection.rule_loader import load_rules, PROJECT_ROOT
from cloud_soc.detection.engine import get_field_value

CORE_FILES = ('authentication.yml', 'authentication_sequence.yml', 'attacks.yml', 'cloud.yml', 'metadata_patterns.yml', 'web_generic.yml')
APPLICATION_FILES = ('security_mall.yml',)
APPLICATION_IDS = ('WEB-ACCESS-01', 'WEB-AUTH-01', 'WEB-WAF-01')
FILES = (*CORE_FILES, *APPLICATION_FILES)
RULE_IDS = ('AUTH-001', 'AUTH-SEQ-001', 'AUTH-SPRAY-001', 'ATTACK-01', 'ATTACK-02', 'ATTACK-03',
            'AWS-IAM-001', 'AWS-AUDIT-001', 'AWS-NETWORK-001', 'OCI-IAM-001', 'WIN-AUTH-001',
            'WEB-404-001', 'NET-PORT-001', 'AWS-CONSOLE-001', 'WEB-ACCESS-01', 'WEB-AUTH-01', 'WEB-WAF-01', 'WEB-SITE-404-001', 'WEB-SITE-WAF-001')
CORE_RULE_IDS = tuple(key for key in RULE_IDS if key not in APPLICATION_IDS)


def catalog(*, include_applications=True):
    files = FILES if include_applications else CORE_FILES
    expected = RULE_IDS if include_applications else CORE_RULE_IDS
    rows = [row for name in files for row in load_rules(PROJECT_ROOT / 'rules' / name, enabled_only=False)]
    found = {row['id']: row for row in rows}
    if len(found) != len(rows) or set(found) != set(expected):
        raise ValueError('Incomplete or duplicate fixed rule inventory')
    return [found[key] for key in expected]


def select(*, isolated_all=False, rule_ids=None, retain_auth=True):
    if isolated_all:
        if rule_ids is not None or not retain_auth:
            raise ValueError('Conflicting rule selections')
        # A private copy records the actual isolated execution in alert snapshots.
        return [{**deepcopy(row), 'enabled': True} for row in catalog()]
    if (not isinstance(rule_ids, (list, tuple)) or not rule_ids
            or any(not isinstance(key, str) for key in rule_ids) or len(set(rule_ids)) != len(rule_ids)
            or set(rule_ids) - set(RULE_IDS)):
        raise ValueError('Invalid explicit rule selection')
    if not retain_auth and 'AUTH-001' in rule_ids:
        raise ValueError('Additional profile must not replace or duplicate AUTH-001')
    chosen = {'AUTH-001', *rule_ids} if retain_auth else set(rule_ids)
    rows = catalog(include_applications=bool(chosen.intersection(APPLICATION_IDS)))
    selected = [row for row in rows if row['id'] in chosen]
    if any(not row.get('enabled', True) for row in selected):
        raise ValueError('Unverified candidates require isolated_all; live defaults remain disabled')
    return selected


def source_observed(event, identifier):
    """Known source family, independent of whether an attack condition matches."""
    adapter = get_field_value(event, 'cloud_soc.detail.adapter')
    if identifier == 'WEB-SITE-404-001':
        return adapter == 'web_access_site_v2'
    if identifier == 'WEB-SITE-WAF-001':
        return adapter == 'modsecurity_audit_v1'
    if identifier == 'WEB-WAF-01':
        return (adapter == 'security_mall_edge_v1' and get_field_value(event, 'service.name') == 'security-mall'
                and get_field_value(event, 'cloud_soc.security_mall_edge.stream') == 'waf')
    if identifier in ('WEB-ACCESS-01', 'WEB-AUTH-01'):
        return adapter == 'security_mall_audit_v1' and get_field_value(event, 'service.name') == 'security-mall'
    if identifier.startswith('AWS-') or identifier in ('ATTACK-02', 'ATTACK-03'):
        return get_field_value(event, 'event.dataset') == 'aws.cloudtrail'
    if identifier == 'OCI-IAM-001':
        return get_field_value(event, 'event.dataset') == 'oci.audit'
    if identifier == 'WIN-AUTH-001':
        return adapter == 'windows_security_v1'
    if identifier == 'NET-PORT-001':
        return adapter == 'packetbeat_metadata_v1'
    if identifier == 'WEB-404-001':
        return adapter in ('web_access_metadata_v1', 'web_access_agent_v1') or (
            adapter == 'linux_operational_v1' and get_field_value(event, 'event.action') == 'http_access')
    if identifier == 'ATTACK-01' and adapter == 'linux_sudo_session_v1':
        return True
    return adapter in ('linux_ssh_v1', 'linux_ssh_v2') or get_field_value(event, 'network.protocol') == 'ssh'


def assessment(counts, phase):
    """Describes only this bounded run, never claims no attack or live validation."""
    if phase not in ('committed', 'evaluated'):
        return {'state': 'unverified', 'reason': 'run_not_committed'}
    if counts.get('unknown', 0) or counts.get('excluded', 0):
        return {'state': 'not_evaluable', 'reason': 'incomplete_or_excluded_input'}
    if not counts.get('source_events', 0):
        return {'state': 'unverified', 'reason': 'no_source_observations'}
    if phase != 'committed':
        return {'state': 'unverified', 'reason': 'run_not_committed'}
    return {'state': 'evaluated', 'reason': 'bounded_observed_input'}
