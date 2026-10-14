"""Fixed rule inventory and explicit selections; defaults never enable candidates."""
from copy import deepcopy
from cloud_soc.detection.rule_loader import load_rules, PROJECT_ROOT
from cloud_soc.detection.engine import get_field_value

FILES = ('authentication.yml', 'authentication_sequence.yml', 'attacks.yml', 'cloud.yml', 'metadata_patterns.yml')
RULE_IDS = ('AUTH-001', 'AUTH-SEQ-001', 'AUTH-SPRAY-001', 'ATTACK-01', 'ATTACK-02', 'ATTACK-03',
            'AWS-IAM-001', 'AWS-AUDIT-001', 'AWS-NETWORK-001', 'OCI-IAM-001', 'WIN-AUTH-001',
            'WEB-404-001', 'NET-PORT-001', 'AWS-CONSOLE-001')


def catalog():
    rows = [row for name in FILES for row in load_rules(PROJECT_ROOT / 'rules' / name, enabled_only=False)]
    found = {row['id']: row for row in rows}
    if len(found) != len(rows) or set(found) != set(RULE_IDS):
        raise ValueError('Incomplete or duplicate fixed rule inventory')
    return [found[key] for key in RULE_IDS]


def select(*, isolated_all=False, rule_ids=None):
    rows = catalog()
    if isolated_all:
        if rule_ids is not None:
            raise ValueError('Conflicting rule selections')
        # A private copy records the actual isolated execution in alert snapshots.
        return [{**deepcopy(row), 'enabled': True} for row in rows]
    if (not isinstance(rule_ids, (list, tuple)) or not rule_ids
            or any(not isinstance(key, str) for key in rule_ids) or len(set(rule_ids)) != len(rule_ids)
            or set(rule_ids) - set(RULE_IDS)):
        raise ValueError('Invalid explicit rule selection')
    chosen = {'AUTH-001', *rule_ids}
    selected = [row for row in rows if row['id'] in chosen]
    if any(not row.get('enabled', True) for row in selected):
        raise ValueError('Unverified candidates require isolated_all; live defaults remain disabled')
    return selected


def source_observed(event, identifier):
    """Known source family, independent of whether an attack condition matches."""
    adapter = get_field_value(event, 'cloud_soc.detail.adapter')
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
