"""OWASP Top 10:2025 signals from validated adapters and explicit outcomes."""

from cloud_soc.portal.log_contract import field

APP_ADAPTER = 'application_security_audit_v1'
APP_SOURCE = 'application_security_audit'
APP_FIELDS = ('application_security.schema', 'application_security.check',
              'application_security.result', 'service.id')
APP_CHECKS = {
    'secure_configuration': 'insecure_configuration_verified',
    'dependency_provenance': 'dependency_provenance_verified',
    'cryptographic_policy': 'cryptographic_policy_verified',
    'business_invariant': 'business_invariant_verified',
    'artifact_integrity': 'artifact_integrity_verified',
    'exception_fail_open': 'exception_fail_open_verified',
}


def application_audit(source):
    """Project a check from a configured application security audit exporter."""
    if field(source, 'labels.log_source') != APP_SOURCE:
        return None
    schema = field(source, 'application_security.schema')
    check = field(source, 'application_security.check')
    result = field(source, 'application_security.result')
    service = field(source, 'service.id')
    from cloud_soc.web.scope import valid_site_id
    if (type(schema) is not int or schema != 1 or not isinstance(check, str) or check not in APP_CHECKS
            or result not in ('pass', 'fail') or not valid_site_id(service)):
        return None
    return {'category': 'web', 'action': APP_CHECKS[check],
            'outcome': 'failure' if result == 'fail' else 'success', 'service_id': service}

# Each entry requires a trusted adapter, a specific action and the relevant
# outcome. Categories that need new application telemetry remain dormant until
# a source adapter validates those actions.
RULES = (
    ('A01', ('security_mall_audit_v1', 'eks_audit_v1'), ('kubernetes_authorization_denied',), 'failure', 'application_authorization_denied'),
    ('A02', ('application_security_audit_v1',), ('insecure_configuration_verified',), 'failure', 'configuration_check_failed'),
    ('A03', ('application_security_audit_v1',), ('dependency_provenance_verified',), 'failure', 'dependency_provenance_check_failed'),
    ('A04', ('application_security_audit_v1',), ('cryptographic_policy_verified',), 'failure', 'cryptographic_policy_check_failed'),
    ('A05', ('modsecurity_audit_v1', 'aws_waf_v1'), (), None, 'validated_waf_injection_signature'),
    ('A06', ('application_security_audit_v1',), ('business_invariant_verified',), 'failure', 'business_invariant_check_failed'),
    ('A07', ('security_mall_audit_v1', 'windows_security_v1', 'linux_ssh_v1', 'linux_ssh_v2',
             'linux_ssh_invalid_user_v1', 'linux_journal_audit_v1', 'linux_priority_v1', 'windows_operational_v1'),
     ('login', 'ssh_login', 'linux_audit_authentication', 'linux_audit_login', 'sshd_authentication_failed',
      'sudo_authentication_failed', 'windows_ntlm_validation'), 'failure', 'authentication_failure_reported'),
    ('A08', ('linux_journal_audit_v1', 'application_security_audit_v1'),
     ('linux_audit_integrity_check', 'artifact_integrity_verified'), 'failure', 'integrity_check_failed'),
    ('A09', ('windows_operational_v1', 'linux_journal_audit_v1'),
     ('windows_security_audit_cleared', 'windows_event_log_stopped', 'linux_audit_daemon_error'),
     None, 'audit_logging_disruption_reported'),
    ('A10', ('application_security_audit_v1',), ('exception_fail_open_verified',), 'failure', 'exception_control_failed'),
)


def signals(adapter, fields, action, outcome):
    result = []
    for category, adapters, actions, required_outcome, basis in RULES:
        if adapter not in adapters or required_outcome is not None and outcome != required_outcome:
            continue
        if category == 'A05':
            if not any(fields.get(key) is True for key in ('sqli', 'injection_signal')):
                continue
        elif action not in actions:
            # The mall auditor retains the attempted operation as its action.
            if category != 'A01' or fields.get('authorization_reason') not in ('not_owner', 'admin_required'):
                continue
        result.append({'category': category + ':2025', 'evidence': basis})
    return result


def normalized_signals(event):
    return signals(field(event, 'cloud_soc.detail.adapter'), field(event, 'cloud_soc.detail.fields') or {},
                   field(event, 'event.action'), field(event, 'event.outcome'))
