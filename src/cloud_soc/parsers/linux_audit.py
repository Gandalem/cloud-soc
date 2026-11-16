"""Interpret journal audit types without exposing the audit message."""
import re

from cloud_soc.portal.log_contract import field

VERSION = 'linux-journal-audit-v1'
ADAPTER = 'linux_journal_audit_v1'
TYPE_FIELD = 'journald.custom.audit_type'
RULES = {
    '1100': ('USER_AUTH', 'authentication', 'linux_audit_authentication'),
    '1101': ('USER_ACCT', 'iam', 'linux_audit_authorization'),
    '1112': ('USER_LOGIN', 'authentication', 'linux_audit_login'),
    '1130': ('SERVICE_START', 'configuration', 'linux_audit_service_start'),
    '1131': ('SERVICE_STOP', 'configuration', 'linux_audit_service_stop'),
    '1209': ('DAEMON_ERR', 'host', 'linux_audit_daemon_error'),
    '1305': ('CONFIG_CHANGE', 'configuration', 'linux_audit_configuration_change'),
    '1334': ('BPF', 'process', 'linux_audit_bpf_activity'),
    '1400': ('AVC', 'iam', 'linux_audit_policy_decision'),
    '1800': ('INTEGRITY_DATA', 'file', 'linux_audit_integrity_check'),
}

AUDITD_VERSION = 'linux-auditd-record-v1'
AUDITD_ADAPTER = 'linux_auditd_record_v1'
AUDITD_FIELDS = tuple('linux_audit_record.' + key for key in ('schema', 'type', 'id', 'arch', 'syscall', 'success'))
AUDITD_RECORD = re.compile(r'(?:node=[A-Za-z0-9_.-]{1,253} )?type=([A-Z_]{2,32}) +msg=audit\((\d{1,12}\.\d{1,9}:\d{1,12})\):[^\r\n]*')
AUDITD_TYPES = {name: (category, action) for name, category, action in RULES.values()}
AUDITD_TYPES.update(SYSCALL=('process', 'linux_audit_syscall_record'),
                    PATH=('file', 'linux_audit_path_record'),
                    CWD=('process', 'linux_audit_working_directory_record'),
                    EXECVE=('process', 'linux_audit_exec_record'))


def interpret_auditd(source):
    if field(source, 'labels.log_source') != 'linux_auditd':
        return None
    message = source.get('message')
    projected = field(source, 'linux_audit_record')
    match = AUDITD_RECORD.fullmatch(message) if isinstance(message, str) and 0 < len(message) <= 8192 else None
    if isinstance(projected, dict) and type(projected.get('schema')) is int and projected['schema'] == 1:
        record_type, audit_id = projected.get('type'), projected.get('id')
    elif match:
        record_type, audit_id = match.groups()
        projected = None
    else:
        return None
    if (not isinstance(record_type, str) or record_type not in AUDITD_TYPES
            or not isinstance(audit_id, str) or not re.fullmatch(r'\d{1,12}\.\d{1,9}:\d{1,12}', audit_id)):
        return None
    category, action = AUDITD_TYPES[record_type]
    outcome = 'unknown'
    if record_type == 'SYSCALL' and projected is not None:
        if projected.get('success') in ('yes', 'no'):
            outcome = 'success' if projected['success'] == 'yes' else 'failure'
    elif record_type == 'SYSCALL':
        from cloud_soc.parsers.linux_security import parse_linux_audit
        host = field(source, 'host.id')
        organization = field(source, 'organization.id')
        parsed = parse_linux_audit([{'host_id': host, 'organization': organization, 'line': message}])
        if parsed:
            outcome = parsed['outcome']
    return {'adapter': AUDITD_ADAPTER, 'status': 'partial', 'fields': {
        'category': category, 'action': action, 'outcome': outcome,
        'audit_id': audit_id, 'audit_record_type': record_type,
    }, 'limitations': ['audit_record_requires_host_scoped_correlation', 'not_a_detection']}


def interpret(source):
    if (field(source, 'labels.log_source') != 'linux_journald'
            or field(source, 'systemd.transport') != 'audit'):
        return None
    code = field(source, TYPE_FIELD)
    if type(code) is int:
        code = str(code)
    rule = RULES.get(code) if isinstance(code, str) else None
    if rule is None:
        return None
    name, category, action = rule
    message = source.get('message')
    outcome = 'unknown'
    if isinstance(message, str) and len(message) <= 8192 and '\n' not in message:
        match = re.fullmatch(r'(?:type=)?' + name + r' +[^\r\n]*?\bres=(success|failed|yes|no)[\x27"]? *', message)
        if match:
            outcome = 'success' if match[1] in ('success', 'yes') else 'failure'
    return {'category': category, 'action': action, 'outcome': outcome, 'event_code': code}
