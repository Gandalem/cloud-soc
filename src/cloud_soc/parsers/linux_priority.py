"""Allowlisted Linux authentication, scheduled job and SSM observations."""
from ipaddress import ip_address
import re

from cloud_soc.portal.log_contract import field
from cloud_soc.parsers.linux_operational import ISO_PREFIX, PREFIX

VERSION = 'linux-priority-v1'
SSH_PAM_VERSION = 'linux-ssh-pam-observation-v1'
ADAPTER = 'linux_priority_v1'
AUTH_PATH = re.compile(r'/var/log/(?:auth\.log|secure)(?:\.[0-9]+)?')
FAIL2BAN_PATH = re.compile(r'/var/log/fail2ban\.log(?:\.[0-9]+)?')
PAM = re.compile(r'pam_[a-z0-9_]+\((sshd|sudo|cron|crond):(session|auth)\): (session opened|session closed|authentication failure)(?=\s|;|$)')
SSM = re.compile(r'\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\s+(INFO|WARN|ERROR|DEBUG|TRACE|CRITICAL)\s+\S.*')
AUTH_OBSERVATIONS = {
    'sshd': ((r'(?:Disconnected from |Connection closed by |Connection closed by authenticating user |Received disconnect from )', 'sshd_connection_closed'),
             (r'Invalid user \S+ from ', 'sshd_invalid_user_reported')),
    'polkitd': ((r'Registered Authentication Agent for ', 'polkit_agent_registered'),
                (r'Unregistered Authentication Agent for ', 'polkit_agent_unregistered')),
    'useradd': ((r'new user: name=', 'linux_user_created'),),
    'groupadd': ((r'new group: name=', 'linux_group_created'),),
    'systemd-logind': ((r'New session \S+ of user ', 'linux_session_created'),
                       (r'Removed session \S+\.?$', 'linux_session_removed')),
}
ALB = re.compile(r'(?P<protocol>http|https|h2|grpcs|ws|wss|h3) (?P<time>\S+) app/\S+ \S+ \S+ (?:-?[0-9]+(?:\.[0-9]+)? ){3}(?P<status>[1-5][0-9]{2}) (?P<target>-|[1-5][0-9]{2})(?: |$)')


def interpret_alb(source):
    if field(source, 'log.file.path') != '/var/log/cloud-soc/alb/alb-access.log':
        return None
    message = source.get('message')
    match = ALB.match(message) if isinstance(message, str) and len(message) <= 16384 and '\n' not in message else None
    if not match:
        return None
    from cloud_soc.portal.agent_status import parse_time
    if parse_time(match['time']) is None:
        return None
    return {**detail('web', 'alb_access_observed', http_status=int(match['status'])), 'occurred_at': match['time']}
JOURNAL_REPORTS = {
    ('crond.service', 'syslog', 'crond'): 'cron_daemon_report',
    ('crond.service', 'syslog', 'anacron'): 'anacron_report',
    ('cron.service', 'syslog', '(cron)'): 'cron_daemon_report',
    ('kdump.service', 'stdout', 'cat'): 'kdump_service_output',
    ('cloud-final.service', 'stdout', 'tee'): 'cloud_init_service_output',
    ('cloud-init.service', 'stdout', 'tee'): 'cloud_init_service_output',
    ('systemd-logind.service', 'journal', 'systemd-logind'): 'linux_session_service_report',
    ('polkit.service', 'syslog', 'polkitd'): 'polkit_service_report',
}


def interpret(source):
    tag = field(source, 'labels.log_source')
    if tag not in ('linux_file', 'linux_journald'):
        return None
    message = source.get('message')
    if not isinstance(message, str) or not 0 < len(message) <= 8192 or any(c in message for c in '\r\n'):
        return None
    path = field(source, 'log.file.path')
    unit = field(source, 'systemd.unit')
    origin = {}
    if tag == 'linux_file':
        if not isinstance(path, str) or not (AUTH_PATH.fullmatch(path) or FAIL2BAN_PATH.fullmatch(path)):
            return None
        prefix = ISO_PREFIX.fullmatch(message) or PREFIX.fullmatch(message)
        if FAIL2BAN_PATH.fullmatch(path):
            return fail2ban(message)
        if not prefix:
            return None
        app, body = prefix['app'].lower(), prefix['body']
        key = 'occurred_at' if ISO_PREFIX.fullmatch(message) else 'time_text'
        origin[key] = prefix['time']
    else:
        transport = field(source, 'systemd.transport')
        name = field(source, 'journald.process.name') or field(source, 'process.name') or field(source, 'journald.syslog.identifier')
        app, body = name.lower() if isinstance(name, str) else '', message
        if (unit, transport, app) in (('cron.service', 'syslog', 'sh'), ('crond.service', 'syslog', 'logger')):
            return detail('configuration', 'scheduled_job_output_observed', partial=True)
        if (unit, transport, app) == ('dnf-makecache.service', 'stdout', 'dnf'):
            return detail('configuration', 'package_cache_log_observed', partial=True)
        if unit == 'amazon-ssm-agent.service' and field(source, 'systemd.transport') == 'stdout':
            match = SSM.fullmatch(message)
            if match:
                return detail('host', 'ssm_agent_error' if match[1] in ('ERROR', 'CRITICAL') else 'ssm_agent_report',
                              log_level=match[1].lower())
            return None
        if unit not in ('cron.service', 'crond.service', 'ssh.service', 'sshd.service',
                        'systemd-logind.service', 'polkit.service'):
            report = JOURNAL_REPORTS.get((unit, transport, app))
            return detail('host', report, partial=True) if report else None
    match = PAM.match(body)
    if match and match[1] == app:
        operation = {'session opened': 'session_opened', 'session closed': 'session_closed',
                     'authentication failure': 'authentication_failed'}[match[3]]
        if (operation == 'authentication_failed') != (match[2] == 'auth'):
            return None
        kind = 'cron' if app in ('cron', 'crond') else app
        fields = {}
        if kind == 'sshd' and operation == 'authentication_failed':
            if tag == 'linux_journald' and unit not in ('ssh.service', 'sshd.service'):
                return None
            fields['pam_protocol'] = 'ssh'
            peers = re.findall(r'(?:^|[ ;])rhost=([^\s;]*)', body[match.end():])
            if len(peers) == 1 and '%' not in peers[0]:
                try:
                    fields['pam_remote_ip'] = str(ip_address(peers[0]))
                except ValueError:
                    pass
        return {**detail('configuration' if kind == 'cron' else 'authentication', kind + '_' + operation,
                         'failure' if operation == 'authentication_failed' else 'unknown', **fields), **origin}
    if app in ('cron', 'crond') and re.fullmatch(r'\([A-Za-z0-9_.@-]{1,128}\) CMD \(.+\)', body):
        return {**detail('configuration', 'cron_job_invoked'), **origin}
    for pattern, action in AUTH_OBSERVATIONS.get(app, ()):
        if re.match(pattern, body):
            return {**detail('authentication', action), **origin}
    if tag == 'linux_journald':
        report = JOURNAL_REPORTS.get((unit, transport, app))
        if report:
            return detail('host', report, partial=True)
    return None


def detail(category, action, outcome='unknown', *, partial=False, **fields):
    return {'adapter': ADAPTER, 'status': 'partial' if partial else 'recognized', 'fields': {
        'category': category, 'action': action, 'outcome': outcome, **fields,
    }, 'limitations': ['message_body_and_arguments_excluded', 'not_a_detection']}


def fail2ban(message):
    from ipaddress import ip_address
    match = re.fullmatch(r'(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d),\d{3} fail2ban\.actions\s+\[\d+\]:\s+NOTICE\s+\[[a-zA-Z0-9_.-]+\] (Ban|Unban) ([0-9a-fA-F:.]+)', message)
    if not match:
        observed = re.fullmatch(r'\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3} fail2ban\.filter\s+\[\d+\]:\s+INFO\s+\[[a-zA-Z0-9_.-]+\] Found ([0-9a-fA-F:.]+)(?: - \d{4}-\d\d-\d\d \d\d:\d\d:\d\d)?', message)
        if not observed:
            return None
        try:
            peer = str(ip_address(observed[1]))
        except ValueError:
            return None
        return {**detail('network', 'fail2ban_filter_match', source_ip=peer), 'collector_time_only': True}
    try:
        peer = str(ip_address(match[3]))
    except ValueError:
        return None
    return {**detail('network', 'fail2ban_block' if match[2] == 'Ban' else 'fail2ban_unblock', source_ip=peer),
            'collector_time_only': True}
