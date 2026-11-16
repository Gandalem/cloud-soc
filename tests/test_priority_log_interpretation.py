import json

from cloud_soc.processing.contract import normalize


STAMP = '2026-11-14T03:36:33Z'
AUDIT_ID = '45a7ed4f-1374-4db1-b794-66bc1b3d17e8'


def event(tag, message='', **extra):
    return {'_index': 'soc-host-raw-fixture', '_id': 'fixture', '_source': {
        '@timestamp': STAMP, 'event': {'ingested': STAMP}, 'organization': {'id': 'fixture'},
        'labels': {'log_source': tag}, 'message': message, **extra,
    }}


def test_eks_stage_and_authorization_evidence():
    payload = {'apiVersion': 'audit.k8s.io/v1', 'kind': 'Event', 'auditID': AUDIT_ID,
               'stageTimestamp': STAMP, 'stage': 'ResponseStarted', 'verb': 'get',
               'objectRef': {'resource': 'pods'}, 'responseStatus': {'code': 403},
               'annotations': {'authorization.k8s.io/decision': 'forbid'},
               'requestObject': {'secret': 'PRIVATE_CANARY'}}
    early = normalize(event('eks_audit', json.dumps(payload)), STAMP)[2]
    assert early['event']['outcome'] == 'unknown'
    assert 'owasp' not in early['cloud_soc']
    payload['stage'] = 'ResponseComplete'
    done = normalize(event('eks_audit', json.dumps(payload)), STAMP)[2]
    assert done['event']['id'] == early['event']['id'] == AUDIT_ID
    assert done['event']['action'] == 'kubernetes_authorization_denied'
    assert done['cloud_soc']['owasp'][0]['category'] == 'A01:2025'
    assert 'PRIVATE_CANARY' not in str(done)
    assert normalize(event('linux_file', json.dumps(payload)), STAMP)[2] is None


def test_rotated_auth_cron_and_ssm_keep_command_and_result_distinct():
    _, record, auth = normalize(event('linux_file',
        '2026-11-14T03:36:33Z host CRON[44]: pam_unix(cron:session): session opened for user fixture',
        log={'file': {'path': '/var/log/auth.log.1'}}), STAMP)
    assert record['version'] == 'linux-priority-v1'
    assert auth['event']['action'] == 'cron_session_opened'
    cron = normalize(event('linux_journald', '(fixture) CMD (PRIVATE_CANARY)',
        systemd={'unit': 'cron.service'}, journald={'process': {'name': 'cron'}}), STAMP)[2]
    assert cron['event']['action'] == 'cron_job_invoked'
    assert cron['event']['outcome'] == 'unknown' and 'PRIVATE_CANARY' not in str(cron)
    ssm = normalize(event('linux_journald', '2026-11-14 03:36:33 ERROR PRIVATE_CANARY',
        systemd={'unit': 'amazon-ssm-agent.service', 'transport': 'stdout'}), STAMP)[2]
    assert ssm['event']['action'] == 'ssm_agent_error'
    assert 'PRIVATE_CANARY' not in str(ssm)


def test_windows_explicit_status_and_partial_auditd_record():
    win = event('windows_event', winlog={'channel': 'Security', 'provider_name': 'Microsoft-Windows-Security-Auditing',
        'event_id': 4776, 'event_data': {'Status': '0xc000006a'}})
    result = normalize(win, STAMP)[2]
    assert result['event']['outcome'] == 'failure'
    assert result['cloud_soc']['owasp'][0]['category'] == 'A07:2025'
    path = normalize(event('linux_auditd', 'type=PATH msg=audit(1794627393.5:17): item=0 name="/PRIVATE_CANARY"'), STAMP)[2]
    assert path['cloud_soc']['parse_status'] == 'partial'
    assert path['cloud_soc']['detail']['fields']['audit_id'] == '1794627393.5:17'
    assert path['event']['outcome'] == 'unknown' and 'PRIVATE_CANARY' not in str(path)


def test_collector_projections_normalize_without_original_message():
    eks = normalize(event('eks_audit', eks_audit={'schema': 1, 'id': AUDIT_ID, 'stage': 'ResponseComplete',
        'verb': 'get', 'stage_at': STAMP, 'status': 403, 'decision': 'forbid', 'resource': 'pods'}), STAMP)[2]
    assert eks['event']['action'] == 'kubernetes_authorization_denied'
    audit = normalize(event('linux_auditd', linux_audit_record={'schema': 1, 'type': 'SYSCALL',
        'id': '1794627393.5:17', 'arch': 'c000003e', 'syscall': 2, 'success': 'no'}), STAMP)[2]
    assert audit['event']['outcome'] == 'failure'
    assert audit['cloud_soc']['parse_status'] == 'partial'


def test_residual_rules_keep_output_and_operation_result_separate():
    raw = event('linux_journald', 'PRIVATE_CANARY', systemd={'unit': 'cron.service', 'transport': 'syslog'},
                journald={'process': {'name': 'sh'}})
    result = normalize(raw, STAMP)[2]
    assert result['event']['action'] == 'scheduled_job_output_observed'
    assert result['event']['outcome'] == 'unknown'
    assert result['cloud_soc']['parse_status'] == 'partial'
    assert 'PRIVATE_CANARY' not in str(result)
