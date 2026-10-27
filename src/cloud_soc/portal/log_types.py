"""Describe source/event types from bounded metadata; never classify attacks."""
import re


def classification(row, detail):
    kind=row['source_kind'];fields=detail.get('fields',{})
    def result(code,label,basis):return {'code':code,'label':label,'basis':basis}
    if kind == 'security_scenario' and detail.get('status') == 'recognized':
        from cloud_soc.parsers.security_scenarios import SCENARIOS
        scenario = SCENARIOS.get(fields.get('scenario_kind'))
        if scenario:
            return result(fields['scenario_kind'], scenario[3], 'structured_security_export')
    if kind=='security_mall_audit' and detail.get('status')=='recognized':
        action=fields.get('action')
        return result('authentication' if action=='login' else 'authorization',
                      '쇼핑몰 로그인 감사' if action=='login' else '쇼핑몰 접근·관리 감사','validated_application_event')
    if kind=='security_mall_edge' and detail.get('status')=='recognized':
        return result('waf' if fields.get('stream')=='waf' else 'web_access',
                      '쇼핑몰 WAF 탐지' if fields.get('stream')=='waf' else '쇼핑몰 웹 접근','validated_edge_stream')
    fixed={'generic_modsecurity':('waf','웹 WAF 탐지'),
           'generic_web_access':('web_access','웹 접근'), 'web_access_metadata':('web_access','웹 접근'),
           'network_packetbeat':('network','네트워크 통신'), 'aws_cloudtrail':('cloud_audit','AWS 관리 감사'),
           'oci_audit':('cloud_audit','OCI 관리 감사'), 'agent_health':('collection_health','에이전트 수집 상태'),
           'agent_collection_notice':('collection_error','수집 입력 오류')}
    if kind in fixed:
        code,label=fixed[kind];return result(code,label,'source_contract')
    if kind=='windows_event':
        channel=row.get('channel') or '';category=fields.get('category')
        if channel=='Security' and row.get('event_code') in {'1100','1102','4719'}:
            return result('audit_change','Windows 감사 중단·정책 변경','event_channel_and_code')
        if channel=='Security' and row.get('event_code') in {'4697','4698','4699','4700','4701','4702'}:
            return result('persistence_change','Windows 서비스·예약 작업 변경','event_channel_and_code')
        known={'authentication':'인증','privilege':'권한','account':'계정 변경','group':'그룹 변경',
               'process':'프로세스 실행','file':'파일 활동','configuration':'설정 변경','network':'네트워크 통신'}
        if category in known:return result(category,'Windows '+known[category],'interpreted_windows_event')
        channel_map={'Security':('security_audit','Windows 보안 감사'),'System':('system_change','Windows 시스템 변경'),
          'Microsoft-Windows-Windows Defender/Operational':('security_product','Windows Defender 보안'),
          'Microsoft-Windows-CodeIntegrity/Operational':('code_integrity','Windows 코드 무결성'),
          'Microsoft-Windows-Sysmon/Operational':('sysmon','Windows Sysmon'),
          'Microsoft-Windows-PowerShell/Operational':('script','Windows PowerShell 실행'),
          'PowerShellCore/Operational':('script','PowerShell 실행'),
          'Microsoft-Windows-TaskScheduler/Operational':('scheduled_task','Windows 예약 작업')}
        if channel in channel_map:
            code,label=channel_map[channel];return result(code,label,'event_channel')
        if channel.startswith('Microsoft-Windows-AppLocker/'):return result('application_control','Windows 실행 제어','event_channel')
        if channel.startswith('Microsoft-Windows-TerminalServices-'):return result('remote_access','Windows 원격 접속','event_channel')
        return result('windows_other','Windows 기타 이벤트','event_channel')
    path=(row.get('file_path') or '').replace('\\','/')
    if kind=='windows_file' and re.search(r'/System32/LogFiles/Firewall/pfirewall(?:_(?:domain|private|public))?\.log(?:\.[0-9]+)?$',path,re.I):
        return result('firewall','Windows 방화벽','source_path')
    if kind in ('linux_file','linux_journald'):
        if re.fullmatch(r'/var/log/(?:auth\.log|secure)(?:\.[0-9]+)?',path):return result('authentication','Linux 인증·권한','source_path')
        if re.fullmatch(r'/var/log/audit/audit\.log(?:\.[0-9]+)?',path):return result('security_audit','Linux 보안 감사','source_path')
        if re.fullmatch(r'/var/log/(?:ufw|fail2ban)\.log(?:\.[0-9]+)?',path):return result('firewall','Linux 접속 차단','source_path')
        if re.fullmatch(r'/var/log/(?:dpkg\.log|apt/history\.log|dnf\.rpm\.log|yum\.log)(?:\.[0-9]+)?',path):return result('package_change','Linux 패키지 변경','source_path')
        unit=row.get('journal_unit') or '';name=row.get('journal_identifier') or ''
        if name in ('sshd','sudo','su','polkitd','systemd-logind') or unit in ('ssh.service','sshd.service'):
            return result('authentication','Linux 인증·권한','journal_source')
        if name in ('audit','auditd','setroubleshoot'):return result('security_audit','Linux 보안 감사','journal_source')
        if name in ('cron','CRON','crond'):return result('scheduled_task','Linux 예약 작업','journal_source')
        if row.get('journal_transport') in ('audit','kernel'):return result('kernel_security','Linux 커널·보안 정책','journal_source')
        return result('linux_other','Linux 기타 기록','source_contract')
    return result('unknown','종류 미확인','insufficient_metadata')
