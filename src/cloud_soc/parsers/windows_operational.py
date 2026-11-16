"""Event meanings keyed by exact Windows channel, provider, and event ID."""

VERSION = 'windows-operational-v1'
ADAPTER = 'windows_operational_v1'
DEFENDER = 'Microsoft-Windows-Windows Defender'
POWERSHELL = 'Microsoft-Windows-PowerShell'

# These describe the provider's observation. They do not assign an attack verdict.
RULES = {
    ('System', 'Microsoft-Windows-FilterManager'): {
        '6': ('configuration', 'windows_filesystem_filter_registered', 'unknown'),
    },
    ('System', 'Microsoft-Windows-Kernel-General'): {
        '1': ('host', 'windows_system_time_changed', 'unknown'),
        '16': ('host', 'windows_kernel_general_report', 'unknown'),
        '24': ('host', 'windows_kernel_general_report', 'unknown'),
    },
    ('System', 'Microsoft-Windows-Time-Service'): {
        '37': ('host', 'windows_time_source_report', 'unknown'),
    },
    ('System', 'Microsoft-Windows-Kernel-Processor-Power'): {
        '55': ('host', 'windows_processor_power_report', 'unknown'),
    },
    ('System', 'Microsoft-Windows-Dhcp-Client'): {
        '50036': ('network', 'windows_dhcp_client_report', 'unknown'),
    },
    ('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational',
     'Microsoft-Windows-TerminalServices-RemoteConnectionManager'): {
        '263': ('network', 'windows_rdp_connection_manager_report', 'unknown'),
        '258': ('network', 'windows_rdp_connection_manager_report', 'unknown'),
        '20523': ('network', 'windows_rdp_connection_manager_report', 'unknown'),
    },
    ('Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
     'Microsoft-Windows-TerminalServices-LocalSessionManager'): {
        '34': ('authentication', 'windows_rdp_session_manager_report', 'unknown'),
        '54': ('authentication', 'windows_rdp_session_manager_report', 'unknown'),
    },
    ('System', 'Service Control Manager'): {
        '7036': ('configuration', 'windows_service_state_reported', 'unknown'),
        '7040': ('configuration', 'windows_service_start_type_changed', 'unknown'),
        '7045': ('configuration', 'windows_service_installed', 'unknown'),
    },
    ('System', 'Microsoft-Windows-DistributedCOM'): {
        '10016': ('configuration', 'windows_dcom_permission_reported', 'unknown'),
    },
    ('System', 'EventLog'): {
        '6013': ('host', 'windows_uptime_reported', 'unknown'),
    },
    ('System', 'Microsoft-Windows-WindowsUpdateClient'): {
        '19': ('configuration', 'windows_update_installed', 'success'),
        '20': ('configuration', 'windows_update_install_failed', 'failure'),
        '43': ('configuration', 'windows_update_install_started', 'unknown'),
        '44': ('configuration', 'windows_update_download_started', 'unknown'),
    },
    (POWERSHELL + '/Operational', POWERSHELL): {
        '4100': ('process', 'powershell_operational_report', 'unknown'),
        '4103': ('process', 'powershell_module_activity_logged', 'unknown'),
        '4104': ('process', 'powershell_script_block_logged', 'unknown'),
        **dict.fromkeys(('40961', '40962', '53504'), ('process', 'powershell_runtime_event_logged', 'unknown')),
    },
    ('PowerShellCore/Operational', 'PowerShellCore'): {
        '4103': ('process', 'powershell_module_activity_logged', 'unknown'),
        '4104': ('process', 'powershell_script_block_logged', 'unknown'),
    },
    (DEFENDER + '/Operational', DEFENDER): {
        '2010': ('configuration', 'defender_cloud_intelligence_received', 'success'),
        '1116': ('malware', 'defender_threat_reported', 'unknown'),
        '1117': ('malware', 'defender_response_reported', 'unknown'),
        '1118': ('malware', 'defender_response_failed', 'failure'),
        '1150': ('host', 'defender_service_health_reported', 'unknown'),
        '1151': ('host', 'defender_health_reported', 'unknown'),
        '2000': ('configuration', 'defender_signatures_updated', 'success'),
        '2001': ('configuration', 'defender_signature_update_failed', 'failure'),
        '5007': ('configuration', 'defender_configuration_changed', 'unknown'),
    },
    ('Security', 'Microsoft-Windows-Security-Auditing'): {
        '5379': ('authentication', 'windows_credentials_read_reported', 'unknown'),
        '4634': ('authentication', 'windows_logoff_reported', 'unknown'),
        '4648': ('authentication', 'windows_explicit_credentials_attempted', 'unknown'),
        '4798': ('iam', 'windows_user_groups_enumerated', 'unknown'),
        '4799': ('iam', 'windows_group_members_enumerated', 'unknown'),
        '4735': ('iam', 'windows_local_group_changed', 'success'),
        '4738': ('iam', 'windows_account_changed', 'success'),
        '4781': ('iam', 'windows_account_renamed', 'success'),
        '4907': ('configuration', 'windows_object_audit_settings_changed', 'success'),
        '4776': ('authentication', 'windows_ntlm_validation', 'unknown'),
        '5058': ('configuration', 'windows_key_file_operation', 'unknown'),
        '5059': ('configuration', 'windows_key_migration_report', 'unknown'),
        '4616': ('host', 'windows_system_time_changed', 'unknown'),
        '5061': ('configuration', 'windows_crypto_operation', 'unknown'),
    },
    ('Security', 'Microsoft-Windows-Eventlog'): {
        '1100': ('host', 'windows_event_log_stopped', 'unknown'),
        '1102': ('host', 'windows_security_audit_cleared', 'unknown'),
    },
}


def interpret(channel, provider, code):
    if not all(isinstance(value, str) for value in (channel, provider, code)):
        return None
    return RULES.get((channel, provider), {}).get(code)
