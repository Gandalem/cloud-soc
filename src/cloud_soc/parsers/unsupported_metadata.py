"""Strict metadata-only adapters for selected previously unsupported host audit records.

No raw message bodies, script blocks, command lines, security setting values, or
event_data payloads are copied into normalized events. An observation is not an
intrusion confirmation or a claim about process execution.
"""
import re

from cloud_soc.portal.log_contract import field
from cloud_soc.privacy import REDACTED, display

VERSION = "selected-host-audit-v1"
LINUX_TYPES = {
    "SERVICE_START": ("configuration", "audit_service_started"),
    "SERVICE_STOP": ("configuration", "audit_service_stopped"),
    "AVC": ("configuration", "selinux_avc_observed"),
    "USER_AVC": ("configuration", "selinux_user_avc_observed"),
    "SECCOMP": ("configuration", "seccomp_audit_observed"),
    "BPF": ("configuration", "bpf_audit_observed"),
}
WINDOWS_TYPES = {
    ("Security", "Microsoft-Windows-Security-Auditing", "5379"):
        ("iam", "credential_manager_read_audit"),
    ("Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell", "4104"):
        ("process", "powershell_script_block_logged"),
    ("Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-Windows Defender", "5007"):
        ("configuration", "defender_configuration_changed"),
    ("System", "Service Control Manager", "7036"):
        ("configuration", "windows_service_state_observed"),
}


def selected_host_audit(source):
    """Return a recognized metadata observation, or None outside the exact scope."""
    if not isinstance(source, dict) or field(source, "agent.type") != "filebeat":
        return None
    kind = field(source, "labels.log_source")
    if kind == "linux_journald" and field(source, "systemd.transport") == "audit":
        name = field(source, "journald.custom.audit_type_name")
        if not isinstance(name, str) or name not in LINUX_TYPES:
            return None
        category, action = LINUX_TYPES[name]
        fields = {"category": category, "action": action,
                  "outcome": "unknown", "audit_type": name}
        unit = field(source, "journald.custom.audit_field_unit")
        if isinstance(unit, str) and re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", unit):
            fields["service_unit"] = unit
        return {
            "adapter": "linux_audit_metadata_v1", "status": "recognized",
            "fields": fields, "missing": [],
            "limitations": ["metadata_only", "audit_event_not_attack_confirmation",
                            "audit_result_and_identity_not_inferred",
                            "message_and_kernel_audit_payload_excluded"],
        }
    if kind != "windows_event":
        return None
    channel = field(source, "winlog.channel")
    provider = field(source, "winlog.provider_name")
    raw_id = field(source, "winlog.event_id")
    if type(raw_id) is int:
        code = str(raw_id)
    elif isinstance(raw_id, str) and re.fullmatch(r"[0-9]{1,6}", raw_id):
        code = raw_id
    else:
        return None
    ecs_code = field(source, "event.code")
    if ecs_code is not None and str(ecs_code) != code:
        return None
    pair = WINDOWS_TYPES.get((channel, provider, code))
    if pair is None:
        return None
    category, action = pair
    fields = {"category": category, "action": action,
              "outcome": "unknown", "event_code": code}
    missing = []
    if code == "5379":
        actor = field(source, "winlog.event_data.SubjectUserName")
        actor = display(actor) if isinstance(actor, str) and actor else None
        if actor in (None, REDACTED):
            missing.append("actor")
        else:
            fields["actor"] = actor
    return {
        "adapter": "windows_observation_v1",
        "status": "partial" if missing else "recognized",
        "fields": fields, "missing": missing,
        "limitations": ["metadata_only", "event_record_not_attack_confirmation",
                        "script_and_configuration_values_excluded",
                        "process_execution_or_credential_exfiltration_not_inferred"],
    }
