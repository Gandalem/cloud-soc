"""Versioned, read-only interpretation of explicitly selected audit metadata.

This is not an alert engine or a claim that host auditing is enabled. Raw text,
command lines, task XML and file contents are never requested by this adapter.
"""

from ipaddress import ip_address
import re

from cloud_soc.portal.log_contract import field
from cloud_soc.portal.privacy import display, REDACTED

WINDOWS_FIELDS = (
    "SubjectUserName", "TargetUserName", "TargetDomainName", "MemberSid",
    "LogonType", "IpAddress", "IpPort", "PrivilegeList", "NewProcessId",
    "NewProcessName", "ProcessId", "ProcessName", "ParentProcessName",
    "ObjectType", "ObjectName", "AccessMask", "TaskName", "ServiceName",
    "ProcessGuid", "ParentProcessGuid", "ParentProcessId", "Image", "ParentImage",
    "User", "Hashes", "TargetFilename", "SourceIp", "SourcePort",
    "DestinationIp", "DestinationPort", "Protocol",
)
DETAIL_FIELDS = (
    "winlog.event_id", "winlog.provider_name", "host.id",
    *("winlog.event_data." + name for name in WINDOWS_FIELDS),
    "source.port", "destination.port", "network.bytes", "network.packets",
    "event.start", "event.end", "dns.question.name", "dns.question.type",
    "tls.client.server_name", "tls.version", "flow.id",
    "event.id", "event.provider", "source.address", "aws.cloudtrail.schema",
    "aws.cloudtrail.identity_arn", "aws.cloudtrail.identity_type", "aws.cloudtrail.identity_account",
    "aws.cloudtrail.session_issuer_arn", "aws.cloudtrail.resources.arn", "aws.cloudtrail.resources_truncated",
    "aws.cloudtrail.error_code", "aws.cloudtrail.outcome_basis", "aws.cloudtrail.management_only",
    "aws.cloudtrail.target_user", "aws.cloudtrail.target_role", "aws.cloudtrail.target_group_id",
    "aws.cloudtrail.target_policy_arn", "aws.cloudtrail.identity_invoked_by",
    *("oci.audit." + name for name in ("schema", "compartment_id", "compartment_name", "resource_id", "resource_name",
      "identity_tenancy", "auth_type", "caller_id", "caller_name", "request_id", "http_method", "http_status", "outcome_basis", "event_type", "grouping_id")),
)
SECURITY_EVENTS = {
    "4624": ("authentication", "login", "success"),
    "4625": ("authentication", "login", "failure"),
    "4672": ("privilege", "special_privileges_assigned", "success"),
    "4688": ("process", "process_created", "success"),
    "4720": ("account", "account_created", "unknown"),
    "4726": ("account", "account_deleted", "unknown"),
    "4732": ("group", "local_group_member_added", "unknown"),
    "4733": ("group", "local_group_member_removed", "unknown"),
    "4663": ("file", "access_right_used", "success"),
    "4670": ("configuration", "object_permissions_changed", "unknown"),
    "4697": ("configuration", "service_installed", "unknown"),
    "4698": ("configuration", "scheduled_task_created", "unknown"),
    "4702": ("configuration", "scheduled_task_updated", "unknown"),
    "4719": ("configuration", "audit_policy_changed", "unknown"),
}
SYSMON_EVENTS = {
    "1": ("process", "process_created", "success"),
    "3": ("network", "connection_observed", "unknown"),
    "11": ("file", "file_created_or_overwritten", "unknown"),
    "26": ("file", "file_delete_detected", "unknown"),
}


def text(value):
    if not isinstance(value, str) or not value or value == "-":
        return None
    if any(ord(char) < 32 for char in value):
        return REDACTED
    return display(value)


def number(value, maximum=2**63 - 1):
    if type(value) is int:
        result = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})", value):
        result = int(value, 16 if value.startswith("0x") else 10)
    else:
        return None
    return result if 0 <= result <= maximum else None


def address(value):
    if not isinstance(value, str) or "%" in value:
        return None
    try:
        return str(ip_address(value))
    except ValueError:
        return None


def guid(value):
    if not isinstance(value, str) or len(value) > 38:
        return None
    if value.startswith("{") and value.endswith("}"):
        value = value[1:-1]
    value = value.lower()
    if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value) and value.replace("-", "").strip("0"):
        return value
    return None


def security_detail(source):
    result = {"version": 1, "status": "unsupported", "adapter": None,
              "audit_configuration": "not_checked", "fields": {}, "missing": [],
              "process_link": "not_established", "limitations": ["not_a_detection"]}
    if not isinstance(source, dict):
        return result
    get = lambda path: field(source, path)
    if get("labels.log_source") == "oci_audit" and get("cloud.provider") == "oci":
        if get("oci.audit.schema") != 1:
            return result
        result.update(status="recognized", adapter="oci_audit_metadata_v1")
        values = {"category": "cloud", "action": "management_api_call", "outcome": get("event.outcome")}
        if values["outcome"] not in ("success", "failure", "unknown"):
            values["outcome"] = "unknown"
        for key, path in {
            "api": "event.action", "event_id": "event.id", "provider": "event.provider",
            "cloud_account": "cloud.account.id", "cloud_region": "cloud.region", "source_address": "source.address",
            **{name: "oci.audit." + name for name in ("compartment_id", "compartment_name", "resource_id", "resource_name",
                "identity_tenancy", "auth_type", "caller_id", "caller_name", "request_id", "http_method", "outcome_basis", "event_type", "grouping_id")},
        }.items():
            values[key] = text(get(path))
        values["actor"] = text(get("user.name")) or text(get("user.id")) or values["caller_id"] or values["caller_name"]
        values["principal_id"] = text(get("user.id"))
        values["http_status"] = number(get("oci.audit.http_status"), 599)
        result["fields"] = values
        result["missing"] = [key for key in ("actor", "api", "cloud_account", "cloud_region", "event_id", "compartment_id") if values[key] in (None, REDACTED)]
        if result["missing"]:
            result["status"] = "partial"
        result["limitations"] += ["oci_audit_not_object_or_identity_domain_access", "api_result_not_resource_effect", "region_from_collection_scope"]
        return result
    if get("labels.log_source") == "aws_cloudtrail" and get("cloud.provider") == "aws":
        if get("aws.cloudtrail.schema") != 1 or get("aws.cloudtrail.management_only") is not True:
            return result
        result.update(status="recognized", adapter="aws_cloudtrail_metadata_v1")
        values = {"category": "cloud", "action": "management_api_call", "outcome": get("event.outcome")}
        if values["outcome"] not in ("success", "failure", "unknown"):
            values["outcome"] = "unknown"
        for key, path in {
            "api": "event.action", "event_id": "event.id", "provider": "event.provider",
            "cloud_account": "cloud.account.id", "cloud_region": "cloud.region",
            "identity_type": "aws.cloudtrail.identity_type", "identity_arn": "aws.cloudtrail.identity_arn",
            "identity_invoked_by": "aws.cloudtrail.identity_invoked_by", "target_policy_arn": "aws.cloudtrail.target_policy_arn",
            "identity_account": "aws.cloudtrail.identity_account", "session_issuer_arn": "aws.cloudtrail.session_issuer_arn",
            "source_address": "source.address", "target_user": "aws.cloudtrail.target_user",
            "target_role": "aws.cloudtrail.target_role", "target_group_id": "aws.cloudtrail.target_group_id",
            "error_code": "aws.cloudtrail.error_code", "outcome_basis": "aws.cloudtrail.outcome_basis",
        }.items():
            values[key] = text(get(path))
        values["actor"] = text(get("user.name")) or text(get("user.id")) or values["identity_arn"] or values["identity_invoked_by"]
        resources = get("aws.cloudtrail.resources")
        values["resource_arns"] = [text(item.get("arn")) for item in resources[:20] if isinstance(item, dict)] if isinstance(resources, list) else []
        values["resource_arns"] = [item for item in values["resource_arns"] if item]
        result["fields"] = values
        result["missing"] = [key for key in ("actor", "api", "cloud_account", "cloud_region", "event_id") if values[key] in (None, REDACTED)]
        if result["missing"]:
            result["status"] = "partial"
        result["limitations"] += ["management_events_not_object_access", "api_result_not_resource_effect"]
        if get("aws.cloudtrail.resources_truncated") is True:
            result["limitations"].append("resource_list_truncated")
        return result
    channel, provider = get("winlog.channel"), get("winlog.provider_name")
    raw_code = get("winlog.event_id")
    code = str(raw_code) if type(raw_code) is int else raw_code
    # Reject conflicting identifiers instead of silently choosing one.
    ecs_code = get("event.code")
    if channel in ("Security", "Microsoft-Windows-Sysmon/Operational") and ecs_code is not None and str(ecs_code) != code:
        result["limitations"].append("conflicting_event_code")
        return result
    security = channel == "Security" and provider == "Microsoft-Windows-Security-Auditing"
    sysmon = channel == "Microsoft-Windows-Sysmon/Operational" and provider == "Microsoft-Windows-Sysmon"
    table = SECURITY_EVENTS if security else SYSMON_EVENTS if sysmon else {}
    if isinstance(code, str) and code in table:
        data = get("winlog.event_data")
        if not isinstance(data, dict):
            data = {}
        d = lambda name: text(data.get(name))
        category, action, outcome = table[code]
        values = {"category": category, "action": action, "outcome": outcome,
                  "actor": d("SubjectUserName") if security else d("User")}
        required = ["actor"]
        result.update(status="recognized", adapter="windows_security_v1" if security else "sysmon_v1")
        if security:
            if code in {"4624", "4625", "4720", "4726"}:
                values.update(target_user=d("TargetUserName"), target_domain=d("TargetDomainName"))
                required = ["target_user"] if code in {"4624", "4625"} else ["actor", "target_user"]
            if code in {"4624", "4625"}:
                values.update(logon_type=number(data.get("LogonType"), 255),
                              source_ip=address(data.get("IpAddress")), source_port=number(data.get("IpPort"), 65535))
                required.append("logon_type")
            if code in {"4732", "4733"}:
                values.update(group=d("TargetUserName"), member_sid=d("MemberSid"))
                required += ["group", "member_sid"]
            if code == "4672":
                values["privileges"] = d("PrivilegeList")
                result["limitations"].append("privilege_assignment_not_use")
            if code == "4688":
                values.update(process_path=d("NewProcessName"), process_pid=number(data.get("NewProcessId")),
                              parent_path=d("ParentProcessName"), parent_pid=number(data.get("ProcessId")),
                              execution_user=d("TargetUserName"))
                required += ["process_path", "process_pid"]
                result["limitations"].append("pid_not_stable_identity")
            if code in {"4663", "4670"}:
                values.update(object_type=d("ObjectType"), object_path=d("ObjectName"),
                              process_path=d("ProcessName"), process_pid=number(data.get("ProcessId")))
                required += ["object_path", "object_type"]
            if code == "4663":
                mask = number(data.get("AccessMask"), 2**32 - 1)
                values["access_mask"] = mask
                required.append("access_mask")
                # A File object can be a directory: do not assert file contents were read.
                if values["object_type"] == "File" and mask is not None:
                    values["access_rights"] = [name for bit, name in (
                        (1, "read_data_or_list_directory"), (2, "write_data_or_add_file"),
                        (4, "append_data_or_add_subdirectory"), (0x10000, "delete_right"),
                        (0x40000, "write_dacl"), (0x80000, "write_owner"),
                    ) if mask & bit]
                elif values["object_type"] != "File":
                    values["category"] = "object"
                result["limitations"].append("access_right_not_exfiltration_or_completed_delete")
            if code in {"4698", "4702"}:
                values["task_name"] = d("TaskName")
                required.append("task_name")
            if code == "4697":
                values["service_name"] = d("ServiceName")
                required.append("service_name")
        else:
            values.update(process_path=d("Image"), process_pid=number(data.get("ProcessId")),
                          process_guid=guid(data.get("ProcessGuid")))
            required += ["process_guid", "process_path"]
            if code == "1":
                values.update(parent_path=d("ParentImage"), parent_pid=number(data.get("ParentProcessId")),
                              parent_guid=guid(data.get("ParentProcessGuid")))
                hashes = data.get("Hashes")
                match = re.search(r"(?:^|,)SHA256=([a-fA-F0-9]{64})(?:,|$)", hashes) if isinstance(hashes, str) and len(hashes) <= 4096 else None
                values["sha256"] = match[1].lower() if match else None
            if code in {"11", "26"}:
                values["object_path"] = d("TargetFilename")
                required.append("object_path")
                result["limitations"].append("not_file_read_audit")
            if code == "3":
                values.update(source_ip=address(data.get("SourceIp")), destination_ip=address(data.get("DestinationIp")),
                              source_port=number(data.get("SourcePort"), 65535), destination_port=number(data.get("DestinationPort"), 65535),
                              protocol=d("Protocol"))
                required += ["source_ip", "destination_ip"]
            scope = [text(get(path)) for path in ("organization.id", "host.id")]
            if values["process_guid"] and all(value and value != REDACTED for value in scope):
                result["process_link"] = "guid_in_same_host_event"
                values.update(identity_organization=scope[0], identity_host=scope[1])
        result["fields"] = values
        result["missing"] = [key for key in required if values.get(key) in (None, REDACTED)]
        if result["missing"]:
            result["status"] = "partial"
        return result
    if get("agent.type") == "packetbeat" and get("labels.log_source") == "network_packetbeat":
        result.update(status="recognized", adapter="packetbeat_metadata_v1")
        values = {"category": "network", "action": "traffic_observed", "outcome": "unknown"}
        for key, path in {"source_ip": "source.ip", "destination_ip": "destination.ip"}.items():
            values[key] = address(get(path))
        for key, path, maximum in (("source_port", "source.port", 65535), ("destination_port", "destination.port", 65535),
                                   ("bytes", "network.bytes", 2**63 - 1), ("packets", "network.packets", 2**63 - 1)):
            values[key] = number(get(path), maximum)
        for key, path in {"dns_name": "dns.question.name", "dns_type": "dns.question.type", "tls_server": "tls.client.server_name",
                          "tls_version": "tls.version", "flow_id": "flow.id", "protocol": "network.protocol",
                          "transport": "network.transport", "start": "event.start", "end": "event.end"}.items():
            values[key] = text(get(path))
        final = get("flow.final")
        values["flow_final"] = final if type(final) is bool else None
        result["fields"] = values
        result["limitations"] += ["no_process_or_file_attribution", "flow_counters_cumulative_do_not_sum_reports"]
        result["missing"] = [key for key in ("source_ip", "destination_ip") if values[key] is None]
        if result["missing"]:
            result["status"] = "partial"
    return result
