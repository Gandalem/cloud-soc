"""Metadata-only normalization with immutable raw-document provenance."""

import hashlib
import json
from datetime import datetime, timezone
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import document_reference, field
from cloud_soc.portal.security_detail import security_detail, address, text
from cloud_soc.privacy import REDACTED
from cloud_soc.parsers.linux_security import parse_linux_ssh
from cloud_soc.parsers.linux_operational import parse_linux_operational, VERSION as LINUX_OPERATIONAL_VERSION
from cloud_soc.normalizers.ecs import parse_syslog_timestamp
from cloud_soc.normalizers.time_context import raw_time_context, parse_utc_offset

VERSION = "intake-v1"
NORMALIZED = "soc-normalized-v1"
RECORDS = "soc-processing-v1"
STATUS = "soc-pipeline-status"


def normalize(hit, processed_at):
    reference = document_reference(hit.get("_index"), hit.get("_id"))
    if reference is None:
        raise ValueError("Invalid raw reference")
    identifier = hashlib.sha256(json.dumps([VERSION, reference], sort_keys=True).encode()).hexdigest()
    source = hit.get("_source")
    if not isinstance(source, dict):
        source = {}
    received, occurred = (parse_time(field(source, path)) for path in ("event.ingested", "@timestamp"))
    raw_organization = field(source, "organization.id")
    organization = text(raw_organization)
    record = {"@timestamp": processed_at, "version": VERSION, "status": "invalid",
              "reason": "missing_scope_or_time", "raw": reference,
              "event": {"ingested": iso(received) if received else None}}
    if not received or not occurred or not organization or organization == REDACTED or organization != raw_organization:
        return identifier, record, None
    detail = security_detail(source)
    time_metadata = {"basis": "source_timestamp"}
    if detail["status"] == "unsupported":
        operational = parse_linux_operational(source)
        if operational:
            time_text = operational.pop("time_text", None)
            access_time = operational.pop("access_time", None)
            if access_time:
                try:
                    # Month abbreviations are parsed independently of the host locale.
                    day, month, rest = access_time.split("/", 2)
                    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
                    year_time, offset = rest.split(" ")
                    year, hour, minute, second = map(int, year_time.split(":"))
                    occurred = datetime(year, months.index(month) + 1, int(day), hour, minute, second,
                        tzinfo=parse_utc_offset(offset[:3] + ":" + offset[3:])).astimezone(timezone.utc)
                    time_metadata = {"basis": "http_access_timestamp", "year_inferred": False}
                except (ValueError, TypeError):
                    record["reason"] = "linux_time_invalid"
                    return identifier, record, None
            if time_text:
                if not field(source, "event.timezone"):
                    record["reason"] = "linux_timezone_missing"
                    return identifier, record, None
                try:
                    ref, zone, time_metadata = raw_time_context(source)
                    occurred = parse_syslog_timestamp(time_text, reference_time=ref, source_timezone=zone)
                except (ValueError, TypeError):
                    record["reason"] = "linux_time_invalid"
                    return identifier, record, None
            detail = operational
            version = ("linux-unclassified-v1" if detail["adapter"] == "linux_unclassified_v1"
                       else LINUX_OPERATIONAL_VERSION)
            if detail["adapter"] == "linux_unclassified_v1":
                time_metadata = {"basis": "collector_timestamp", "source_event_time_known": False}
            identifier = hashlib.sha256(json.dumps([version, reference], sort_keys=True).encode()).hexdigest()
            record["version"] = version
    if detail["status"] == "unsupported" and field(source, "labels.log_source") in ("linux_file", "linux_journald", "linux_auth"):
        parsed = parse_linux_ssh(source.get("message"))
        if parsed:
            # RFC3164 has neither year nor zone: require an explicit zone, never guess UTC.
            if not field(source, "event.timezone"):
                record["reason"] = "ssh_timezone_missing"
                return identifier, record, None
            try:
                ref, zone, time_metadata = raw_time_context(source)
                occurred = parse_syslog_timestamp(parsed["time_text"], reference_time=ref, source_timezone=zone)
            except (ValueError, TypeError):
                record["reason"] = "ssh_time_invalid"
                return identifier, record, None
            parsed["protocol"] = "ssh"
            detail = {"adapter": "linux_ssh_v1", "status": "recognized", "fields": parsed,
                      "missing": [], "limitations": ["syslog_year_inferred"]}
    if detail["status"] == "unsupported":
        record.update(status="unsupported", reason="adapter_not_supported")
        return identifier, record, None
    expected = {"windows_security_v1": "soc-host-raw-", "sysmon_v1": "soc-host-raw-", "linux_ssh_v1": "soc-host-raw-",
                "linux_operational_v1": "soc-host-raw-", "linux_unclassified_v1": "soc-host-raw-", "packetbeat_metadata_v1": "soc-network-", "aws_cloudtrail_metadata_v1": "soc-cloud-aws-", "oci_audit_metadata_v1": "soc-cloud-oci-"}
    if not reference["index"].startswith(expected[detail["adapter"]]):
        record.update(status="invalid", reason="source_scope_mismatch")
        return identifier, record, None
    values = detail["fields"]
    user_name = (values.get("target_user") or values.get("actor")) if values["category"] == "authentication" else values.get("actor")
    category = {"account": "iam", "group": "iam", "privilege": "iam", "object": "file", "cloud": "configuration"}.get(values["category"], values["category"])
    event = {"@timestamp": iso(occurred), "organization": {"id": organization},
             "event": {"kind": "event", "category": [category] if category else [], "action": values.get("api") or values["action"],
                       "outcome": values["outcome"], "ingested": iso(received)},
             "cloud_soc": {"normalized_at": processed_at, "normalizer_version": record["version"], "parse_status": detail["status"],
                           "detail": detail, "provenance": {"schema_version": 1, "raw": reference, "time": time_metadata}}}
    for name in ("source", "destination"):
        ip = address(values.get(name + "_ip") or field(source, name + ".ip"))
        if ip:
            event[name] = {"ip": ip}
            if values.get(name + "_port") is not None:
                event[name]["port"] = values[name + "_port"]
    for group, mapping in {
        "host": {"id": field(source, "host.id"), "name": field(source, "host.name")},
        "user": {"name": user_name, "id": field(source, "user.id")},
        "network": {"protocol": values.get("protocol"), "transport": values.get("transport")},
        "cloud": {"provider": field(source, "cloud.provider"), "region": field(source, "cloud.region")},
    }.items():
        selected = {key: text(value) for key, value in mapping.items() if text(value) not in (None, REDACTED)}
        if selected:
            event[group] = selected
    account = text(field(source, "cloud.account.id"))
    if "cloud" in event and account not in (None, REDACTED):
        event["cloud"]["account"] = {"id": account}
    for key in ("code", "dataset", "provider"):
        value = text(field(source, "event." + key))
        if value not in (None, REDACTED):
            event["event"][key] = value
    if values.get("process_pid") is not None:
        event["process"] = {"pid": values["process_pid"]}
        if values.get("process_path") not in (None, REDACTED):
            event["process"]["executable"] = values["process_path"]
    record.update(status="normalized", reason=detail["status"], adapter=detail["adapter"],
                  normalized={"index": NORMALIZED, "id": identifier})
    return identifier, record, event
