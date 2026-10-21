"""Metadata-only normalization with immutable raw-document provenance."""

import hashlib
import json
from datetime import datetime, timezone
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import document_reference, field
from cloud_soc.portal.security_detail import security_detail, address, text
from cloud_soc.privacy import REDACTED
from cloud_soc.parsers.linux_security import parse_linux_ssh, parse_linux_ssh_source, SSH_INVALID_USER_VERSION
from cloud_soc.parsers.linux_operational import parse_linux_operational, VERSION as LINUX_OPERATIONAL_VERSION, SUDO_SESSION_VERSION
from cloud_soc.normalizers.ecs import parse_syslog_timestamp
from cloud_soc.normalizers.time_context import raw_time_context, parse_utc_offset
from cloud_soc.web.metadata import VERSION as WEB_VERSION
from cloud_soc.web.scope import NORMALIZER_VERSION as SITE_VERSION, NORMALIZED_ADAPTER as SITE_ADAPTER, LEGACY_VERSION
from cloud_soc.web.modsecurity import VERSION as WAF_VERSION, ADAPTER as WAF_ADAPTER
from cloud_soc.parsers.security_mall import ADAPTER as MALL_ADAPTER, VERSION as MALL_VERSION
from cloud_soc.parsers.security_mall_edge import ADAPTER as EDGE_ADAPTER, VERSION as EDGE_VERSION

VERSION = "intake-v1"
NORMALIZED = "soc-normalized-v1"
RECORDS = "soc-processing-v1"
STATUS = "soc-pipeline-status"


def normalize(hit, processed_at, *, ssh_v2_start=None, web_version=LEGACY_VERSION):
    if web_version not in (SITE_VERSION, LEGACY_VERSION):
        raise ValueError('Unsupported generic web normalizer version')
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
    if detail['adapter'] == EDGE_ADAPTER:
        identifier = hashlib.sha256(json.dumps([EDGE_VERSION, reference], sort_keys=True).encode()).hexdigest()
        record.update(version=EDGE_VERSION, adapter=EDGE_ADAPTER)
        if detail['status'] != 'recognized':
            record.update(reason=detail['reason'])
            return identifier, record, None
        if not reference['index'].startswith('soc-host-raw-mall-edge-'):
            record.update(reason='source_scope_mismatch')
            return identifier, record, None
        values = detail['fields']
        access = values['stream'] == 'access'
        status = values.get('status_code', 0)
        outcome = ('failure' if status >= 400 else 'success' if status < 300 else 'unknown') if access else 'unknown'
        event = {'@timestamp': iso(occurred), 'organization': {'id': organization},
                 'host': {'id': field(source, 'host.id')}, 'service': {'name': values['service_name']},
                 'source': {'ip': values['source_ip']},
                 'event': {'id': field(source, 'event.id'), 'kind': 'event', 'category': ['web'],
                           'action': 'http_access' if access else 'waf_rule_match',
                           'outcome': outcome, 'ingested': iso(received)},
                 'http': {'request': {'id': values['request_id']}},
                 'cloud_soc': {'normalized_at': processed_at, 'normalizer_version': EDGE_VERSION,
                     'parse_status': 'recognized', 'detail': detail, 'security_mall_edge': values,
                     'provenance': {'schema_version': 1, 'raw': reference,
                         'time': {'basis': 'apache_access_timestamp' if access else 'modsecurity_audit_timestamp',
                                  'year_inferred': False, 'raw_is_protected_metadata': True}}}}
        if access:
            event['http']['request']['method'] = values['method']
            event['http']['response'] = {'status_code': status}
            event['url'] = {'path': values['path']}
            event['event']['duration'] = values['duration_us'] * 1000
        record.update(status='normalized', reason='recognized', normalized={'index': NORMALIZED, 'id': identifier})
        return identifier, record, event
    time_metadata = {"basis": "source_timestamp"}
    mall = detail["adapter"] == MALL_ADAPTER
    if mall:
        identifier = hashlib.sha256(json.dumps([MALL_VERSION, reference], sort_keys=True).encode()).hexdigest()
        record["version"] = MALL_VERSION
        if detail["status"] != "recognized":
            record.update(status=detail["status"], reason=detail["reason"], adapter=MALL_ADAPTER)
            return identifier, record, None
        host_id = field(source, "host.id")
        if not isinstance(host_id, str) or not 0 < len(host_id) <= 128 or text(host_id) != host_id:
            record["reason"] = "security_mall_collector_host_invalid"
            return identifier, record, None
        if parse_time(detail["fields"]["timestamp"]) != occurred:
            record["reason"] = "security_mall_time_mismatch"
            return identifier, record, None
        time_metadata = {"basis": "security_mall_audit_timestamp", "year_inferred": False}
    if detail['adapter'] == WAF_ADAPTER:
        identifier = hashlib.sha256(json.dumps([WAF_VERSION, reference], sort_keys=True).encode()).hexdigest()
        record['version'] = WAF_VERSION
        host_id = field(source, 'host.id')
        if not isinstance(host_id, str) or not 0 < len(host_id) <= 128 or host_id != host_id.strip() or text(host_id) != host_id:
            record.update(reason='web_collector_host_invalid', adapter=WAF_ADAPTER)
            return identifier, record, None
        time_metadata = {'basis': 'modsecurity_local_time_with_explicit_offset', 'year_inferred': False,
                         'raw_is_protected_metadata': True}
    if detail['adapter'] == 'web_access_agent_v1':
        version = web_version
        identifier = hashlib.sha256(json.dumps([version, reference], sort_keys=True).encode()).hexdigest()
        record['version'] = version
        time_metadata = {'basis':'access_timestamp','year_inferred':False,'raw_is_protected_metadata':True}
        if version == SITE_VERSION:
            host_id = field(source, 'host.id')
            if not isinstance(host_id, str) or not 0 < len(host_id) <= 128 or host_id != host_id.strip() or text(host_id) != host_id:
                record.update(reason='web_collector_host_invalid', adapter=SITE_ADAPTER)
                return identifier, record, None
            detail['adapter'] = SITE_ADAPTER
    if detail['adapter'] == 'web_access_metadata_v1':
        identifier = hashlib.sha256(json.dumps([WEB_VERSION, reference], sort_keys=True).encode()).hexdigest()
        record['version'] = WEB_VERSION
        time_metadata = {'basis':'apache_access_timestamp','year_inferred':False,'raw_is_protected_metadata':True}
    modern_ssh = (parse_linux_ssh_source(source) if detail["status"] == "unsupported"
                  and (ssh_v2_start is None or received >= ssh_v2_start) else None)
    if modern_ssh:
        occurred = modern_ssh.pop('occurred')
        origin = modern_ssh.pop('origin')
        time_metadata = {'basis': {'journald': 'journald_timestamp', 'rfc3339': 'rfc3339_timestamp',
                                   'rfc3164': 'syslog_timestamp_with_collector_timezone'}[origin],
                         'year_inferred': origin == 'rfc3164'}
        ssh_adapter = modern_ssh['adapter']
        if ssh_adapter == 'linux_ssh_invalid_user_v1':
            record['version'] = SSH_INVALID_USER_VERSION
            identifier = hashlib.sha256(json.dumps([record['version'], reference], sort_keys=True).encode()).hexdigest()
        detail = {'adapter': ssh_adapter, 'status': 'recognized', 'fields': modern_ssh,
                  'missing': [], 'limitations': ['metadata_only', 'authentication_failure_not_attack_confirmation']}
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
            if detail['adapter'] == 'linux_sudo_session_v1':
                version = SUDO_SESSION_VERSION
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
    expected = {MALL_ADAPTER: "soc-host-raw-", "web_access_agent_v1":"soc-host-raw-", "web_access_metadata_v1":"soc-host-raw-web-", "windows_security_v1": "soc-host-raw-", "sysmon_v1": "soc-host-raw-", "linux_ssh_v1": "soc-host-raw-", "linux_ssh_v2": "soc-host-raw-", "linux_ssh_invalid_user_v1": "soc-host-raw-",
                "linux_operational_v1": "soc-host-raw-", "linux_sudo_session_v1": "soc-host-raw-", "linux_unclassified_v1": "soc-host-raw-", "packetbeat_metadata_v1": "soc-network-", "aws_cloudtrail_metadata_v1": "soc-cloud-aws-", "oci_audit_metadata_v1": "soc-cloud-oci-"}
    expected[SITE_ADAPTER] = 'soc-host-raw-'
    expected[WAF_ADAPTER] = 'soc-host-raw-'
    if not reference["index"].startswith(expected[detail["adapter"]]):
        record.update(status="invalid", reason="source_scope_mismatch")
        return identifier, record, None
    values = detail["fields"]
    user_name = (values.get("target_user") or values.get("actor")) if values["category"] == "authentication" else values.get("actor")
    if detail['adapter'] == 'linux_sudo_session_v1':
        user_name = values['actor']
    category = {"account": "iam", "group": "iam", "privilege": "iam", "object": "file", "cloud": "configuration"}.get(values["category"], values["category"])
    event = {"@timestamp": iso(occurred), "organization": {"id": organization},
             "event": {"kind": "event", "category": [category] if category else [], "action": values.get("api") or values["action"],
                       "outcome": values["outcome"], "ingested": iso(received)},
             "cloud_soc": {"normalized_at": processed_at, "normalizer_version": record["version"], "parse_status": detail["status"],
                           "detail": detail, "provenance": {"schema_version": 1, "raw": reference, "time": time_metadata}}}
    if mall:
        # Only the collector envelope supplies organization/host identity. Do not
        # inherit user/cloud/destination/event claims or raw text from the input.
        event["event"]["id"] = values["event_id"]
        event["service"] = {"name": values["service_name"]}
        event["host"] = {"id": host_id}
        event["source"] = {"ip": values["source_ip"]}
        if "request_id" in values:
            event["http"] = {"request": {"id": values["request_id"]}}
        event["cloud_soc"]["security_mall"] = {
            name: values[name] for name in ("schema_version", "account_id", "account_key_id",
                                           "resource_type", "authorization_reason") if name in values}
        record.update(status="normalized", reason="recognized", adapter=MALL_ADAPTER,
                      normalized={"index": NORMALIZED, "id": identifier})
        return identifier, record, event
    if detail['adapter'] in (SITE_ADAPTER, WAF_ADAPTER):
        event['service'] = {'id': values['service_id']}
        service_name = text(field(source, 'service.name'))
        if service_name not in (None, REDACTED):
            event['service']['name'] = service_name
        event['http'] = {'request': {'method': values['http_method']},
                         'response': {'status_code': values['http_status']}}
        if detail['adapter'] == WAF_ADAPTER:
            event['http']['request']['id'] = values['request_id']
            event['waf'] = {'schema': WAF_VERSION, 'engine_mode': values['engine_mode'],
                            'interruption': values['interruption'], 'rules': values['rules']}
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
    if modern_ssh:
        host_id = field(source, 'host.id')
        if isinstance(host_id, str) and 0 < len(host_id) <= 128 and text(host_id) == host_id:
            # Millisecond precision is shared by journald and its ISO file mirror.
            identity = ['ssh-observation-v1', organization, host_id, occurred.isoformat(timespec='milliseconds'),
                        values['process_pid'], values['action'], values['outcome'], values['target_user'],
                        values['source_ip'], values['source_port'], values['auth_method']]
            event['cloud_soc']['observation'] = {'version': 1, 'id': hashlib.sha256(json.dumps(identity).encode()).hexdigest(),
                                                'origin': origin}
    record.update(status="normalized", reason=detail["status"], adapter=detail["adapter"],
                  normalized={"index": NORMALIZED, "id": identifier})
    return identifier, record, event
