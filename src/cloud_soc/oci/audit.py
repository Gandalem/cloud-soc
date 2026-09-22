"""Project OCI SDK snake_case AuditEvent dictionaries to selected metadata."""

import hashlib
from ipaddress import ip_address
import re

from cloud_soc.aws.cloudtrail import UUID, iso, safe, timestamp


def project_event(event, *, tenancy, compartment, region, organization):
    if not isinstance(event, dict):
        raise ValueError("Invalid OCI Audit event")
    identifier = event.get("event_id")
    data = event.get("data")
    kind = event.get("event_type")
    if (not isinstance(identifier, str) or not UUID.fullmatch(identifier)
            or event.get("cloud_events_version") != "0.1"
            or not isinstance(event.get("event_type_version"), str)
            or not re.fullmatch(r"2\.\d{1,3}", event["event_type_version"])
            or not isinstance(kind, str) or not re.fullmatch(r"com\.oraclecloud\.[A-Za-z0-9_.:-]{1,220}", kind)
            or not isinstance(data, dict) or data.get("compartment_id") != compartment):
        raise ValueError("Invalid or out-of-scope OCI Audit event")
    occurred = timestamp(event.get("event_time"))
    identity = data.get("identity") if isinstance(data.get("identity"), dict) else {}
    request = data.get("request") if isinstance(data.get("request"), dict) else {}
    response = data.get("response") if isinstance(data.get("response"), dict) else {}
    status = response.get("status")
    status = int(status) if isinstance(status, str) and re.fullmatch(r"[1-5]\d{2}", status) else None
    outcome = "success" if status and 200 <= status < 300 else "failure" if status and status >= 400 else "unknown"
    method = request.get("action")
    audit = {
        "schema": 1, "compartment_id": compartment, "compartment_name": safe(data.get("compartment_name")),
        "resource_id": safe(data.get("resource_id")), "resource_name": safe(data.get("resource_name")),
        "identity_tenancy": safe(identity.get("tenant_id")), "auth_type": safe(identity.get("auth_type")),
        "caller_id": safe(identity.get("caller_id")), "caller_name": safe(identity.get("caller_name")),
        "request_id": safe(request.get("id")), "http_method": method if method in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS") else None,
        "http_status": status, "outcome_basis": "http_status" if status else "status_not_observed",
        "event_type": kind, "grouping_id": safe(data.get("event_grouping_id")),
    }
    source = {"address": safe(identity.get("ip_address"))}
    try:
        value = identity.get("ip_address")
        if not isinstance(value, str) or "%" in value:
            raise ValueError()
        source["ip"] = str(ip_address(value))
    except ValueError:
        pass
    document = {
        "@timestamp": iso(occurred),
        "event": {"id": identifier, "kind": "event", "dataset": "oci.audit", "provider": safe(event.get("source")),
                  "action": safe(data.get("event_name")), "outcome": outcome},
        # Region/tenancy identify the authenticated query, not the actor's tenancy.
        "cloud": {"provider": "oci", "account": {"id": tenancy}, "region": region,
                  "service": {"name": safe(event.get("source"))}},
        "organization": {"id": organization},
        "agent": {"type": "oci-audit", "id": "oci-" + hashlib.sha256(f"{tenancy}|{region}|{compartment}".encode()).hexdigest()},
        "labels": {"log_source": "oci_audit", "privacy_policy": "oci_audit_metadata_v1"},
        "user": {"id": safe(identity.get("principal_id")), "name": safe(identity.get("principal_name"))},
        "source": source, "oci": {"audit": audit},
    }
    digest = hashlib.sha256(f"oci|{organization}|{tenancy}|{region}|{compartment}|{identifier.lower()}".encode()).hexdigest()
    return "soc-cloud-oci-" + occurred.strftime("%Y.%m.%d"), digest, document
