"""Privacy-first CloudTrail Event History adapter. No AWS I/O in this module."""

from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import re

from cloud_soc.privacy import display, REDACTED

INDEX_PATTERN = "soc-cloud-aws-*"
SOURCE_LABEL = "aws_cloudtrail"
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")


def timestamp(value):
    try:
        value = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise ValueError()
        return value.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise ValueError("Invalid CloudTrail timestamp") from None


def iso(value):
    return timestamp(value).isoformat().replace("+00:00", "Z")


def safe(value):
    if not isinstance(value, str) or not value:
        return None
    if len(value) > 512 or any(ord(c) < 32 for c in value):
        return REDACTED
    return display(value)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate CloudTrail field")
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("Invalid JSON constant")


def project_event(envelope, *, account, region, organization):
    """Return (index, deterministic id, allowlisted metadata), never the payload."""
    try:
        raw = envelope.get("CloudTrailEvent")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 1024 * 1024:
            raise ValueError()
        event = json.loads(raw, object_pairs_hook=_object, parse_constant=_reject_constant)
        if not isinstance(event, dict):
            raise ValueError()
        identifier = event.get("eventID")
        if not isinstance(identifier, str) or not UUID.fullmatch(identifier) or envelope.get("EventId") != identifier:
            raise ValueError()
        if event.get("recipientAccountId") != account or event.get("awsRegion") != region:
            raise ValueError()
        version = event.get("eventVersion")
        if not isinstance(version, str) or not re.fullmatch(r"1\.\d{1,3}", version):
            raise ValueError()
        if event.get("eventCategory") not in (None, "Management") or event.get("managementEvent") is False:
            raise ValueError()
        if event.get("eventCategory") != "Management" and event.get("managementEvent") is not True:
            raise ValueError()
        occurred = timestamp(event.get("eventTime"))
        if timestamp(envelope.get("EventTime")) != occurred:
            raise ValueError()
        name, provider = event.get("eventName"), event.get("eventSource")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", name):
            raise ValueError()
        if not isinstance(provider, str) or not re.fullmatch(r"[a-z0-9.-]{1,128}\.amazonaws\.com", provider):
            raise ValueError()
        for outer, inner in (("EventName", name), ("EventSource", provider)):
            if outer in envelope and envelope[outer] != inner:
                raise ValueError()
        if event.get("errorCode") is not None and not isinstance(event["errorCode"], str):
            raise ValueError()
    except (AttributeError, ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("Invalid or out-of-scope CloudTrail management event") from None

    identity = event.get("userIdentity")
    identity = identity if isinstance(identity, dict) else {}
    context = identity.get("sessionContext")
    context = context if isinstance(context, dict) else {}
    issuer = context.get("sessionIssuer")
    issuer = issuer if isinstance(issuer, dict) else {}
    error = safe(event.get("errorCode"))
    response = event.get("responseElements")
    console = response.get("ConsoleLogin") if isinstance(response, dict) else None
    if error:
        outcome, basis = "failure", "error_code"
    elif name == "ConsoleLogin":
        outcome = {"Success": "success", "Failure": "failure"}.get(console, "unknown") if isinstance(console, str) else "unknown"
        basis = "console_response"
    else:
        outcome, basis = "success", "no_error_reported"
    resources = event.get("resources")
    resources = resources if isinstance(resources, list) else []
    selected = []
    for resource in resources[:20]:
        if isinstance(resource, dict):
            selected.append({key: safe(resource.get(raw_key)) for key, raw_key in
                             (("arn", "ARN"), ("type", "type"), ("account_id", "accountId"))})
    audit = {
        "schema": 1, "identity_type": safe(identity.get("type")), "identity_arn": safe(identity.get("arn")),
        "identity_invoked_by": safe(identity.get("invokedBy")),
        "identity_account": safe(identity.get("accountId")), "session_issuer_arn": safe(issuer.get("arn")),
        "resources": selected, "resources_truncated": len(resources) > 20,
        "error_code": error, "outcome_basis": basis, "management_only": True,
        "read_only": event.get("readOnly") if type(event.get("readOnly")) is bool else None,
    }
    request = event.get("requestParameters")
    if isinstance(request, dict):
        if provider == "iam.amazonaws.com":
            audit.update(target_user=safe(request.get("userName")), target_role=safe(request.get("roleName")),
                         target_policy_arn=safe(request.get("policyArn")))
        if provider == "ec2.amazonaws.com":
            group = request.get("groupId")
            if isinstance(group, str) and re.fullmatch(r"sg-(?:[0-9a-f]{8}|[0-9a-f]{17})", group):
                audit["target_group_id"] = group
    source = {"address": safe(event.get("sourceIPAddress"))}
    try:
        value = event.get("sourceIPAddress")
        if not isinstance(value, str) or "%" in value:
            raise ValueError()
        source["ip"] = str(ip_address(value))
    except ValueError:
        pass
    document = {
        "@timestamp": iso(occurred),
        "event": {"id": identifier, "kind": "event", "dataset": "aws.cloudtrail",
                  "provider": provider, "action": name, "outcome": outcome},
        "cloud": {"provider": "aws", "account": {"id": account}, "region": region, "service": {"name": provider}},
        "organization": {"id": organization},
        "agent": {"type": "cloudtrail", "id": "aws-" + account + "-" + region},
        "labels": {"log_source": SOURCE_LABEL, "privacy_policy": "cloudtrail_metadata_v1"},
        "user": {"id": safe(identity.get("principalId")), "name": safe(identity.get("userName"))},
        "source": source, "aws": {"cloudtrail": audit},
    }
    # No host fields: an AWS resource is not the collector's operating system.
    digest = hashlib.sha256(f"aws|{organization}|{account}|{region}|{identifier.lower()}".encode()).hexdigest()
    return "soc-cloud-aws-" + occurred.strftime("%Y.%m.%d"), digest, document
