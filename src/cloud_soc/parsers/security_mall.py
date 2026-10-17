"""Pure, bounded security-mall schema v1 parsing; no secrets, files or I/O."""

from datetime import datetime
from ipaddress import ip_address
import json
import re
from uuid import UUID

from cloud_soc.privacy import sensitive
from cloud_soc.parsers.security_mall_edge import REQUEST_ID

VERSION = "security-mall-audit-v1"
ADAPTER = "security_mall_audit_v1"
SOURCE_KIND = "security_mall_audit"
PAYLOAD_PATH = "security_mall.audit"
COMMON_FIELDS = (
    "schema_version", "@timestamp", "event_id", "service_name", "event_action", "event_outcome",
    "source_ip", "account_id", "account_key_id",
)
AUTHORIZATION_FIELDS = ("resource_type", "authorization_reason")
OPTIONAL_FIELDS = ("request_id",)
SOURCE_FIELDS = tuple(PAYLOAD_PATH + "." + name for name in COMMON_FIELDS + AUTHORIZATION_FIELDS + OPTIONAL_FIELDS)
ADMIN_RESOURCES = {
    "admin_view": "admin", "item_create_form": "item", "item_create": "item",
    "item_edit_form": "item", "item_update": "item", "item_delete": "item", "user_delete": "user",
}
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class AuditError(ValueError):
    """Only fixed reason codes may leave the parser, never input or JSON errors."""

    def __init__(self, reason, *, status="invalid"):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("security_mall_duplicate_field")
        result[key] = value
    return result


def _constant(_value):
    raise AuditError("security_mall_json_invalid")


def parse(payload):
    """Accept a JSON line or decoded object; return only validated allowlisted metadata.

    Unknown fields are discarded. Collectors must use this decoder before storing
    objects to reject duplicate JSON keys instead of silently picking a value.
    """
    if isinstance(payload, str):
        try:
            if len(payload) > 8192 or len(payload.encode("utf-8")) > 8192:
                raise AuditError("security_mall_payload_too_large")
            payload = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_constant)
        except AuditError:
            raise
        except (ValueError, UnicodeError, RecursionError):
            raise AuditError("security_mall_json_invalid") from None
    if not isinstance(payload, dict) or not set(COMMON_FIELDS).issubset(payload):
        raise AuditError("security_mall_fields_missing")
    schema = payload["schema_version"]
    if type(schema) is not int:
        raise AuditError("security_mall_schema_invalid")
    if schema != 1:
        raise AuditError("security_mall_schema_unsupported", status="unsupported")
    stamp = payload["@timestamp"]
    try:
        if not isinstance(stamp, str) or not STAMP.fullmatch(stamp):
            raise ValueError()
        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        raise AuditError("security_mall_time_invalid") from None
    identifier = payload["event_id"]
    try:
        if not isinstance(identifier, str) or len(identifier) != 36:
            raise ValueError()
        parsed_id = UUID(identifier)
        if not parsed_id.int or str(parsed_id) != identifier:
            raise ValueError()
    except ValueError:
        raise AuditError("security_mall_event_id_invalid") from None
    for name in ("service_name", "account_key_id"):
        value = payload[name]
        if not isinstance(value, str) or not TOKEN.fullmatch(value) or sensitive(value):
            raise AuditError("security_mall_label_invalid")
    peer = payload["source_ip"]
    try:
        if not isinstance(peer, str) or len(peer) > 45 or "%" in peer:
            raise ValueError()
        peer = str(ip_address(peer))
    except ValueError:
        raise AuditError("security_mall_ip_invalid") from None
    account = payload["account_id"]
    if account is not None and (not isinstance(account, str) or not re.fullmatch(r"[0-9a-f]{64}", account)):
        raise AuditError("security_mall_account_invalid")
    action, outcome = payload["event_action"], payload["event_outcome"]
    if not isinstance(action, str) or action not in {"login", "order_view", *ADMIN_RESOURCES}:
        raise AuditError("security_mall_action_unsupported", status="unsupported")
    if outcome not in ("success", "failure"):
        raise AuditError("security_mall_outcome_invalid")
    values = {
        "schema_version": 1, "timestamp": stamp, "event_id": identifier,
        "service_name": payload["service_name"], "action": action, "outcome": outcome,
        "source_ip": peer, "account_id": account, "account_key_id": payload["account_key_id"],
        "category": "authentication" if action == "login" else "iam",
    }
    request_id = payload.get("request_id")
    if request_id is not None:
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            raise AuditError("security_mall_request_id_invalid")
        values["request_id"] = request_id
    if action == "login":
        if account is None or any(name in payload for name in AUTHORIZATION_FIELDS):
            raise AuditError("security_mall_login_invalid")
        return values
    if not set(AUTHORIZATION_FIELDS).issubset(payload):
        raise AuditError("security_mall_fields_missing")
    resource, reason = payload["resource_type"], payload["authorization_reason"]
    expected_resource = "order" if action == "order_view" else ADMIN_RESOURCES[action]
    if resource != expected_resource or not isinstance(reason, str):
        raise AuditError("security_mall_authorization_invalid")
    if reason == "unauthenticated":
        valid = outcome == "failure" and account is None
    elif account is None:
        valid = False
    elif action == "order_view":
        valid = (outcome, reason) in (("success", "owner"), ("failure", "not_owner"), ("failure", "not_found"))
    else:
        valid = (outcome, reason) in (("success", "admin"), ("failure", "admin_required"))
    if not valid:
        raise AuditError("security_mall_authorization_invalid")
    values.update(resource_type=resource, authorization_reason=reason)
    return values
