"""Shared metadata display filtering; not a general-purpose DLP guarantee."""

import re

REDACTED = "[REDACTED]"
SENSITIVE = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----|"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|private[_-]?key|access[_-]?key|secret[_-]?access[_-]?key|session[_-]?token|client[_-]?secret|refresh[_-]?token|x-api-key|set-cookie)\s*[\"']?\s*[:=]|"
    r"\b(?:Bearer|Basic)\s+\S+|https?://[^\s/]+@|"
    r"https?://[^\s]*[?#]|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    re.IGNORECASE,
)


def sensitive(value):
    return isinstance(value, str) and (len(value) > 8192 or bool(SENSITIVE.search(value)))


def display(value, limit=512):
    if not isinstance(value, str):
        return None
    return REDACTED if sensitive(value) else value[:limit]


SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "token", "apikey", "authorization",
    "cookie", "privatekey", "accesskey", "accesskeyid", "secretaccesskey",
    "sessiontoken", "clientsecret", "refreshtoken", "xapikey", "setcookie",
}


def redact_metadata(value, *, depth=0):
    """Return a new bounded display object. Never alter raw evidence in place."""
    if depth >= 12:
        return REDACTED
    if isinstance(value, dict):
        if len(value) > 256:
            return REDACTED
        return {str(key): REDACTED if re.sub(r"[^a-z0-9]", "", str(key).lower()) in SENSITIVE_KEYS
                else redact_metadata(item, depth=depth + 1) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        if len(value) > 256:
            return REDACTED
        return [redact_metadata(item, depth=depth + 1) for item in value]
    if isinstance(value, str):
        return display(value, 8192)
    return value if value is None or type(value) in (int, float, bool) else REDACTED
