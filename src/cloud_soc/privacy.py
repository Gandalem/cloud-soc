"""Shared metadata display filtering; not a general-purpose DLP guarantee."""

import re

REDACTED = "[REDACTED]"
SENSITIVE = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----|"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*[\"']?\s*[:=]|"
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
