"""Shared metadata display filtering; not a general-purpose DLP guarantee."""

import re

REDACTED = "[REDACTED]"
SENSITIVE = re.compile(
    r"-----BEGIN [^-]*(?:PRIVATE KEY|CERTIFICATE)-----|"
    r"(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie)\s*[\"']?\s*[:=]|"
    r"(?:--?|/)(?:password|passwd|pwd|secret|token|api[_-]?key)\b(?:\s+|=|:)|"
    r"\b(?:Bearer|Basic)\s+\S+|\b[a-z][a-z0-9+.-]*://[^\s/]+@|"
    r"\b[a-z][a-z0-9+.-]*://[^\s]*[?#]|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u206f]|"
    r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    re.IGNORECASE,
)


def sensitive(value):
    return isinstance(value, str) and (len(value) > 8192 or bool(SENSITIVE.search(value)))


def display(value, limit=512):
    if not isinstance(value, str):
        return None
    return REDACTED if sensitive(value) else value[:limit]
