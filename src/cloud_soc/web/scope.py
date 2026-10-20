"""Collector-configured site identity; never inferred from a URL or Host header."""
import re

NORMALIZER_VERSION = 'web-access-site-v2'
NORMALIZED_ADAPTER = 'web_access_site_v2'
LEGACY_VERSION = 'web-access-agent-v1'


def valid_site_id(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value) is not None
