"""Explicit server-owned lab scope; no browser-controlled index selection."""
import json
from pathlib import Path
import re


def validate_scope(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {'alerts', 'normalized', 'raw'}:
        raise ValueError('Invalid Security Mall lab scope')
    prefixes = {'alerts': 'soc-mall-alerts-lab-live-', 'normalized': 'soc-normalized-mall-',
                'raw': 'soc-host-raw-mall-'}
    result = {}
    for key, prefix in prefixes.items():
        name = value[key]
        if (not isinstance(name, str) or len(name) > 255 or 'synthetic' in name
                or not re.fullmatch(re.escape(prefix) + r'[a-z0-9][a-z0-9-]*', name)):
            raise ValueError('Only exact live lab indices are accepted')
        result[key] = name
    return result


def read_scope(path):
    if not path:
        return None
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 4096:
        raise ValueError('Invalid Security Mall lab scope file')
    return validate_scope(json.loads(source.read_text(encoding='utf-8')))
