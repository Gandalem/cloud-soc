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
        names = value[key]
        single = isinstance(names, str)
        if single:
            names = (names,)
        elif key == 'alerts' or not isinstance(names, (list, tuple)):
            raise ValueError('Only raw/normalized accept explicit index lists')
        if not 1 <= len(names) <= 8:
            raise ValueError('Bounded nonempty index list required')
        for name in names:
            if (not isinstance(name, str) or len(name) > 255 or 'synthetic' in name
                    or not re.fullmatch(re.escape(prefix) + r'[a-z0-9][a-z0-9-]*', name)):
                raise ValueError('Only exact live lab indices are accepted')
        if len(set(names)) != len(names):
            raise ValueError('Duplicate lab index')
        result[key] = names[0] if single else tuple(names)
    return result


def scope_indices(scope, key=None):
    """Flatten a validated server scope; legacy strings retain their contract."""
    keys = (key,) if key else ('alerts', 'normalized', 'raw')
    return tuple(dict.fromkeys(name for field in keys for name in
                              ((scope[field],) if isinstance(scope[field], str) else scope[field])))


def read_scope(path):
    if not path:
        return None
    source = Path(path)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 4096:
        raise ValueError('Invalid Security Mall lab scope file')
    return validate_scope(json.loads(source.read_text(encoding='utf-8')))
