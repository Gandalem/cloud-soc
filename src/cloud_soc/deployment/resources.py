"""Bounded, per-filesystem upgrade budgets. No cleanup or ES setting writes."""
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import os
from pathlib import Path
import re
import shutil


DISK = 'cluster.routing.allocation.disk.'
LEVELS = ('low', 'high', 'flood_stage')
MIB = 1024**2


def byte_size(value, *, disabled=False):
    if disabled and str(value) == '-1':
        return None
    match = re.fullmatch(r'(\d+(?:\.\d+)?)\s*(b|kb|mb|gb|tb|pb|kib|mib|gib|tib|pib)?', str(value).lower())
    if not match:
        raise ValueError('Unknown disk byte unit')
    unit = (match[2] or 'b').replace('ib', 'b')
    return int((Decimal(match[1]) * 1024**('b', 'kb', 'mb', 'gb', 'tb', 'pb').index(unit)).to_integral_value(rounding=ROUND_CEILING))


def watermark(value):
    text = str(value).lower()
    if text.endswith('%'):
        try:
            ratio = Decimal(text[:-1]) / 100
        except InvalidOperation:
            raise ValueError('Invalid ES disk watermark') from None
    elif re.fullmatch(r'\d*\.\d+|\d+', text):
        ratio = Decimal(text)
    else:
        return {'kind': 'free_bytes', 'value': byte_size(value)}
    if not ratio.is_finite() or not 0 < ratio < 1:
        raise ValueError('Invalid ES disk ratio')
    return {'kind': 'used_ratio', 'value': str(ratio)}


def disk_policy(settings, node_settings=None):
    """Resolve actual ES settings; explicit ratios do not inherit default headroom."""
    sources = [settings.get('defaults', {}), node_settings or {}, settings.get('persistent', {}), settings.get('transient', {})]
    effective = {}
    for source in sources:
        effective.update(source)
    enabled = str(effective.get(DISK + 'threshold_enabled', '')).lower()
    if enabled != 'true':
        raise ValueError('ES disk protection is disabled or unverified')
    result = {}
    for level in LEVELS:
        key = DISK + 'watermark.' + level
        if key not in effective:
            raise ValueError('ES disk watermark unavailable')
        row = watermark(effective[key]);headroom = key + '.max_headroom'
        explicit_ratio = any(key in source for source in sources[1:])
        explicit_headroom = any(headroom in source for source in sources[1:])
        row['max_headroom_bytes'] = (byte_size(effective[headroom], disabled=True)
            if headroom in effective and (not explicit_ratio or explicit_headroom) else None)
        row['configured_value'] = str(effective[key]);result[level] = row
    kinds = {row['kind'] for row in result.values()}
    if len(kinds) != 1:
        raise ValueError('Mixed ES ratio and byte watermark units')
    values = [Decimal(result[level]['value']) for level in LEVELS]
    if (next(iter(kinds)) == 'used_ratio' and values != sorted(values)
            or next(iter(kinds)) == 'free_bytes' and values != sorted(values, reverse=True)):
        raise ValueError('ES disk watermark ordering invalid')
    return result


def initial_disk_policy():
    """Conservative plan for the pinned fresh ES image; mandatory startup readback.

    This is explicitly an estimate, never presented as an observed cluster.
    Existing clusters must always supply their actual settings instead.
    """
    return disk_policy({'defaults': {DISK+'threshold_enabled': 'true', **{
        DISK+'watermark.'+level: value for level, value in zip(LEVELS, ('85%', '90%', '95%'))}, **{
        DISK+'watermark.'+level+'.max_headroom': value for level, value in zip(LEVELS, ('200gb', '150gb', '100gb'))}}})


def free_floor(row, total):
    if row['kind'] == 'free_bytes':
        return int(row['value'])
    wanted = int((Decimal(total) * (1 - Decimal(row['value']))).to_integral_value(rounding=ROUND_CEILING))
    headroom = row.get('max_headroom_bytes')
    return min(wanted, headroom) if headroom is not None else wanted


def allocation_filesystem(path, mountinfo):
    """Refuse shared/remote/volatile pools whose st_dev is not a space boundary."""
    matches = []
    for line in mountinfo.splitlines():
        left, separator, right = line.partition(' - ')
        fields, filesystem = left.split(), right.split()
        if not separator or len(fields) < 6 or len(filesystem) < 2:
            raise ValueError('Filesystem mount observation malformed')
        mount = re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), fields[4])
        if Path(path).is_relative_to(Path(mount)):
            matches.append((len(Path(mount).parts), filesystem[0], filesystem[1], fields[2]))
    if not matches:
        raise ValueError('Actual filesystem mount unavailable')
    _, kind, source, device = max(matches)
    if kind not in ('ext2', 'ext3', 'ext4', 'xfs'):
        raise ValueError('Shared-pool, remote or volatile filesystem requires explicit allocation accounting; upgrade refused')
    return {'filesystem': kind, 'mount_source': source, 'mount_device': device}


def path_filesystem(path):
    """Use allocated filesystem identity, so two directories/bind mounts do not count twice."""
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError('Symlinked storage location')
    existing = path
    while not existing.exists():
        existing = existing.parent
    info = existing.stat();usage = shutil.disk_usage(existing)
    filesystem = (allocation_filesystem(existing, Path('/proc/self/mountinfo').read_text()) if os.name == 'posix' else {})
    return {'path': str(path), 'device': str(info.st_dev), 'total_bytes': usage.total,
            'free_bytes': usage.free, 'used_bytes': usage.used, **filesystem}


def validate_backup_root(backup_root, state, docker_root, es_paths):
    """An external backup requires a real separate allocation pool, not another directory."""
    path = Path(backup_root)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ValueError('External backup must be an existing absolute private directory')
    if path.resolve() == Path(path.anchor) or path.resolve().is_relative_to(Path(state).resolve()):
        raise ValueError('External backup must be outside operational state')
    filesystem = path_filesystem(path)
    if any(path_filesystem(other)['device'] == filesystem['device'] for other in (state, docker_root, *es_paths)):
        raise ValueError('External backup is on the same storage device')
    if os.name == 'posix' and (path.stat().st_mode & 0o022 or path.stat().st_uid != 0):
        raise ValueError('External backup parent must be root-owned and not group/world writable')
    return filesystem


def disk_budget(locations, *, online_bytes, stopped_bytes, adoption_bytes, preflight_bytes,
                build_bytes, ingress_bytes, safety_bytes, es_policy=None):
    """Model sequential peaks, not a sum of mutually exclusive phases or existing data."""
    required = {'state', 'scratch', 'backup', 'docker'}
    if not required <= set(locations):
        raise ValueError('Required storage location missing')
    for value in (online_bytes, stopped_bytes, adoption_bytes, preflight_bytes, build_bytes, ingress_bytes, safety_bytes):
        if type(value) is not int or value < 0:
            raise ValueError('Invalid deployment storage estimate')
    devices = {}
    for name, row in locations.items():
        if not row.get('device') or row['total_bytes'] <= 0 or row['free_bytes'] < 0:
            raise ValueError('Unverified deployment filesystem')
        key = row['device']
        if key in devices and devices[key]['total_bytes'] != row['total_bytes']:
            raise ValueError('Inconsistent storage device capacity')
        device = devices.setdefault(key, {'total_bytes': row['total_bytes'], 'free_bytes': row['free_bytes'], 'locations': []})
        device['free_bytes'] = min(device['free_bytes'], row['free_bytes']);device['locations'].append(name)
    phases = {
        'candidate_build': [('docker', build_bytes)],
        'read_only_preflight': [('scratch', preflight_bytes)],
        'online_backup': [('backup', online_bytes)],
        'quiesced_backup': [('backup', online_bytes + stopped_bytes)],
        'state_adoption': [('backup', online_bytes + stopped_bytes), ('state', adoption_bytes)],
        'services_running': [('backup', online_bytes + stopped_bytes), ('state', adoption_bytes)],
    }
    report = {};issues = []
    for stage, costs in phases.items():
        charges = {key: 0 for key in devices}
        for location, size in costs:
            charges[locations[location]['device']] += size
        if stage != 'candidate_build':
            # Before-build plans conservatively retain the entire declared image
            # and scratch bound until completion; shared layers are not assumed.
            charges[locations['docker']['device']] += build_bytes
        # Continued incoming logs consume the ES filesystem, even for an external backup.
        ingress_device = locations.get('elasticsearch', locations['state'])['device']
        charges[ingress_device] += ingress_bytes
        if locations['state']['device'] != ingress_device:
            charges[locations['state']['device']] += ingress_bytes
        rows = {}
        for key, device in devices.items():
            floors = {'operator_safety': safety_bytes}
            if 'elasticsearch' in device['locations']:
                if es_policy is None:
                    raise ValueError('Actual ES watermarks required before upgrading data storage')
                floors.update({level: free_floor(es_policy[level], device['total_bytes']) for level in LEVELS})
            # Staying below the low watermark avoids entering relocation/block conditions at any stage.
            floor = max(floors.values());needed = charges[key] + floor
            shortage = max(0, needed - device['free_bytes'])
            rows[key] = {'additional_bytes': charges[key], 'remaining_bytes': device['free_bytes'] - charges[key],
                         'required_free_bytes': needed, 'shortfall_bytes': shortage, 'free_floors': floors,
                         'locations': device['locations']}
            if shortage:
                issues.append({'resource': 'disk', 'stage': stage, 'device': key, 'shortfall_bytes': shortage,
                               'reason': 'elasticsearch_watermark_or_backup_budget'})
        report[stage] = rows
    return {'ok': not issues, 'issues': issues, 'filesystems': devices, 'stages': report,
            'peak_required_bytes': {key: max(rows[key]['required_free_bytes'] for rows in report.values()) for key in devices},
            'existing_data_counted_as_additional': False,
            'remedies': ['Use a verified separate backup filesystem', 'Add disk capacity',
                         'Explicitly review old backups or unused images; no automatic deletion']}


def es_disk_observation(client):
    """Read real defaults/overrides and node filesystem statistics without returning secrets."""
    settings = client.cluster.get_settings(include_defaults=True, flat_settings=True).body
    info = client.nodes.info(metric='settings', flat_settings=True).body
    stats = client.nodes.stats(metric='fs').body
    if any(response.get('_nodes', {}).get('failed', 0) for response in (info, stats)):
        raise ValueError('Partial Elasticsearch disk observation')
    nodes = stats.get('nodes', {})
    if len(nodes) != 1 or set(nodes) != set(info.get('nodes', {})):
        raise ValueError('Cannot map ES data storage to this single-host Compose deployment')
    identifier = next(iter(nodes));node = nodes[identifier]
    actual = disk_policy(settings, info['nodes'][identifier].get('settings', {}))
    data = node.get('fs', {}).get('data', [])
    if len(data) != 1:
        raise ValueError('Exactly one verified local ES data path is required')
    row = data[0]
    return {'policy': actual, 'data': {k: row[k] for k in ('path', 'total_in_bytes', 'available_in_bytes')},
            'node': identifier, 'settings_source': 'defaults/node/persistent/transient'}
