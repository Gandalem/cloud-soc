"""Observe Compose ownership and freeze a reversible, image-pinned execution recipe."""
from copy import deepcopy
from pathlib import Path
import re

from cloud_soc.deployment.contract import APP_SERVICES, digest


def compose_capabilities(engine):
    version = engine.run(['compose', 'version', '--short']).strip()
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+].*)?', version)
    if not match or int(match[1]) != 2 or tuple(map(int, match.groups())) < (2, 20, 0):
        raise ValueError('Docker Compose v2.20+ required for reviewed JSON config and no-deps recovery')
    return {'version': version, 'recovery_no_deps': True}


def classify(rendered, objects):
    defined = set(rendered.get('services', {}))
    running = {name for name, obj in objects.items() if obj.get('State', {}).get('Running')}
    residual = running - defined
    if residual:
        raise ValueError('Running service outside active Compose; recover retained execution before planning')
    return {'defined': sorted(defined), 'running': sorted(running),
            'stopped': sorted(set(objects) - running), 'residual_stopped': sorted(set(objects) - defined),
            'stop': sorted(running & defined & set(APP_SERVICES))}


def verify_previous(engine, active, rendered, objects, project):
    if rendered.get('name', project) != project:
        raise ValueError('Active Compose project differs from the observed project')
    classification = classify(rendered, objects)
    files = [active[i + 1] for i, value in enumerate(active[:-1]) if value == '-f']
    if not files or any(not Path(path).is_file() or Path(path).is_symlink() for path in files):
        raise ValueError('Active Compose source missing or unsafe')
    frozen = deepcopy(rendered)
    for name in classification['running']:
        obj = objects[name];labels = obj['Config'].get('Labels') or {}
        if (labels.get('com.docker.compose.project') != project
                or labels.get('com.docker.compose.project.config_files', '').split(',') != files):
            raise ValueError('Compose labels differ from the active receipt')
        row = frozen['services'][name]
        image = engine.json(['image', 'inspect', row['image']])[0]
        if image['Id'] != obj['Image']:
            raise ValueError('Previous image tag moved; preserve an exact recovery image before applying')
        defaults = image.get('Config') or {}
        for field, docker_field in (('command', 'Cmd'), ('entrypoint', 'Entrypoint')):
            configured = row.get(field)
            expected = defaults.get(docker_field) if configured is None else configured
            observed = obj['Config'].get(docker_field)
            # Compose JSON null means inherit the image; an explicit []/""
            # suppresses the image default. Docker represents absence as null/[] .
            if (expected or []) != (observed or []):
                raise ValueError('Active Compose command differs from observed execution')
        environment = dict(item.split('=', 1) for item in defaults.get('Env', []) if '=' in item)
        environment.update(row.get('environment', {}))
        if digest(sorted(k + '=' + str(v) for k, v in environment.items())) != digest(sorted(obj['Config'].get('Env', []))):
            raise ValueError('Active Compose environment differs from observed execution')
        actual = {m['Destination']: m for m in obj.get('Mounts', [])}
        for mount in row.get('volumes', []):
            found = actual.pop(mount['target'], None)
            if not found or found.get('RW', True) == mount.get('read_only', False):
                raise ValueError('Active Compose mount differs from observed execution')
            if mount['type'] == 'bind':
                source = mount['source']
            elif mount['type'] == 'volume':
                volume = rendered.get('volumes', {}).get(mount['source'], {})
                source = engine.json(['volume', 'inspect', volume.get('name', project + '_' + mount['source'])])[0]['Mountpoint']
            else:
                raise ValueError('Unsupported recovery mount type')
            if source != found['Source'] or mount['type'] != found.get('Type'):
                raise ValueError('Active Compose storage differs from observed execution')
        for secret in row.get('secrets', []):
            source = rendered.get('secrets', {}).get(secret['source'], {}).get('file')
            target = secret.get('target', secret['source'])
            target = target if target.startswith('/') else '/run/secrets/' + target
            found = actual.pop(target, None)
            if not source or not found or found['Source'] != source or found.get('RW', True):
                raise ValueError('Active Compose secret mount differs from observed execution')
        for target in row.get('tmpfs', []):
            target = target.split(':', 1)[0]
            found = actual.pop(target, None)
            # Engine versions either report tmpfs in Mounts or only HostConfig.Tmpfs.
            if found and found.get('Type') != 'tmpfs':
                raise ValueError('Active Compose tmpfs differs from observed execution')
        if actual:
            raise ValueError('Unrecorded container storage prevents exact recovery')
        host = obj.get('HostConfig', {})
        for field, observed, default in (('mem_limit', 'Memory', 0), ('read_only', 'ReadonlyRootfs', False)):
            configured = int(row.get(field, default)) if field == 'mem_limit' else row.get(field, default)
            if configured != host.get(observed, default):
                raise ValueError('Active Compose resource/security settings differ from observed execution')
        row['image'] = obj['Image']
    return classification, frozen


def literal_config(value):
    """A rendered config may contain literal dollars; do not interpolate it twice."""
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [literal_config(item) for item in value]
    if isinstance(value, dict):
        return {key: literal_config(item) for key, item in value.items()}
    return value
