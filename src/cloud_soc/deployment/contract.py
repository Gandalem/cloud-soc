"""Pure deployment contracts; importing this module needs only the standard library."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath

WORKERS = ('normalizer', 'normalizer-priority', 'detector', 'detector-priority',
           'detector-additional', 'detector-retrospective')
AUXILIARY = ('slack-notifier',)
ALL_WORKERS = (*WORKERS, *AUXILIARY)
APP_SERVICES = ('portal', 'enrollment-cleanup', *ALL_WORKERS)
SERVICES = (*APP_SERVICES, 'elasticsearch', 'kibana', 'gateway')
VALUES = {'--start', '--state', '--es-url', '--ca-file', '--api-key-file', '--interval',
          '--window-minutes', '--max-pages', '--max-documents', '--max-active-events',
          '--lateness-seconds', '--linux-ssh-v2-start', '--rules', '--additional-rules', '--status-id'}
FLAGS = {'--run', '--priority', '--early-auth', '--accept-legacy-exclusion', '--retrospective'}
SOURCE_PREFIXES = ('src/', 'rules/', 'prototype/', 'deploy/agents/', 'deploy/aws/', 'deploy/oci/', 'deploy/server/')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def stamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Explicit aware UTC start required')
    return result.astimezone(timezone.utc)


def policy(workspace):
    value = json.loads((Path(workspace) / 'deploy/server/runtime-policy.json').read_text(encoding='utf-8'))
    if value['version'] != 2 or value['workers'] != list(WORKERS) or value.get('auxiliary_workers') != list(AUXILIARY):
        raise ValueError('Unsupported runtime policy')
    return value


def validate_rules(value):
    from cloud_soc.detection.worker import approved_rules
    from cloud_soc.detection.engine import rule_revision
    actual = {r['id']: rule_revision(r) for r in approved_rules(rule_ids=list(value['verified_rules']))}
    if actual != value['verified_rules']:
        raise ValueError('Rule revision has no release validation; live activation refused')
    return list(actual)


def source_files(workspace):
    root = Path(workspace).resolve()
    names = [p for prefix in SOURCE_PREFIXES for p in (root / prefix).rglob('*') if p.is_file()]
    names += [root / name for name in ('requirements.txt', 'constraints.txt')]
    result = {}
    for path in names:
        if any(part in ('__pycache__', 'tests') for part in path.relative_to(root).parts) or path.suffix == '.pyc':
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('Release sources must be regular files inside the workspace')
        result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return dict(sorted(result.items()))


def options(command, module):
    if not isinstance(command, list) or command[:3] not in (['python', '-m', module], ['python3', '-m', module]):
        raise ValueError('Unsupported worker entry point; explicit adoption required')
    result, i = {}, 3
    while i < len(command):
        key = command[i]
        if key in result:
            raise ValueError('Duplicate worker option')
        if key in FLAGS:
            result[key] = True
            i += 1
        elif key in VALUES and i + 1 < len(command) and not command[i + 1].startswith('--'):
            result[key] = command[i + 1]
            i += 2
        else:
            raise ValueError('Unreviewed worker option; no inferred configuration')
    if not result.get('--run') or not all(k in result for k in ('--start', '--state', '--es-url', '--ca-file', '--api-key-file')):
        raise ValueError('Incomplete live worker command')
    stamp(result['--start'])
    if result['--es-url'] != 'https://elasticsearch:9200':
        raise ValueError('Unexpected internal ES URL; identity must be reviewed')
    for key in ('--state', '--ca-file', '--api-key-file'):
        p = PurePosixPath(result[key])
        if not p.is_absolute() or '..' in p.parts or any(ord(c) < 32 for c in str(p)):
            raise ValueError('Unsafe worker path')
    return result


def command(module, values):
    return ['python', '-m', module, *[v for k, value in values.items() for v in ([k] if value is True else [k, str(value)])]]


def mapped_file(container, target, state):
    path = PurePosixPath(target)
    matches = []
    for mount in container.get('Mounts', []):
        destination = PurePosixPath(mount['Destination'])
        if path == destination or destination in path.parents:
            source = Path(mount['Source']) / str(path.relative_to(destination))
            matches.append((len(destination.parts), source))
    if not matches:
        raise ValueError('Worker path has no inspected mount')
    source = max(matches, key=lambda item: item[0])[1]
    if source.is_symlink() or not source.resolve().is_relative_to(Path(state).resolve()):
        raise ValueError('Worker state/key outside protected state root')
    return source


def defaults(name, floor, rules):
    normalizer = name.startswith('normalizer')
    values = {'--run': True, '--start': floor, '--state': '/data/checkpoint.sqlite' if normalizer else '/data/runtime.sqlite',
              '--es-url': 'https://elasticsearch:9200', '--ca-file': '/run/certs/ca.crt',
              '--api-key-file': '/run/keys/worker.key', '--interval': '10' if name != 'normalizer' else '30'}
    if normalizer:
        values.update({'--window-minutes': '60' if name == 'normalizer' else '5', '--max-pages': '1000'})
        if name.endswith('priority'):
            values['--priority'] = True
    else:
        values.update({'--lateness-seconds': '900', '--max-documents': '20000'})
        if name == 'detector':
            values['--early-auth'] = True
        elif name == 'detector-priority':
            values['--status-id'] = 'detector-priority'
        elif name == 'detector-additional':
            values['--additional-rules'] = ','.join(k for k in rules if k != 'AUTH-001')
        elif name == 'detector-retrospective':
            values.update({'--retrospective': True, '--rules': ','.join(rules)})
    return values


def build_contract(value, containers, state, *, now=None, existing=None, initial_start=None):
    """Adopt inspected state identities; new workers get a pinned recent floor once."""
    now = now or datetime.now(timezone.utc)
    floor = (now - timedelta(seconds=60)).isoformat()
    if existing:
        if (existing.get('version') == 1 and value['version'] == 2
                and existing.get('policy_sha256') == 'cfe8183e7e8defe239ac6fc99c3cdb248963ac3df0eb7f6ccaa0ebbe2bf5b989'
                and set(existing.get('workers', {})) == set(WORKERS)
                and set(existing.get('verified_rules', [])) == set(value['verified_rules'])):
            result = deepcopy(existing)
            result.update(version=2, policy_sha256=digest(value), auxiliary_workers=list(AUXILIARY), migrated_from=1)
            return result, {}
        if existing.get('version') != value['version'] or existing.get('policy_sha256') != digest(value):
            raise ValueError('Policy changed; add an explicit version migration')
        return deepcopy(existing), {}
    rules = sorted(value['verified_rules'])
    result = {'version': value['version'], 'policy_sha256': digest(value), 'verified_rules': rules,
              'created_at': now.isoformat(), 'workers': {}, 'auxiliary_workers': list(AUXILIARY)}
    adoption = {}
    for name in WORKERS:
        module = 'cloud_soc.processing' if name.startswith('normalizer') else 'cloud_soc.detection'
        if name in containers:
            obj = containers[name]
            opts = options(obj['Config']['Cmd'], module)
            if name == 'detector' and ('--rules' in opts or '--additional-rules' in opts or '--retrospective' in opts):
                raise ValueError('Existing AUTH profile requires explicit migration')
            expected = defaults(name, floor, rules)
            for key in ('--rules', '--additional-rules', '--retrospective', '--priority'):
                actual, wanted = opts.get(key), expected.get(key)
                if key in ('--rules', '--additional-rules'):
                    actual = sorted(actual.split(',')) if actual is not None else None
                    wanted = sorted(wanted.split(',')) if wanted is not None else None
                if name not in ('normalizer', 'detector') and actual != wanted:
                    raise ValueError('Existing rule/source profile differs; no identity rewrite')
            source = mapped_file(obj, opts['--state'], state)
            key = mapped_file(obj, opts['--api-key-file'], state)
            if (not source.is_file() and not (obj.get('UnactivatedRuntime') and not obj.get('State', {}).get('Running'))) or not key.is_file():
                raise ValueError('Existing state/key missing; no reinitialization')
            adoption[name] = {'key_source': str(key), 'container': obj['Id']}
            if source.is_file():
                adoption[name]['state_source'] = str(source)
            # Observable status routing and early mode do not change detector identity.
            if name == 'detector-priority':
                opts['--status-id'] = 'detector-priority'
            if name == 'detector':
                opts['--early-auth'] = True
            opts['--api-key-file'] = '/run/keys/worker.key'
            opts['--ca-file'] = '/run/certs/ca.crt'
            opts['--state'] = '/data/' + source.name
        else:
            opts = defaults(name, initial_start or floor if name in ('normalizer', 'detector') else floor, rules)
            predecessor = 'normalizer' if name.startswith('normalizer') else 'detector'
            if predecessor in containers:
                previous = options(containers[predecessor]['Config']['Cmd'], 'cloud_soc.processing' if predecessor == 'normalizer' else 'cloud_soc.detection')
                adoption[name] = {'key_source': str(mapped_file(containers[predecessor], previous['--api-key-file'], state))}
        if name.startswith('normalizer'):
            if name == 'normalizer':
                opts.setdefault('--window-minutes', '60')
                opts.setdefault('--interval', '30')
            # Preserve the legacy format floor; a new priority scope starts later.
            if name == 'normalizer-priority' and '--linux-ssh-v2-start' not in opts:
                opts['--linux-ssh-v2-start'] = opts['--start']
        result['workers'][name] = {'module': module, 'options': opts, 'state_file': PurePosixPath(opts['--state']).name}
    return result, adoption


def resource_check(value, hardware, *, fresh, database_bytes=0, adoption_bytes=0, storage=None, backup_memory_bytes=0):
    r = value['resources'];issues = []
    reserved = sum(r['limits_mib'].values()) * 1024**2 + r['headroom_bytes']
    available = hardware.get('available_memory_bytes', 0) + hardware.get('managed_working_set_bytes', 0)
    needed = (r['fresh_free_bytes'] if fresh else r['upgrade_free_bytes']) + 2 * database_bytes + adoption_bytes
    for ok, reason in [(hardware['cpus'] >= r['min_cpus'], 'cpu_below_minimum'),
                       (hardware['memory_bytes'] >= max(reserved, r['min_memory_bytes']), 'memory_budget_exceeded'),
                       (available >= reserved, 'available_memory_budget_exceeded'),
                       (storage['ok'] if storage is not None else hardware['free_bytes'] >= needed, 'disk_backup_and_release_budget_exceeded'),
                       (hardware.get('available_memory_bytes', 0) >= backup_memory_bytes + r['headroom_bytes'], 'backup_restore_memory_budget_exceeded'),
                       (hardware.get('map_count', 0) >= 262144, 'vm_max_map_count_too_low')]:
        if not ok:
            issues.append(reason)
    return {'ok': not issues, 'issues': issues, 'required_free_bytes': needed, 'adoption_copy_bytes': adoption_bytes, 'reserved_memory_bytes': reserved,
            'available_after_replacing_managed_bytes': available,
            'observed': dict(hardware), 'disk': storage,
            'backup_restore_memory_bytes': backup_memory_bytes + r['headroom_bytes']}


def validate_rendered(value, rendered, image):
    services = rendered.get('services', {})
    if not set(SERVICES) <= set(services):
        raise ValueError('Common Compose omitted mandatory services')
    for name in APP_SERVICES:
        if services[name].get('image') != image:
            raise ValueError('Mixed application versions in Compose')
    for name, limit in value['resources']['limits_mib'].items():
        if int(services[name].get('mem_limit', 0)) != limit * 1024**2:
            raise ValueError('Compose resource limit differs from the reviewed budget')
    for name in WORKERS:
        if services[name].get('command') != ['python', '-m', 'cloud_soc.deployment.worker', '--service', name]:
            raise ValueError('Per-server worker command override refused')
    if services['slack-notifier'].get('command') != ['python', '-m', 'cloud_soc.notifications.worker']:
        raise ValueError('Notification worker override refused')
    if services['kibana'].get('environment', {}).get('NODE_OPTIONS') != '--max-old-space-size=1024':
        raise ValueError('Kibana heap and container budget must be declared together')
    if services.get('bootstrap', {}).get('profiles') != ['initialization']:
        raise ValueError('Initialization must not run during a normal upgrade')
    return {'required_services': list(SERVICES), 'same_application_image': True, 'resource_limits_match_policy': True}
