"""Local-Docker coordinator. Plans are reviewed before any service is stopped."""
from contextlib import closing, contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time

from cloud_soc.deployment.contract import (ALL_WORKERS, APP_SERVICES, SERVICES, WORKERS, build_contract, command, digest,
    policy, resource_check, source_files, validate_rendered)
from cloud_soc.deployment.migrations import atomic_json, durable_unlink, reusable_key
from cloud_soc.deployment import backups, execution, resources as disk_resources


class PreservationError(ValueError):
    pass


class ResourceBudgetError(ValueError):
    def __init__(self, report):
        self.report = report
        super().__init__('Resource budget refused; no service stop requested')


class Docker:
    def __init__(self):
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
        self.prefix = ['docker', '--host', 'unix:///var/run/docker.sock']

    def run(self, args, *, input=None, env=None, timeout=180):
        p = subprocess.run(self.prefix + args, input=input, text=True, capture_output=True,
                           env={**self.env, **(env or {})}, timeout=timeout)
        if p.returncode:
            raise RuntimeError('docker_command_failed_' + str(p.returncode))
        return p.stdout

    def json(self, args, **kw):
        return json.loads(self.run(args, **kw))


def checked_path(path, root, *, file=False):
    path, root = Path(path), Path(root).resolve()
    if path.is_symlink() or not path.resolve().is_relative_to(root):
        raise ValueError('State path escapes the approved root')
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise ValueError('Symlink in protected state path')
    if file and not path.is_file():
        raise ValueError('Required protected file missing')
    return path


def protected_hashes(state):
    root = Path(state)
    paths = [p for folder in ('tls', 'private', 'secrets') for p in (root / folder).rglob('*') if p.is_file()]
    paths += [root / 'compose.env']
    paths += [p for p in (root / 'runtime/keys').glob('*') if p.is_file() and p.suffix in ('.key', '.issued')]
    if (root / 'notifications/slack.key').exists():
        paths.append(root / 'notifications/slack.key')
    # Site-specific bind mounts are included separately in the runtime snapshot.
    return {str(checked_path(p, root, file=True)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def backup_database(source, target):
    if target.exists() or target.is_symlink():
        raise ValueError('Backup output already exists')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with closing(sqlite3.connect('file:' + str(source) + '?mode=ro', uri=True)) as original, closing(sqlite3.connect(target)) as copy:
        original.backup(copy, pages=256, sleep=0.01)
        # A standalone backup must not need to create WAL/shm in its read-only mount.
        copy.execute('pragma journal_mode=delete').fetchall()
        if copy.execute('pragma integrity_check').fetchall() != [('ok',)]:
            raise ValueError('Backup integrity failed')
        with closing(sqlite3.connect(':memory:')) as restored:
            copy.backup(restored)
            if restored.execute('pragma integrity_check').fetchall() != [('ok',)]:
                raise ValueError('Backup restore verification failed')
    target.chmod(0o600)
    with target.open('r+b') as stream:
        os.fsync(stream.fileno())
    backups.fsync_directory(target.parent)


def portal_rows(state):
    """Hash saved case/dashboard rows from online snapshots, excluding SQLite counters."""
    result = {}
    with tempfile.TemporaryDirectory(prefix='portal-preservation-', dir=Path(state).parent) as temporary:
        for name in ('cases.sqlite', 'dashboards.sqlite'):
            source = Path(state) / 'portal' / name
            if not source.exists():
                continue
            copy = Path(temporary) / name;backup_database(source, copy)
            with closing(sqlite3.connect(copy)) as conn:
                result[name] = sorted(hashlib.sha256(line.encode()).hexdigest() for line in conn.iterdump()
                    if line.startswith(('CREATE TABLE ', 'INSERT INTO ')) and '"sqlite_sequence"' not in line)
    return result


def immutable_documents(engine, state, image, project, before=None):
    payload = {'password': (state / 'secrets/elastic_password').read_text().strip()}
    if before is not None:
        payload['before'] = before
    return engine.json(['run', '--rm', '-i', '--network', project + '_default',
        '-v', str(state / 'tls/ca.crt') + ':/run/certs/ca.crt:ro', '--entrypoint', 'python',
        image, '-m', 'cloud_soc.deployment.preservation'], input=json.dumps(payload))


@contextmanager
def lock(directory):
    import fcntl
    if directory.is_symlink():
        raise ValueError('Runtime directory must not be a symlink')
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = checked_path(directory / 'upgrade.lock', directory)
    with path.open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def containers(engine, project):
    identifiers = engine.run(['ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project]).split()
    if not identifiers:
        return {}
    result = {}
    for obj in engine.json(['inspect', *identifiers]):
        labels = obj['Config'].get('Labels') or {}
        name = labels.get('com.docker.compose.service')
        if obj['Name'] != '/' + project + '-' + str(name) + '-1':
            continue  # Explicitly unmanaged helpers, never re-created by this tool.
        if name in SERVICES:
            if name in result:
                raise ValueError('Ambiguous service identity')
            result[name] = obj
    return result


def worker_inventory(engine, project, *, stopped=False):
    """Refuse a second Compose project, manual run, scale replica or renamed worker."""
    ids = engine.run(['ps', '-q']).split()
    found = {}
    for obj in engine.json(['inspect', *ids]) if ids else []:
        config = obj['Config'];tokens = [*(config.get('Entrypoint') or []), *(config.get('Cmd') or [])]
        text = ' '.join(str(token) for token in tokens)
        if not any(module in text for module in ('cloud_soc.processing', 'cloud_soc.detection', 'cloud_soc.deployment.worker', 'cloud_soc.notifications.worker')):
            continue
        labels = config.get('Labels') or {};name = labels.get('com.docker.compose.service')
        if (stopped or name not in ALL_WORKERS or labels.get('com.docker.compose.project') != project
                or obj['Name'] != '/' + project + '-' + str(name) + '-1' or name in found):
            raise ValueError('Unmanaged or duplicate SOC worker running; preserve it and resolve ownership before applying')
        found[name] = obj['Id']
    return found


def active_command(state, objects):
    if (Path(state) / 'runtime/install.json').exists() and not (Path(state) / 'runtime/current.json').exists():
        return None
    if 'portal' not in objects:
        return None
    labels = objects['portal']['Config'].get('Labels') or {}
    files = labels.get('com.docker.compose.project.config_files', '').split(',')
    paths = [Path(state) / 'runtime/compose.active.json', *Path(state).parent.glob('*/compose*.json')]
    for path in paths:
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text())
        except (ValueError, OSError):
            continue
        if isinstance(value, list) and value[:2] == ['docker', 'compose']:
            arguments = value[2:];position = 0
            pairs = {'-f', '--project-name', '-p', '--env-file', '--project-directory', '--profile'}
            while position < len(arguments):
                option = arguments[position]
                if option == '--compatibility':
                    position += 1;continue
                if option not in pairs or position+1 >= len(arguments) or str(arguments[position+1]).startswith('-'):
                    raise ValueError('Active receipt must contain only reviewed Compose global options')
                position += 2
            observed = [value[i+1] for i, v in enumerate(value[:-1]) if v == '-f']
            if observed == files:
                for name in observed:
                    source = Path(name)
                    if not source.is_absolute():
                        raise ValueError('Active Compose receipt must record absolute source files')
                    # Source releases may live on a different disk from state.
                    # Labels + receipt + rendered/observed signature prove them;
                    # guessing ancestry from the state directory rejects valid releases.
                    checked_path(source, Path(source.anchor), file=True)
                return value[2:]
    raise ValueError('Cannot identify the exact active Compose command; provide its protected receipt')


def public_environment(obj):
    allowed = {'SOC_PUBLIC_URL', 'SOC_PUBLIC_HOST', 'SOC_PORTAL_LAN_ORIGIN', 'SOC_ENROLLMENT_ENABLED',
        'SOC_ELASTIC_ENDPOINT', 'SOC_AGENT_ENDPOINT', 'SOC_ADMIN_ALLOWED_CIDRS', 'SOC_USERS_FILE',
        'SOC_LOG_ACCESS_POLICY_FILE', 'SOC_LOG_FORMAT', 'SOC_INTERNAL_ES_URL', 'SOC_CA_FILE',
        'SOC_STATE_DIR', 'SOC_ADMIN_USER', 'SOC_ADMIN_HASH_FILE', 'SOC_ISSUER_PASSWORD_FILE', 'SOC_MONITOR_PASSWORD_FILE'}
    return {k: v for item in obj['Config'].get('Env', []) for k, _, v in [item.partition('=')] if k in allowed}


def observed_services(objects):
    """Docker's Mounts array has no stable order; preserve values, canonicalize order."""
    return {name: {'id': obj['Id'], 'image': obj['Image'], 'command': obj['Config']['Cmd'],
                  'mounts': sorted(obj.get('Mounts', []), key=lambda row: (row['Destination'], row['Source'], row.get('Type', ''))),
                  'environment': public_environment(obj)} for name, obj in objects.items()}


def site_overlay(rendered, objects):
    """Keep explicitly reviewed site mounts/endpoints, never historical worker commands."""
    result = {'services': {}, 'secrets': deepcopy(rendered.get('secrets', {})),
              'volumes': deepcopy(rendered.get('volumes', {})), 'networks': deepcopy(rendered.get('networks', {}))}
    for name in ('portal', 'enrollment-cleanup', 'gateway', 'elasticsearch', 'kibana'):
        if name not in rendered.get('services', {}):
            continue
        old = rendered['services'][name]
        row = {k: deepcopy(old[k]) for k in ('volumes', 'ports', 'secrets', 'configs', 'networks') if k in old}
        if name == 'elasticsearch':
            allowed = ('path.repo', 'cluster.name', 'node.name')
            row['environment'] = {k: v for k, v in old.get('environment', {}).items() if k in allowed}
        if name in ('portal', 'enrollment-cleanup', 'gateway') and name in objects:
            row['environment'] = public_environment(objects[name])
            if name == 'portal':
                row['environment']['SOC_RUNTIME_CONTRACT_FILE'] = '/run/runtime/contract.json'
                row['environment']['SOC_NOTIFICATION_STATE_DIR'] = '/notifications'
        result['services'][name] = row
    # Message links follow the actual portal origin, including an existing site's custom port.
    portal_url = result['services'].get('portal', {}).get('environment', {}).get('SOC_PUBLIC_URL')
    if portal_url:
        result['services']['slack-notifier'] = {'environment': {'SOC_PUBLIC_URL': portal_url}}
    return result


def hardware(engine, state, project='cloud-soc-central'):
    info = engine.json(['info', '--format', '{{json .}}'])
    if info.get('OSType') != 'linux':
        raise ValueError('A local Linux Docker engine is required')
    paths = [Path(state), Path(info['DockerRootDir'])]
    free = min(shutil.disk_usage(p).free for p in paths)
    memory = {line.split(':')[0]: int(line.split()[1]) * 1024 for line in Path('/proc/meminfo').read_text().splitlines()}
    managed, other = 0, 0
    working = {}
    for line in engine.run(['stats', '--no-stream', '--format', '{{json .}}']).splitlines():
        row = json.loads(line)
        match = re.fullmatch(r'([0-9.]+)(B|KiB|MiB|GiB|TiB)', row['MemUsage'].split('/')[0].strip())
        if not match:
            raise ValueError('Cannot measure container working memory')
        usage = int(float(match[1]) * 1024 ** ('B', 'KiB', 'MiB', 'GiB', 'TiB').index(match[2]))
        working[row['Name']] = usage
        if row['Name'] in {project + '-' + n + '-1' for n in SERVICES}:
            managed += usage
        else:
            other += usage
    return {'cpus': info['NCPU'], 'memory_bytes': info['MemTotal'], 'free_bytes': free,
            'available_memory_bytes': memory['MemAvailable'], 'managed_working_set_bytes': managed,
            'other_container_working_set_bytes': other, 'container_working_set_bytes': working,
            'docker_root': info['DockerRootDir'],
            'map_count': int(Path('/proc/sys/vm/max_map_count').read_text())}


def storage_budget(engine, state, image, project, objects, rows, adopted_bytes, hardware, value,
                   *, backup_root=None, ingress_bytes=1024**3, build_bytes=0, fresh=False, online_complete=False):
    """Inspect actual allocation pools and ES floors before any DB copy or stop."""
    locations = {name: disk_resources.path_filesystem(path) for name, path in {
        'state': state, 'scratch': state.parent, 'backup': backup_root or state / 'runtime/upgrades',
        'docker': hardware['docker_root']}.items()}
    es_paths = [];observed = None
    if 'elasticsearch' in objects:
        mounts = [m['Source'] for m in objects['elasticsearch'].get('Mounts', [])
                  if m['Destination'] == '/usr/share/elasticsearch/data']
        if len(mounts) != 1:
            raise ValueError('Cannot map the actual Elasticsearch data allocation pool')
        es_paths = mounts;locations['elasticsearch'] = disk_resources.path_filesystem(mounts[0])
        # The read-only probe also works before building the candidate, using the
        # previous app's Python dependencies and this reviewed public helper text.
        probe = "import json,sys;from elasticsearch import Elasticsearch;v=json.load(sys.stdin);s={};exec(compile(v['source'],'disk_probe','exec'),s);c=Elasticsearch('https://elasticsearch:9200',basic_auth=('elastic',v['password']),ca_certs='/run/certs/ca.crt',request_timeout=30,max_retries=0);print(json.dumps(s['es_disk_observation'](c)))"
        observed = engine.json(['run', '--rm', '-i', '--network', project + '_default',
            '-v', str(state / 'tls/ca.crt') + ':/run/certs/ca.crt:ro', '--entrypoint', 'python',
            image, '-c', probe],
            input=json.dumps({'source': Path(disk_resources.__file__).read_text(),
                              'password': (state / 'secrets/elastic_password').read_text().strip()}))
        if abs(observed['data']['total_in_bytes'] - locations['elasticsearch']['total_bytes']) > 1024**2:
            raise ValueError('Elasticsearch and host filesystem observations disagree')
        locations['elasticsearch']['free_bytes'] = min(locations['elasticsearch']['free_bytes'], observed['data']['available_in_bytes'])
    elif not fresh:
        raise ValueError('Existing Elasticsearch missing; storage budget cannot be verified')
    else:
        # The common fresh named data volume uses Docker's allocation pool.
        locations['elasticsearch'] = dict(locations['docker'])
    if backup_root:
        locations['backup'] = disk_resources.validate_backup_root(backup_root, state, hardware['docker_root'], es_paths)
    amount = sum(row['copy_upper_bound_bytes'] for row in rows)
    storage = disk_resources.disk_budget(locations, online_bytes=0 if online_complete else amount, stopped_bytes=amount,
        adoption_bytes=adopted_bytes, preflight_bytes=0 if online_complete else amount, build_bytes=build_bytes,
        ingress_bytes=ingress_bytes, safety_bytes=max(value['resources']['headroom_bytes'],
            value['resources']['fresh_free_bytes'] if fresh else value['resources']['upgrade_free_bytes']),
        es_policy=observed['policy'] if observed else disk_resources.initial_disk_policy())
    storage['sqlite'] = rows;storage['sqlite_wal_bytes'] = sum(row['wal_bytes'] for row in rows)
    storage['elasticsearch'] = observed;storage['ingress_reserve_bytes'] = ingress_bytes
    storage['es_policy_source'] = 'actual_cluster' if observed else 'fresh_pinned_defaults_requires_startup_readback'
    storage['backup_root'] = str(backup_root) if backup_root else None
    storage['candidate_already_built'] = build_bytes == 0
    storage['new_backup_upper_bound_bytes'] = 2 * amount
    storage['elasticsearch_allocated_bytes'] = sum(backups.allocated_bytes(path) for path in es_paths)
    storage['retained_upgrades_allocated_bytes'] = backups.allocated_bytes(state / 'runtime/upgrades')
    images = {obj['Image'] for obj in objects.values()}
    inspected = [engine.json(['image', 'inspect', identifier])[0] for identifier in images]
    storage['existing_images'] = [{'id': row['Id'], 'uncompressed_bytes': row['Size']} for row in inspected]
    storage['image_sizes_share_layers'] = True
    return storage


def before_build(engine, workspace, state, *, build_bytes, backup_root=None, ingress_bytes=1024**3, project='cloud-soc-central'):
    """Resource-only, non-applicable plan. Build cost is an operator-supplied bound."""
    if type(build_bytes) is not int or build_bytes < 1024**3:
        raise ValueError('Declare at least 1GiB of candidate/build scratch before building')
    state = Path(state).resolve();value = policy(workspace);objects = containers(engine, project)
    if (state / 'runtime/pending.json').exists():
        raise ValueError('Recover the interrupted upgrade before building another candidate')
    current = state / 'runtime/contract.json'
    contract, adoption = build_contract(value, adoption_containers(objects, state), state,
        existing=json.loads(current.read_text()) if current.exists() else None)
    rows = backups.inventory(state, contract, adoption)
    amount = sum(row['copy_upper_bound_bytes'] for row in rows)
    machine = hardware(engine, state, project)
    probe_image = objects.get('portal', {}).get('Image')
    if objects and not probe_image:
        raise ValueError('Existing app image required for pre-build ES observation')
    storage = storage_budget(engine, state, probe_image, project, objects, rows, amount, machine, value,
        backup_root=backup_root, ingress_bytes=ingress_bytes, build_bytes=build_bytes, fresh=not objects)
    return {'applicable': False, 'kind': 'before_build_budget', 'build_upper_bound_bytes': build_bytes,
            'resources': resource_check(value, machine, fresh=not objects, storage=storage,
                database_bytes=amount, backup_memory_bytes=max((r['copy_upper_bound_bytes'] for r in rows), default=0)),
            'next': 'Build only within the declared bound, then create a new full manage.py plan'}


def compose_environment(state, image, objects):
    env = {'SOC_STATE_DIR': str(state), 'SOC_RUNTIME_IMAGE': image}
    if 'portal' in objects:
        from urllib.parse import urlsplit
        host = urlsplit(public_environment(objects['portal'])['SOC_PUBLIC_URL']).hostname
        if not host:
            raise ValueError('Missing public portal origin')
        env['SOC_PUBLIC_HOST'] = host
    return env


def inspect_prerequisites(engine, state, image, project, value, contract, adoption):
    runtime = state / 'runtime';keys, states, mounts = {}, {}, []
    # The container sees disposable, integrity-checked standalone copies only.
    # It never receives a writable mount of operational SQLite directories.
    with tempfile.TemporaryDirectory(prefix='runtime-preflight-', dir=state.parent) as temporary:
        copies = Path(temporary)
        for name in WORKERS:
            row = adoption.get(name, {})
            key = Path(row['key_source']) if 'key_source' in row else runtime / 'keys' / (name + '.key')
            encoded = reusable_key(key)
            if encoded:
                keys[name] = encoded
            db = Path(row['state_source']) if 'state_source' in row else runtime / 'state' / name / contract['workers'][name]['state_file']
            if db.is_file():
                folder = copies / name;folder.mkdir(mode=0o700)
                copy = folder / db.name;backup_database(db, copy)
                target = '/adopted/' + name
                mounts += ['-v', str(folder) + ':' + target + ':ro']
                states[name] = target + '/' + db.name
        return engine.json(['run', '--rm', '-i', '--network', project + '_default', '--user', '0:0',
            '-v', str(state / 'tls/ca.crt') + ':/run/certs/ca.crt:ro', *mounts,
            '--entrypoint', 'python', image, '-m', 'cloud_soc.deployment.preflight'],
            input=json.dumps({'password': (state / 'secrets/elastic_password').read_text().strip(),
                              'policy': value, 'contract': contract, 'keys': keys, 'states': states,
                              'notification_key': reusable_key(runtime / 'keys/slack-notifier.key')}))


def adoption_containers(objects, state):
    """Resolve stopped, unactivated managed workers from a verified recovery contract."""
    result = deepcopy(objects)
    for name in WORKERS:
        obj = result.get(name)
        if not obj or obj.get('State', {}).get('Running'):
            continue
        if obj.get('Config', {}).get('Cmd') != ['python', '-m', 'cloud_soc.deployment.worker', '--service', name]:
            continue
        retry = Path(state) / 'runtime/retry.json'
        if not retry.is_file():
            raise ValueError('Unactivated managed state has no verified recovery receipt')
        pointer = json.loads(retry.read_text())
        path = checked_path(Path(pointer['run']) / 'interrupted-contract.json', Path(state) / 'runtime/upgrades', file=True)
        if hashlib.sha256(path.read_bytes()).hexdigest() != pointer['contract_sha256']:
            raise ValueError('Retained state contract changed')
        row = json.loads(path.read_text())['workers'][name]
        obj['Config']['Cmd'] = command(row['module'], row['options'])
        retained_plan = json.loads(checked_path(Path(pointer['run']) / 'plan.json', Path(state) / 'runtime/upgrades', file=True).read_text()) if (Path(pointer['run']) / 'plan.json').is_file() else {}
        if name in retained_plan.get('new_workers', []):
            obj['UnactivatedRuntime'] = True
    return result


def snapshot(engine, workspace, state, image, project='cloud-soc-central', *, backup_root=None, ingress_bytes=1024**3):
    workspace, state = Path(workspace).resolve(), Path(state).resolve()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', project) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}', image):
        raise ValueError('Invalid image/project identity')
    checked_path(state / 'compose.env', state, file=True)
    checked_path(state / 'notifications', state)
    if (state / 'runtime/pending.json').exists():
        raise ValueError('Interrupted upgrade retained; run manage.py recover before making a new plan')
    if (state / 'runtime/preservation-failed.json').exists():
        raise ValueError('Data preservation failure retained; reconcile the quiesced baseline before another upgrade')
    value = policy(workspace);objects = containers(engine, project)
    capabilities = execution.compose_capabilities(engine)
    inventory = worker_inventory(engine, project)
    active = active_command(state, objects)
    env = compose_environment(state, image, objects)
    original = engine.json(['compose', *active, 'config', '--format', 'json']) if active else {}
    runtime = state / 'runtime'
    current = json.loads((runtime / 'contract.json').read_text()) if (runtime / 'contract.json').is_file() else None
    adopted_objects = adoption_containers(objects, state)
    contract, adoption = build_contract(value, adopted_objects, state, existing=current)
    ledger = runtime / 'migrations.json'
    if ledger.exists():
        history = json.loads(checked_path(ledger, state, file=True).read_text())
        if (history.get('version', 0) > value['version'] or set(history.get('migrations', {})) - set(value['migrations'])
                or any(row.get('state') not in ('applying', 'applied', 'failed') for row in history.get('migrations', {}).values())
                or (history.get('version') == value['version'] and any(row.get('policy_sha256') != digest(value)
                    for row in history.get('migrations', {}).values() if row.get('state') == 'applied'))):
            raise ValueError('Migration journal incompatible; no services stopped')
    for name in ALL_WORKERS:
        reusable_key(runtime / 'keys' / (name + '.key'))
    fresh = not (runtime / 'current.json').exists() and (not objects or (runtime / 'install.json').is_file())
    classification, frozen = (execution.verify_previous(engine, active, original, objects, project) if active
                               else ({'defined': [], 'running': [], 'stopped': sorted(objects), 'residual_stopped': [], 'stop': []}, {}))
    rows = backups.inventory(state, contract, adoption)
    if fresh and rows and not (runtime / 'install.json').is_file():
        raise ValueError('Existing databases without an installation receipt; fresh bootstrap refused')
    adoption_bytes = sum(path.stat().st_size + (Path(str(path)+'-wal').stat().st_size if Path(str(path)+'-wal').exists() else 0)
                         for _, paths in adopted_files({'state': str(state), 'adoption': adoption, 'contract': contract}, runtime) for path in paths)
    machine = hardware(engine, state, project)
    storage = storage_budget(engine, state, image, project, objects, rows, adoption_bytes, machine, value,
                             backup_root=backup_root, ingress_bytes=ingress_bytes, fresh=fresh)
    resources = resource_check(value, machine, fresh=fresh, storage=storage,
                               database_bytes=sum(row['copy_upper_bound_bytes'] for row in rows), adoption_bytes=adoption_bytes,
                               backup_memory_bytes=max((row['copy_upper_bound_bytes'] for row in rows), default=0))
    selected = observed_services(objects)
    fingerprints = protected_hashes(state)
    for obj in objects.values():
        for mount in obj.get('Mounts', []):
            path = Path(mount['Source'])
            if path.is_file():
                if path.is_symlink():
                    raise ValueError('Symlinked protected bind file')
                if path.resolve() != (state / 'runtime/contract.json').resolve():
                    fingerprints[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    source = source_files(workspace)
    candidate = engine.json(['image', 'inspect', image])[0]['Id']
    # Verify actual image bytes; labels and checkout SHA alone are insufficient.
    script = "import hashlib,json,pathlib,sys;from cloud_soc.deployment.contract import policy,validate_rules;root=pathlib.Path('/app');m=json.load(sys.stdin);assert all((root/p).is_file() and hashlib.sha256((root/p).read_bytes()).hexdigest()==h for p,h in m.items());validate_rules(policy(root));print('verified')"
    if engine.run(['run', '--rm', '--network', 'none', '-i', '--entrypoint', 'python', image, '-c', script], input=json.dumps(source)).strip() != 'verified':
        raise ValueError('Candidate source verification failed')
    if objects and not active and not fresh:
        raise ValueError('Existing infrastructure has no adoption receipt; not a fresh installation')
    prerequisites = {'state': 'fresh_bootstrap_required'}
    if not fresh and resources['ok']:
        prerequisites = inspect_prerequisites(engine, state, image, project, value, contract, adoption)
    elif not fresh:
        prerequisites = {'state': 'resource_budget_refused_before_sqlite_copy'}
    # Only stable configuration participates in the stale-plan guard, not progress counters.
    identity = {'containers': selected, 'protected_sha256': fingerprints, 'image': candidate,
                'source_sha256': digest(source), 'prerequisites': prerequisites,
                'execution': digest(frozen), 'disk_policy': storage['elasticsearch']['policy'] if storage['elasticsearch'] else None,
                'backup_root': storage['backup_root'], 'ingress_reserve_bytes': ingress_bytes,
                'migration_sha256': backups.sha256(ledger) if ledger.exists() else None}
    result = {'plan_version': 2, 'policy': value, 'workspace': str(workspace), 'state': str(state), 'project': project,
        'image': image, 'image_id': candidate, 'source': source, 'source_sha256': digest(source),
        'fresh': fresh, 'contract': contract, 'adoption': adoption, 'resources': resources,
        'observed': selected, 'protected_sha256': fingerprints, 'previous_compose': active,
        'site': site_overlay(original, objects) if original else {}, 'compose_environment': env,
        'new_workers': [n for n in ALL_WORKERS if n not in objects or n not in classification['defined']
                        or adopted_objects.get(n, {}).get('UnactivatedRuntime')], 'prerequisites': prerequisites,
        'worker_inventory': inventory, 'fingerprint': digest(identity)}
    desired = engine.json(['compose', '--profile', 'initialization', '--project-name', project, '--env-file', str(state / 'compose.env'),
        '-f', str(workspace / 'deploy/server/compose.yaml'), '-f', '-', 'config', '--format', 'json'],
        input=json.dumps(configure_site(result, runtime)), env=env)
    result['compose_validation'] = validate_rendered(value, desired, image)
    result['previous_execution'] = frozen;result['service_classification'] = classification
    result['compose_capabilities'] = capabilities
    result['backup_root'] = storage['backup_root'];result['ingress_reserve_bytes'] = ingress_bytes
    return result


def summary(plan):
    return {k: plan[k] for k in ('plan_version', 'image_id', 'source_sha256', 'fresh', 'resources', 'new_workers', 'fingerprint', 'prerequisites')} | {
        'required_workers': list(ALL_WORKERS), 'verified_rules': list(plan['policy']['verified_rules']),
        'preserve': ['data', 'state_identity', 'checkpoints', 'certificates', 'existing_key_material', 'site_endpoints'],
        'permissions': 'additive_exact_runtime_grants_with_restricted_scope_refusal',
        'infrastructure_changes': {'kibana': '1536MiB limit / 1024MiB Node heap', 'elasticsearch': '3072MiB limit / 1536MiB heap'}}


def configure_site(plan, runtime):
    site = deepcopy(plan['site']) or {'services': {}}
    portal = site.setdefault('services', {}).setdefault('portal', {})
    mounts = portal.setdefault('volumes', [])
    # Compose merges by target: preserve the inspected site mounts and add the managed contract.
    mounts.append({'type': 'bind', 'source': str(runtime / 'contract.json'), 'target': '/run/runtime/contract.json', 'read_only': True})
    for name in APP_SERVICES:
        site['services'].setdefault(name, {})['image'] = plan['image']
    return site


def adopted_files(plan, runtime):
    """Copy only a worker's database and its required AUTH early-notice companion."""
    for name, row in plan['adoption'].items():
        if 'state_source' not in row:
            continue
        source = checked_path(Path(row['state_source']), plan['state'], file=True)
        if source.parent.resolve() == (runtime / 'state' / name).resolve():
            continue
        paths = [source]
        early = Path(str(source) + '.early.sqlite')
        if early.exists() and plan['contract']['workers'][name]['options'].get('--early-auth'):
            paths.append(checked_path(early, plan['state'], file=True))
        yield name, paths


def copy_adopted_state(plan, runtime):
    selected = dict(adopted_files(plan, runtime))
    for name in WORKERS:
        folder = runtime / 'state' / name;folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        adoption = plan['adoption'].get(name, {})
        if 'state_source' in adoption:
            source = Path(adoption['state_source'])
            checked_path(source, plan['state'], file=True)
            if source.parent.resolve() == folder.resolve():
                # A failed first attempt already prepared this independent worker's state.
                # Reuse it in place; never rename its source and then try to copy itself.
                continue
            for path in selected[name]:
                checked_path(path, plan['state'], file=True)
                dest = folder / path.name
                if dest.exists():
                    if (runtime / 'current.json').exists():
                        raise ValueError('Active managed state cannot be re-adopted')
                    # Preserve an unactivated copy before retrying from the resumed legacy DB.
                    archived = folder / (dest.name + '.unactivated-' + datetime.now(timezone.utc).strftime('%H%M%S%f'))
                    os.replace(dest, archived)
                    for suffix in ('-wal', '-shm'):
                        sidecar = Path(str(dest) + suffix)
                        if sidecar.exists():
                            checked_path(sidecar, plan['state'], file=True)
                            os.replace(sidecar, Path(str(archived) + suffix))
                backup_database(path, dest)
                if os.name == 'posix':
                    os.chown(dest, 1000, 1000)
        if os.name == 'posix':
            os.chown(folder, 1000, 1000)


def apply(engine, plan, *, poll=None):
    workspace, state = Path(plan['workspace']), Path(plan['state']);runtime = state / 'runtime'
    if not plan['resources']['ok']:
        raise ResourceBudgetError(plan['resources'])
    if (runtime / 'preservation-failed.json').exists():
        raise ValueError('Data preservation failure requires explicit reconciliation; no mutation performed')
    with lock(runtime):
        options = ({'backup_root': plan.get('backup_root'), 'ingress_bytes': plan['ingress_reserve_bytes']}
                   if plan.get('plan_version') == 2 else {})
        current = snapshot(engine, workspace, state, plan['image'], plan['project'], **options)
        if current['fingerprint'] != plan['fingerprint']:
            raise ValueError('Deployment changed after planning; no mutation performed')
        if not current['resources']['ok']:
            raise ResourceBudgetError(current['resources'])
        for field in ('policy', 'site', 'observed', 'protected_sha256', 'previous_compose', 'source', 'image_id', 'adoption'):
            if current[field] != plan[field]:
                raise ValueError('Reviewed plan was modified; no mutation performed')
        for field in ('previous_execution', 'service_classification', 'backup_root', 'ingress_reserve_bytes'):
            if current.get(field) != plan.get(field):
                raise ValueError('Reviewed recovery or storage plan was modified')
        existing_receipt = runtime / 'current.json'
        if existing_receipt.is_file():
            receipt = json.loads(existing_receipt.read_text())
            actual = containers(engine, plan['project'])
            if (receipt.get('source_sha256') == plan['source_sha256'] and receipt.get('image_id') == plan['image_id']
                    and receipt.get('policy_sha256') == digest(plan['policy'])
                    and receipt.get('execution_sha256') == digest({name: service_signature(obj) for name, obj in actual.items() if name in SERVICES})
                    and set(actual) >= set(SERVICES) and all(service_running(actual[name]) for name in SERVICES)):
                return {**receipt, 'unchanged': True}
        from cloud_soc.deployment.contract import stamp
        previous_contract = json.loads((runtime / 'contract.json').read_text()) if (runtime / 'contract.json').is_file() else None
        expected_contract, _ = build_contract(plan['policy'], adoption_containers(containers(engine, plan['project']), state), state,
            now=stamp(plan['contract']['created_at']), existing=previous_contract)
        if expected_contract != plan['contract']:
            raise ValueError('Reviewed state/command plan was modified')
        run = runtime / 'upgrades' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        run.mkdir(mode=0o700, parents=True)
        backups.fsync_directory(run.parent);backups.fsync_directory(runtime)
        if plan['fresh'] and not (runtime / 'install.json').exists():
            atomic_json(runtime / 'install.json', {'version': plan['policy']['version'], 'started': True})
        atomic_json(run / 'plan.json', plan)
        active = plan['previous_compose']
        old_objects = containers(engine, plan['project'])
        old_contract = (runtime / 'contract.json').read_bytes() if (runtime / 'contract.json').is_file() else None
        canonical = ['compose', '--project-name', plan['project'], '--env-file', str(state / 'compose.env'),
                     '-f', str(workspace / 'deploy/server/compose.yaml'), '-f', str(runtime / 'site.json')]
        old_running = {name: obj for name, obj in old_objects.items() if obj.get('State', {}).get('Running')}
        recovery_compose = None
        if active and plan.get('previous_execution'):
            frozen = run / 'previous.compose.json'
            atomic_json(frozen, execution.literal_config(plan['previous_execution']))
            recovery_compose = ['--project-name', plan['project'], '-f', str(frozen)]
        atomic_json(run / 'recovery.json', {'previous_compose': active, 'old_names': list(old_running),
            'recovery_compose': recovery_compose,
            'recovery_compose_sha256': backups.sha256(frozen) if recovery_compose else None,
            'old_services': {name: service_signature(obj) for name, obj in old_running.items()},
            'old_contract': json.loads(old_contract) if old_contract else None,
            'old_current': json.loads((runtime / 'current.json').read_text()) if (runtime / 'current.json').is_file() else None,
            'canonical': canonical, 'environment': plan['compose_environment']})
        atomic_json(runtime / 'pending.json', {'run': str(run)})
        def stage(name):
            atomic_json(run / 'stage.json', {'stage': name, 'utc': datetime.now(timezone.utc).isoformat()})
        try:
            stage('online_backup')
            for name, digest_value in plan['protected_sha256'].items():
                p = Path(name)
                if hashlib.sha256(p.read_bytes()).hexdigest() != digest_value:
                    raise ValueError('Protected file changed before backup')
                # Flat names avoid drive-anchor escapes and Windows path limits.
                # The protected plan records the source-to-hash mapping.
                target = run / 'settings' / digest(str(p))[:24]
                if target.exists():
                    raise ValueError('Protected backup target collision')
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True);shutil.copy2(p, target)
                target.chmod(0o600)
                if backups.sha256(target) != digest_value:
                    raise ValueError('Protected settings backup differs')
            backup_run = Path(plan['backup_root']) / ('cloud-soc-' + run.name) if plan.get('backup_root') else run
            rows = backups.inventory(state, plan['contract'], plan['adoption'])
            online = backups.snapshot_set(rows, backup_run / 'online', backup_database)
            atomic_json(run / 'backup-location.json', {'path': str(backup_run), 'online_manifest_sha256': backups.sha256(backup_run / 'online/manifest.json')})
            if plan.get('plan_version') == 2:
                # Writers may have grown WAL during online backup. Re-budget the
                # remaining phases, counting the completed copy as existing usage.
                rows = backups.inventory(state, plan['contract'], plan['adoption'])
                machine = hardware(engine, state, plan['project'])
                remaining = storage_budget(engine, state, plan['image_id'], plan['project'], old_objects, rows,
                    plan['resources'].get('adoption_copy_bytes', 0), machine, plan['policy'],
                    backup_root=plan.get('backup_root'), ingress_bytes=plan['ingress_reserve_bytes'],
                    fresh=plan['fresh'], online_complete=True)
                remaining_check = resource_check(plan['policy'], machine, fresh=plan['fresh'], storage=remaining,
                    backup_memory_bytes=max((row['copy_upper_bound_bytes'] for row in rows), default=0))
                atomic_json(run / 'remaining-resource-check.json', remaining_check)
                if not remaining_check['ok']:
                    raise ResourceBudgetError(remaining_check)
                if any(backups.sha256(Path(name)) != value for name, value in plan['protected_sha256'].items()):
                    raise ValueError('Protected files changed during backup; services not stopped')
            stage('quiescing')
            if active:
                stop = plan['service_classification']['stop'] if 'service_classification' in plan else [n for n in APP_SERVICES if n in old_running]
                if stop:
                    engine.run(['compose', *active, 'stop', *stop])
            worker_inventory(engine, plan['project'], stopped=True)
            if plan.get('plan_version') == 2 and any(obj.get('State', {}).get('Running') for name, obj in containers(engine, plan['project']).items() if name in APP_SERVICES):
                raise ValueError('Application writers not fully stopped; quiesced baseline refused')
            stage('quiesced_backup')
            rows = backups.inventory(state, plan['contract'], plan['adoption'])
            backups.snapshot_set(rows, backup_run / 'stopped', backup_database, previous=online)
            saved_rows = portal_rows(state)
            saved_docs = {} if plan['fresh'] else immutable_documents(engine, state, plan['image'], plan['project'])
            atomic_json(run / 'preservation-before.json', {'portal_rows': saved_rows, 'documents': saved_docs})
            stage('adoption')
            if not old_contract:
                copy_adopted_state(plan, runtime)
            contract = deepcopy(plan['contract']);contract['prepared'] = False
            atomic_json(runtime / 'contract.json', contract, uid=1000)
            execution_plan = {**plan, 'image': plan['image_id']} if plan.get('plan_version') == 2 else plan
            atomic_json(runtime / 'site.json', configure_site(execution_plan, runtime))
            env = {**plan['compose_environment'], 'SOC_RUNTIME_IMAGE': execution_plan['image']}
            rendered = engine.json(canonical + ['config', '--format', 'json'], env=env)
            if not set(SERVICES) <= set(rendered['services']):
                raise ValueError('Common Compose omitted required services')
            for name in APP_SERVICES:
                if rendered['services'][name]['image'] != execution_plan['image']:
                    raise ValueError('Mixed application image versions refused')
            if plan['fresh']:
                engine.run(canonical + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'elasticsearch'], env=env)
                if poll:
                    poll(engine, 'elasticsearch', plan['project'])
                if plan.get('plan_version') == 2:
                    measured = storage_budget(engine, state, plan['image_id'], plan['project'], containers(engine, plan['project']),
                        backups.inventory(state, plan['contract'], plan['adoption']), 0, hardware(engine, state, plan['project']),
                        plan['policy'], backup_root=plan.get('backup_root'), ingress_bytes=plan['ingress_reserve_bytes'],
                        fresh=True, online_complete=True)
                    atomic_json(run / 'fresh-es-disk-readback.json', measured)
                    if not measured['ok'] or measured.get('es_policy_source') != 'actual_cluster':
                        raise ResourceBudgetError({'issues': ['fresh_es_disk_readback_failed'], 'disk': measured})
                bootstrap = runtime / 'bootstrap.json'
                if bootstrap.exists():
                    if json.loads(bootstrap.read_text()).get('state') != 'complete':
                        raise ValueError('Interrupted bootstrap requires explicit reconciliation; never automatically rerun')
                else:
                    atomic_json(bootstrap, {'state': 'running'})
                    engine.run(canonical + ['--profile', 'initialization', 'run', '--rm', '--no-deps', '--pull', 'never', 'bootstrap'], env=env)
                    atomic_json(bootstrap, {'state': 'complete'})
            keys = {name: Path(row['key_source']).read_text().strip() for name, row in plan['adoption'].items() if 'key_source' in row}
            password = (state / 'secrets/elastic_password').read_text().strip()
            stage('migrations')
            migration = engine.json(['run', '--rm', '-i', '--network', plan['project'] + '_default', '--user', '0:0',
                '-v', str(state / 'tls/ca.crt') + ':/run/certs/ca.crt:ro', '-v', str(runtime) + ':/deployment',
                '-v', str(state / 'notifications') + ':/notifications',
                '--entrypoint', 'python', plan['image'], '-m', 'cloud_soc.deployment.migrations'],
                input=json.dumps({'password': password, 'policy': plan['policy'], 'contract': contract, 'existing_keys': keys}))
            contract['prepared'] = True
            atomic_json(runtime / 'contract.json', contract, uid=1000)
            try:
                # Initial notices may legitimately advance after detector resume.
                # Compare the migration's effects while all writers are fenced.
                preservation = immutable_documents(engine, state, plan['image'], plan['project'], before=saved_docs)
            except Exception as error:
                raise PreservationError('Existing alert/notice preservation could not be verified') from error
            # Check saved mutable portal rows while its writer is still stopped.
            background = [name for name in SERVICES if name not in ('portal', 'gateway')]
            stage('background_readiness')
            engine.run(canonical + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', *background], env=env, timeout=300)
            if poll:
                for name in background:
                    poll(engine, name, plan['project'])
            after_rows = portal_rows(state)
            if any(not set(rows) <= set(after_rows.get(name, [])) for name, rows in saved_rows.items()):
                raise PreservationError('Existing case/dashboard rows changed')
            engine.run(canonical + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'portal', 'gateway'], env=env, timeout=300)
            stage('portal_readiness')
            if poll:
                for name in ('portal', 'gateway'):
                    poll(engine, name, plan['project'])
            after = containers(engine, plan['project'])
            if set(worker_inventory(engine, plan['project'])) != set(ALL_WORKERS):
                raise ValueError('Exactly one instance of every common worker is required')
            for name in SERVICES:
                if name not in after or not service_running(after[name]):
                    raise ValueError('Required service not running')
                if name in APP_SERVICES and after[name]['Image'] != plan['image_id']:
                    raise ValueError('Runtime image differs from verified release')
            for name, h in plan['protected_sha256'].items():
                if hashlib.sha256(Path(name).read_bytes()).hexdigest() != h:
                    raise ValueError('Existing key/certificate/site file changed')
            receipt = {'version': plan['policy']['version'], 'policy_sha256': digest(plan['policy']), 'runtime_ready': True, 'source_sha256': plan['source_sha256'],
                'image_id': plan['image_id'], 'migrations': migration, 'preservation': preservation,
                'preservation_phase': 'after_migrations_before_writer_resume',
                'execution_sha256': digest({name: service_signature(obj) for name, obj in after.items() if name in SERVICES}),
                'portal_saved_rows_preserved': sum(len(rows) for rows in saved_rows.values()), 'new_workers': plan['new_workers'],
                'live_ingestion_acceptance': 'not_yet_verified', 'utc': datetime.now(timezone.utc).isoformat()}
            atomic_json(run / 'applied.json', receipt)
            atomic_json(runtime / 'current.json', receipt)
            # A receipt is also the unambiguous input for the next upgrade.
            atomic_json(run / 'compose.active.json', ['docker', *canonical])
            atomic_json(runtime / 'compose.active.json', ['docker', *canonical])
            stage('complete')
            durable_unlink(runtime / 'pending.json')
            return receipt
        except BaseException as error:
            # Revert execution only. Original DBs were retained; migrated DBs are never rewound.
            failure = {'state': 'restoring', 'error_type': type(error).__name__, 'databases_rewound': False}
            atomic_json(run / 'failed.json', failure)
            if isinstance(error, PreservationError):
                atomic_json(runtime / 'preservation-failed.json', {'run': str(run), 'baseline': 'preservation-before.json',
                    'reason': 'quiesced_data_preservation_failed_or_unverified', 'automatic_retry_allowed': False})
            try:
                _restore_execution(engine, runtime, run, json.loads((run / 'recovery.json').read_text()))
            except BaseException as recovery_error:
                atomic_json(run / 'failed.json', {**failure, 'state': 'recovery_failed',
                    'recovery_error_type': type(recovery_error).__name__, 'old_execution_restored': False})
                raise
            atomic_json(run / 'failed.json', {'state': 'failed', 'error_type': type(error).__name__,
                'old_execution_restored': bool(active), 'databases_rewound': False})
            durable_unlink(runtime / 'pending.json')
            raise


def service_running(obj):
    state = obj.get('State', {})
    return bool(state.get('Running') and state.get('Status', 'running') == 'running'
                and not state.get('Restarting') and not state.get('OOMKilled')
                and state.get('Health', {}).get('Status', 'healthy') == 'healthy')


def service_signature(obj):
    config = obj.get('Config', {});host = obj.get('HostConfig', {})
    return {'image': obj.get('Image'), 'command': config.get('Cmd'), 'entrypoint': config.get('Entrypoint'),
        'mounts': sorted((m['Destination'], m['Source'], m.get('Type', 'bind'), m.get('RW', True)) for m in obj.get('Mounts', [])),
        'memory': host.get('Memory'), 'ports': host.get('PortBindings'),
        'read_only': host.get('ReadonlyRootfs'), 'security_opt': host.get('SecurityOpt'),
        'cap_drop': host.get('CapDrop'), 'cap_add': host.get('CapAdd'), 'user': config.get('User'),
        'network_mode': host.get('NetworkMode'),
        'environment_sha256': digest(sorted(config.get('Env', [])))}


def _restore_execution(engine, runtime, run, saved):
    active = saved.get('recovery_compose') or saved['previous_compose']
    if saved.get('recovery_compose'):
        frozen = checked_path(run / 'previous.compose.json', runtime, file=True)
        if backups.sha256(frozen) != saved['recovery_compose_sha256']:
            raise ValueError('Frozen previous execution changed; recovery journal retained')
    project = saved['canonical'][saved['canonical'].index('--project-name') + 1]
    present = containers(engine, project)
    signatures = saved.get('old_services', {})
    original_plan = json.loads((run / 'plan.json').read_text()) if (run / 'plan.json').exists() else {}
    def matches(name, obj):
        if not obj:
            return False
        if name in signatures:
            # JSON protection records encode the sorted mount tuples as lists.
            return digest(service_signature(obj)) == digest(signatures[name])
        previous = original_plan.get('observed', {}).get(name)
        if previous:
            current = service_signature(obj)
            mounts = sorted((m['Destination'], m['Source'], m.get('Type', 'bind'), m.get('RW', True)) for m in previous.get('mounts', []))
            return current['image'] == previous['image'] and current['command'] == previous['command'] and current['mounts'] == mounts
        return False
    targets = [project + '-' + name + '-1' for name in SERVICES if name != 'elasticsearch' and name in present
        and (name not in saved['old_names'] or not matches(name, present[name]))]
    if targets:
        engine.run(['stop', *targets])
    # Restore metadata before starting the previous image; never restore a database.
    for name, value in (('contract.json', saved['old_contract']), ('current.json', saved['old_current'])):
        path = runtime / name
        if value is not None:
            atomic_json(path, value, uid=1000 if name == 'contract.json' else None)
        elif path.exists() and (active or name != 'contract.json'):
            shutil.copy2(path, run / ('interrupted-' + name));path.unlink()
    if active:
        needed = [name for name in saved['old_names'] if not matches(name, present.get(name)) or not service_running(present.get(name, {}))]
        if needed:
            engine.run(['compose', *active, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', *needed], timeout=300)
        deadline = time.monotonic() + 180
        while True:
            restored = containers(engine, project)
            if all(name in restored and service_running(restored[name]) for name in saved['old_names']):
                break
            if time.monotonic() >= deadline:
                raise ValueError('Previous services not ready; recovery journal retained')
            time.sleep(0.5)
        if (signatures or original_plan.get('observed')) and any(not matches(name, restored[name]) for name in saved['old_names']):
            raise ValueError('Previous service identity differs; recovery journal retained')
        expected = set(saved['old_names']) & set(ALL_WORKERS)
        if set(worker_inventory(engine, project)) != expected:
            raise ValueError('Unexpected worker after recovery; journal retained')
        retained = run / 'interrupted-contract.json'
        if not saved['old_contract'] and retained.is_file():
            atomic_json(runtime / 'retry.json', {'run': str(run),
                'contract_sha256': hashlib.sha256(retained.read_bytes()).hexdigest()})
        atomic_json(runtime / 'compose.active.json', ['docker', 'compose', *active])


def recover(engine, state):
    """Restore interrupted execution from the protected journal without restoring DBs."""
    state = Path(state).resolve();runtime = state / 'runtime'
    with lock(runtime):
        pending = runtime / 'pending.json'
        if not pending.exists():
            return {'recovery_required': False}
        run = checked_path(json.loads(pending.read_text())['run'], runtime / 'upgrades')
        saved = json.loads(checked_path(run / 'recovery.json', runtime, file=True).read_text())
        active = saved['previous_compose']
        _restore_execution(engine, runtime, run, saved)
        atomic_json(run / 'recovered.json', {'old_execution_restored': bool(active), 'databases_rewound': False})
        durable_unlink(pending)
        return {'recovery_required': True, 'old_execution_restored': bool(active), 'databases_rewound': False,
                'fresh_install_can_resume': not bool(active)}
