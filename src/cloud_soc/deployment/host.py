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

from cloud_soc.deployment.contract import (ALL_WORKERS, APP_SERVICES, SERVICES, WORKERS, build_contract, digest,
    policy, resource_check, source_files, validate_rendered)
from cloud_soc.deployment.migrations import atomic_json


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
    if (root / 'notifications/slack.key').exists():
        paths.append(root / 'notifications/slack.key')
    # Site-specific bind mounts are included separately in the runtime snapshot.
    return {str(checked_path(p, root, file=True)): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def databases(state):
    return [checked_path(p, state, file=True) for p in Path(state).rglob('*')
            if p.suffix in ('.sqlite', '.sqlite3') and 'upgrades' not in p.relative_to(state).parts
            and 'backup' not in p.relative_to(state).parts]


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


def active_command(state, objects, *, workspace=None):
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
            observed = [value[i+1] for i, v in enumerate(value[:-1]) if v == '-f']
            if observed == files:
                allowed_roots = [Path(state).parent.parent.resolve()]
                if workspace is not None:
                    allowed_roots.append(Path(workspace).resolve())
                for name in observed:
                    selected = next((root for root in allowed_roots
                                     if Path(name).resolve().is_relative_to(root)), None)
                    if selected is None:
                        raise ValueError('Active Compose file escapes approved state/workspace roots')
                    checked_path(name, selected, file=True)
                return value[2:]
    raise ValueError('Cannot identify the exact active Compose command; provide its protected receipt')


def public_environment(obj):
    allowed = {'SOC_PUBLIC_URL', 'SOC_PUBLIC_HOST', 'SOC_PORTAL_LAN_ORIGIN', 'SOC_ENROLLMENT_ENABLED',
        'SOC_ELASTIC_ENDPOINT', 'SOC_AGENT_ENDPOINT', 'SOC_ADMIN_ALLOWED_CIDRS', 'SOC_USERS_FILE',
        'SOC_LOG_ACCESS_POLICY_FILE', 'SOC_LOG_FORMAT', 'SOC_INTERNAL_ES_URL', 'SOC_CA_FILE',
        'SOC_STATE_DIR', 'SOC_ADMIN_USER', 'SOC_ADMIN_HASH_FILE', 'SOC_ISSUER_PASSWORD_FILE', 'SOC_MONITOR_PASSWORD_FILE'}
    return {k: v for item in obj['Config'].get('Env', []) for k, _, v in [item.partition('=')] if k in allowed}


def site_overlay(rendered, objects):
    """Keep explicitly reviewed site mounts/endpoints, never historical worker commands."""
    result = {'services': {}, 'secrets': deepcopy(rendered.get('secrets', {})),
              'volumes': deepcopy(rendered.get('volumes', {})), 'networks': deepcopy(rendered.get('networks', {}))}
    for name in ('portal', 'enrollment-cleanup', 'gateway', 'elasticsearch', 'kibana'):
        if name not in rendered.get('services', {}):
            continue
        old = rendered['services'][name]
        row = {k: deepcopy(old[k]) for k in ('volumes', 'ports') if k in old}
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
            'map_count': int(Path('/proc/sys/vm/max_map_count').read_text())}


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
            if key.is_file():
                keys[name] = key.read_text().strip()
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
                              'notification_key': (runtime / 'keys/slack-notifier.key').read_text().strip()
                              if (runtime / 'keys/slack-notifier.key').is_file() else None}))


def snapshot(engine, workspace, state, image, project='cloud-soc-central'):
    workspace, state = Path(workspace).resolve(), Path(state).resolve()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', project) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}', image):
        raise ValueError('Invalid image/project identity')
    checked_path(state / 'compose.env', state, file=True)
    checked_path(state / 'notifications', state)
    if (state / 'runtime/pending.json').exists():
        raise ValueError('Interrupted upgrade retained; run manage.py recover before making a new plan')
    value = policy(workspace);objects = containers(engine, project)
    inventory = worker_inventory(engine, project)
    active = active_command(state, objects, workspace=workspace)
    env = compose_environment(state, image, objects)
    original = engine.json(['compose', *active, 'config', '--format', 'json']) if active else {}
    runtime = state / 'runtime'
    current = json.loads((runtime / 'contract.json').read_text()) if (runtime / 'contract.json').is_file() else None
    contract, adoption = build_contract(value, objects, state, existing=current)
    dbs = databases(state)
    fresh = not objects or ((runtime / 'install.json').is_file() and not (runtime / 'current.json').exists())
    resources = resource_check(value, hardware(engine, state, project), fresh=fresh,
                               database_bytes=sum(p.stat().st_size for p in dbs))
    selected = {name: {'id': obj['Id'], 'image': obj['Image'], 'command': obj['Config']['Cmd'],
                      'mounts': obj.get('Mounts', []), 'environment': public_environment(obj)} for name, obj in objects.items()}
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
    if not fresh:
        prerequisites = inspect_prerequisites(engine, state, image, project, value, contract, adoption)
    # Only stable configuration participates in the stale-plan guard, not progress counters.
    identity = {'containers': selected, 'protected_sha256': fingerprints, 'image': candidate,
                'source_sha256': digest(source), 'prerequisites': prerequisites}
    result = {'plan_version': 1, 'policy': value, 'workspace': str(workspace), 'state': str(state), 'project': project,
        'image': image, 'image_id': candidate, 'source': source, 'source_sha256': digest(source),
        'fresh': fresh, 'contract': contract, 'adoption': adoption, 'resources': resources,
        'observed': selected, 'protected_sha256': fingerprints, 'previous_compose': active,
        'site': site_overlay(original, objects) if original else {}, 'compose_environment': env,
        'new_workers': [n for n in ALL_WORKERS if n not in objects], 'prerequisites': prerequisites,
        'worker_inventory': inventory, 'fingerprint': digest(identity)}
    desired = engine.json(['compose', '--profile', 'initialization', '--project-name', project, '--env-file', str(state / 'compose.env'),
        '-f', str(workspace / 'deploy/server/compose.yaml'), '-f', '-', 'config', '--format', 'json'],
        input=json.dumps(configure_site(result, runtime)), env=env)
    result['compose_validation'] = validate_rendered(value, desired, image)
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


def copy_adopted_state(plan, runtime):
    for name in WORKERS:
        folder = runtime / 'state' / name;folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        adoption = plan['adoption'].get(name, {})
        if 'state_source' in adoption:
            source = Path(adoption['state_source'])
            for path in source.parent.iterdir():
                if path.suffix not in ('.sqlite', '.sqlite3'):
                    continue
                checked_path(path, plan['state'], file=True)
                dest = folder / path.name
                if dest.exists():
                    if (runtime / 'current.json').exists():
                        raise ValueError('Active managed state cannot be re-adopted')
                    # Preserve an unactivated copy before retrying from the resumed legacy DB.
                    os.replace(dest, folder / (dest.name + '.unactivated-' + datetime.now(timezone.utc).strftime('%H%M%S%f')))
                backup_database(path, dest)
                if os.name == 'posix':
                    os.chown(dest, 1000, 1000)
        if os.name == 'posix':
            os.chown(folder, 1000, 1000)


def apply(engine, plan, *, poll=None):
    workspace, state = Path(plan['workspace']), Path(plan['state']);runtime = state / 'runtime'
    if not plan['resources']['ok']:
        raise ValueError('Server resource preflight failed; no mutation performed')
    with lock(runtime):
        current = snapshot(engine, workspace, state, plan['image'], plan['project'])
        if current['fingerprint'] != plan['fingerprint']:
            raise ValueError('Deployment changed after planning; no mutation performed')
        if not current['resources']['ok']:
            raise ValueError('Resource budget changed after review; no mutation performed')
        for field in ('policy', 'site', 'observed', 'protected_sha256', 'previous_compose', 'source', 'image_id', 'adoption'):
            if current[field] != plan[field]:
                raise ValueError('Reviewed plan was modified; no mutation performed')
        from cloud_soc.deployment.contract import stamp
        previous_contract = json.loads((runtime / 'contract.json').read_text()) if (runtime / 'contract.json').is_file() else None
        expected_contract, _ = build_contract(plan['policy'], containers(engine, plan['project']), state,
            now=stamp(plan['contract']['created_at']), existing=previous_contract)
        if expected_contract != plan['contract']:
            raise ValueError('Reviewed state/command plan was modified')
        run = runtime / 'upgrades' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        run.mkdir(mode=0o700, parents=True)
        if plan['fresh'] and not (runtime / 'install.json').exists():
            atomic_json(runtime / 'install.json', {'version': plan['policy']['version'], 'started': True})
        atomic_json(run / 'plan.json', plan)
        for name, digest_value in plan['protected_sha256'].items():
            p = Path(name)
            if hashlib.sha256(p.read_bytes()).hexdigest() != digest_value:
                raise ValueError('Protected file changed before backup')
            target = run / 'settings' / p.as_posix().lstrip('/')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True);shutil.copy2(p, target)
        for p in databases(state):
            backup_database(p, run / 'online' / p.relative_to(state))
        active = plan['previous_compose']
        old_objects = containers(engine, plan['project'])
        old_contract = (runtime / 'contract.json').read_bytes() if (runtime / 'contract.json').is_file() else None
        canonical = ['compose', '--project-name', plan['project'], '--env-file', str(state / 'compose.env'),
                     '-f', str(workspace / 'deploy/server/compose.yaml'), '-f', str(runtime / 'site.json')]
        atomic_json(run / 'recovery.json', {'previous_compose': active, 'old_names': list(old_objects),
            'old_contract': json.loads(old_contract) if old_contract else None,
            'old_current': json.loads((runtime / 'current.json').read_text()) if (runtime / 'current.json').is_file() else None,
            'canonical': canonical, 'environment': plan['compose_environment']})
        atomic_json(runtime / 'pending.json', {'run': str(run)})
        try:
            if active:
                stop = [n for n in APP_SERVICES if n in old_objects]
                engine.run(['compose', *active, 'stop', *stop])
            worker_inventory(engine, plan['project'], stopped=True)
            for p in databases(state):
                backup_database(p, run / 'stopped' / p.relative_to(state))
            saved_rows = portal_rows(state)
            saved_docs = {} if plan['fresh'] else immutable_documents(engine, state, plan['image'], plan['project'])
            atomic_json(run / 'preservation-before.json', {'portal_rows': saved_rows, 'documents': saved_docs})
            if not old_contract:
                copy_adopted_state(plan, runtime)
            contract = deepcopy(plan['contract']);contract['prepared'] = False
            atomic_json(runtime / 'contract.json', contract, uid=1000)
            atomic_json(runtime / 'site.json', configure_site(plan, runtime))
            env = plan['compose_environment']
            rendered = engine.json(canonical + ['config', '--format', 'json'], env=env)
            if not set(SERVICES) <= set(rendered['services']):
                raise ValueError('Common Compose omitted required services')
            for name in APP_SERVICES:
                if rendered['services'][name]['image'] != plan['image']:
                    raise ValueError('Mixed application image versions refused')
            if plan['fresh']:
                engine.run(canonical + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'elasticsearch'], env=env)
                if poll:
                    poll(engine, 'elasticsearch', plan['project'])
                engine.run(canonical + ['--profile', 'initialization', 'run', '--rm', '--no-deps', '--pull', 'never', 'bootstrap'], env=env)
            keys = {name: Path(row['key_source']).read_text().strip() for name, row in plan['adoption'].items() if 'key_source' in row}
            password = (state / 'secrets/elastic_password').read_text().strip()
            migration = engine.json(['run', '--rm', '-i', '--network', plan['project'] + '_default', '--user', '0:0',
                '-v', str(state / 'tls/ca.crt') + ':/run/certs/ca.crt:ro', '-v', str(runtime) + ':/deployment',
                '-v', str(state / 'notifications') + ':/notifications',
                '--entrypoint', 'python', plan['image'], '-m', 'cloud_soc.deployment.migrations'],
                input=json.dumps({'password': password, 'policy': plan['policy'], 'contract': contract, 'existing_keys': keys}))
            contract['prepared'] = True
            atomic_json(runtime / 'contract.json', contract, uid=1000)
            engine.run(canonical + ['up', '-d', '--no-build', '--pull', 'never', *SERVICES], env=env, timeout=300)
            if poll:
                for name in SERVICES:
                    poll(engine, name, plan['project'])
            after = containers(engine, plan['project'])
            if set(worker_inventory(engine, plan['project'])) != set(ALL_WORKERS):
                raise ValueError('Exactly one instance of every common worker is required')
            for name in SERVICES:
                if name not in after or not after[name]['State']['Running']:
                    raise ValueError('Required service not running')
                if name in APP_SERVICES and after[name]['Image'] != plan['image_id']:
                    raise ValueError('Runtime image differs from verified release')
            for name, h in plan['protected_sha256'].items():
                if hashlib.sha256(Path(name).read_bytes()).hexdigest() != h:
                    raise ValueError('Existing key/certificate/site file changed')
            after_rows = portal_rows(state)
            if any(not set(rows) <= set(after_rows.get(name, [])) for name, rows in saved_rows.items()):
                raise ValueError('Existing case/dashboard rows changed')
            preservation = immutable_documents(engine, state, plan['image'], plan['project'], before=saved_docs)
            receipt = {'version': plan['policy']['version'], 'policy_sha256': digest(plan['policy']), 'runtime_ready': True, 'source_sha256': plan['source_sha256'],
                'image_id': plan['image_id'], 'migrations': migration, 'preservation': preservation,
                'portal_saved_rows_preserved': sum(len(rows) for rows in saved_rows.values()), 'new_workers': plan['new_workers'],
                'live_ingestion_acceptance': 'not_yet_verified', 'utc': datetime.now(timezone.utc).isoformat()}
            atomic_json(run / 'applied.json', receipt)
            atomic_json(runtime / 'current.json', receipt)
            # A receipt is also the unambiguous input for the next upgrade.
            (run / 'compose.active.json').write_text(json.dumps(['docker', *canonical]))
            (runtime / 'compose.active.json').write_text(json.dumps(['docker', *canonical]))
            (runtime / 'pending.json').unlink()
            return receipt
        except BaseException as error:
            # Revert execution only. Original DBs were retained; migrated DBs are never rewound.
            _restore_execution(engine, runtime, run, json.loads((run / 'recovery.json').read_text()))
            atomic_json(run / 'failed.json', {'state': 'failed', 'error_type': type(error).__name__,
                'old_execution_restored': bool(active), 'databases_rewound': False})
            (runtime / 'pending.json').unlink()
            raise


def _restore_execution(engine, runtime, run, saved):
    active = saved['previous_compose']
    project = saved['canonical'][saved['canonical'].index('--project-name') + 1]
    present = containers(engine, project)
    targets = [project + '-' + name + '-1' for name in APP_SERVICES if name in present]
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
        engine.run(['compose', *active, 'up', '-d', '--no-build', '--pull', 'never', *saved['old_names']], timeout=300)
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
        pending.unlink()
        return {'recovery_required': True, 'old_execution_restored': bool(active), 'databases_rewound': False,
                'fresh_install_can_resume': not bool(active)}
