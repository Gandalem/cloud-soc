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
import stat
import subprocess
import sys
import tempfile

from cloud_soc.deployment.contract import (ALL_WORKERS, APP_SERVICES, SERVICES, WORKERS, build_contract, digest,
    policy, resource_check, source_files, validate_rendered)
from cloud_soc.deployment.migrations import atomic_json
from cloud_soc.deployment import image_safety
from cloud_soc.deployment.recovery_health import wait_for_recovery


class DockerCommandError(RuntimeError):
    """Allowlisted diagnostics only; Docker output may contain runtime secrets."""

    def __init__(self, args, *, returncode=None, timed_out=False, stderr=''):
        if args[0] == 'build':
            operation = 'image build'
        elif args[0] == 'pull':
            operation = 'image pull'
        elif args[0] == 'compose':
            operation = 'compose ' + next((v for v in ('pull', 'config', 'up', 'run', 'stop') if v in args), 'operation')
        else:
            operation = args[0] if args[0] in ('run', 'inspect', 'info', 'stats', 'ps', 'image', 'stop', 'exec') else 'operation'
        reason = 'Docker 서비스와 해당 단계의 출력을 확인하세요'
        lowered = stderr.lower()
        self.image_missing = args[:2] == ['image', 'inspect'] and any(
            word in lowered for word in ('no such image', 'image is not present locally', 'no such object'))
        terminal = ('no space left on device', 'permission denied', 'unauthorized', 'authentication required',
                    'manifest unknown', 'not found: manifest', 'pull access denied', 'x509:', 'invalid reference format')
        transient = ('no such host', 'network is unreachable', 'i/o timeout', 'tls handshake timeout',
                     'connection reset', 'connection refused', 'context deadline exceeded',
                     'temporary failure', 'temporary error', 'unexpected eof', 'awaiting headers',
                     '500 internal server error', '502 bad gateway', '503 service unavailable',
                     '504 gateway timeout', 'download timed out', 'read timed out', 'readtimeout',
                     'connecttimeout', 'network is down')
        self.retryable = not any(s in lowered for s in terminal) and (timed_out or any(s in lowered for s in transient))
        for patterns, hint in (
            (('no such image', 'image is not present locally'), '필요한 이미지가 서버에 없습니다'),
            (('manifest unknown', 'not found: manifest'), '저장소에서 해당 이미지 버전을 찾을 수 없습니다'),
            (('no space left on device',), '디스크 여유 공간이 부족합니다'),
            (('permission denied',), 'Docker 또는 연결 파일의 접근 권한이 없습니다'),
            (('cannot connect to the docker daemon',), 'Docker 서비스에 연결할 수 없습니다'),
            (('no such host', 'network is unreachable', 'i/o timeout', 'tls handshake timeout'), '이미지 저장소 또는 네트워크 연결에 실패했습니다'),
            (('healthcheck', 'unhealthy'), '필수 컨테이너의 상태 확인에 실패했습니다'),
        ):
            if any(pattern in lowered for pattern in patterns):
                reason = hint
                break
        status = '시간 초과' if timed_out else '실패 (종료 코드 ' + str(returncode) + ')'
        super().__init__('Docker ' + operation + ' ' + status + ': ' + reason + '. 기존 설정은 보존됐습니다.')


class Docker:
    def __init__(self):
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
        self.prefix = ['docker', '--host', 'unix:///var/run/docker.sock']

    def run(self, args, *, input=None, env=None, timeout=180, stream=False, idle_timeout=120):
        # Only public build/pull operations may inherit terminal output. JSON,
        # bootstrap and migration responses remain captured to protect secrets.
        if stream and (input is not None or not (args[0] in ('build', 'pull') or args[0] == 'compose' and 'pull' in args)):
            raise ValueError('Streaming is restricted to public image build/pull commands')
        if stream:
            from cloud_soc.deployment.public_stream import run
            try:
                code, tail = run(self.prefix + args, env={**self.env, **(env or {})},
                                 timeout=timeout, idle_timeout=idle_timeout)
            except subprocess.TimeoutExpired:
                raise DockerCommandError(args, timed_out=True) from None
            if code:
                raise DockerCommandError(args, returncode=code, stderr=tail)
            return ''
        try:
            p = subprocess.run(self.prefix + args, input=input, text=True, capture_output=not stream,
                               env={**self.env, **(env or {})}, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise DockerCommandError(args, timed_out=True) from None
        if p.returncode:
            raise DockerCommandError(args, returncode=p.returncode, stderr=p.stderr or '')
        return p.stdout or ''

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


def previous_compose_paths(active, runtime):
    """Static -f inputs only; site.json has its own mutable-state backup contract."""
    if not active:
        return []
    if not isinstance(active, list) or not all(isinstance(word, str) for word in active):
        raise image_safety.DeploymentSafetyError('이전 Compose 파일 목록을 확인할 수 없습니다')
    files = []
    for number, word in enumerate(active):
        if word != '-f':
            continue
        if number + 1 == len(active) or not Path(active[number + 1]).is_absolute():
            raise image_safety.DeploymentSafetyError('이전 Compose 파일은 명시적인 절대 경로여야 합니다')
        files.append(active[number + 1])
    if not files:
        raise image_safety.DeploymentSafetyError('이전 Compose 파일 목록이 없어 복구를 중단했습니다')
    return list(dict.fromkeys(name for name in files if Path(name) != Path(runtime) / 'site.json'))


def previous_compose_hashes(active, runtime):
    from cloud_soc.deployment.compose_review import regular
    try:
        return {name: hashlib.sha256(regular(name).read_bytes()).hexdigest()
                for name in previous_compose_paths(active, runtime)}
    except (ValueError, OSError):
        raise image_safety.DeploymentSafetyError('이전 Compose 파일이 없거나 안전한 일반 파일이 아닙니다') from None


def verify_previous_compose(active, runtime, expected):
    actual = previous_compose_hashes(active, runtime)
    if (not isinstance(expected, dict) or actual != expected
            or any(not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{64}', value)
                   for value in expected.values())):
        raise image_safety.DeploymentSafetyError('이전 Compose 파일의 검토 지문이 없거나 변경됐습니다. 기존 서비스와 복구 기록을 보존했습니다')
    return actual


def recovery_compose_hashes(active, runtime, run, saved):
    """Legacy journals need recorded evidence too; never trust today's file bytes."""
    names = previous_compose_paths(active, runtime)
    expected = saved.get('previous_compose_sha256')
    if expected is None:
        recorded = saved.get('reviewed_compose_files', {})
        if not isinstance(recorded, dict):
            raise image_safety.DeploymentSafetyError('이전 Compose 검토 기록 형식이 올바르지 않습니다')
        if not all(name in recorded for name in names):
            try:
                plan = json.loads(checked_path(run / 'plan.json', run, file=True).read_text())
                if not isinstance(plan, dict) or plan.get('previous_compose') != active:
                    raise ValueError('Previous command differs from its plan')
                recorded = plan.get('previous_compose_sha256', plan.get('protected_sha256', {}))
                if not isinstance(recorded, dict):
                    raise ValueError('Previous Compose hashes are not a mapping')
            except (ValueError, OSError):
                raise image_safety.DeploymentSafetyError('이전 Compose 검토 지문을 찾을 수 없습니다. 복구 기록을 보존했습니다') from None
        expected = {name: recorded.get(name) for name in names}
    return verify_previous_compose(active, runtime, expected)


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


def backup_stopped_database(source, target):
    """Snapshot a stopped writer's journal set; recover only disposable copies.

    A process terminated during a rollback transaction can leave a hot journal.
    Opening its live database mode=ro then fails with SQLITE_READONLY_ROLLBACK.
    Preserve committed WAL frames too, but never copy stale shared-memory locks.
    Caller must have stopped and verified every writer before invoking this.
    """
    source, target = Path(source), Path(target)
    if target.exists() or target.is_symlink():
        raise ValueError('Backup output already exists')
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    paths = [source, Path(str(source) + '-wal'), Path(str(source) + '-journal')]
    def signature():
        result = {}
        for path in paths:
            if path.is_symlink():
                raise ValueError('Symlinked database journal refused')
            if path.exists():
                info = path.stat()
                result[path.name] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
        if source.name not in result:
            raise ValueError('Stopped source database missing')
        return result
    before = signature()
    with tempfile.TemporaryDirectory(prefix='.stopped-sqlite-', dir=target.parent) as temporary:
        root = Path(temporary).resolve()
        for path in paths:
            if path.name in before:
                shutil.copyfile(path, root / path.name)
                (root / path.name).chmod(0o600)
        if signature() != before:
            raise ValueError('Stopped database changed during snapshot')
        staged = root / source.name
        # SQLite performs rollback/WAL recovery here, never on the live files.
        with closing(sqlite3.connect(staged.as_uri() + '?mode=rw', uri=True)) as recovered:
            if recovered.execute('pragma integrity_check').fetchall() != [('ok',)]:
                raise ValueError('Stopped snapshot integrity failed')
        backup_database(staged, target)


def portal_rows(state, *, stopped=False):
    """Hash saved case/dashboard rows from online snapshots, excluding SQLite counters."""
    result = {}
    with tempfile.TemporaryDirectory(prefix='portal-preservation-', dir=Path(state).parent) as temporary:
        for name in ('cases.sqlite', 'dashboards.sqlite'):
            source = Path(state) / 'portal' / name
            if not source.exists():
                continue
            copy = Path(temporary) / name
            (backup_stopped_database if stopped else backup_database)(source, copy)
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


def applied_release_root(state, objects, command):
    """Trust a previous external base only through its protected successful run."""
    from cloud_soc.deployment.compose_review import regular
    runtime = Path(state) / 'runtime'
    current = json.loads(regular(runtime / 'current.json', protected=True).read_text())
    if current.get('runtime_ready') is not True or current.get('image_id') != objects['portal']['Image']:
        raise ValueError('Applied release identity differs from the running Portal')
    for run in (runtime / 'upgrades').glob('*'):
        applied = run / 'applied.json'
        if not applied.is_file():
            continue
        if json.loads(regular(applied, protected=True).read_text()) != current:
            continue
        plan = json.loads(regular(run / 'plan.json', protected=True).read_text())
        saved = json.loads(regular(run / 'recovery.json', protected=True).read_text())
        previous = Path(plan['workspace'])
        base = previous / 'deploy/server/compose.yaml'
        canonical = ['docker', 'compose', '--project-name', 'cloud-soc-central',
                     '--env-file', str(Path(state) / 'compose.env'), '-f', str(base),
                     '-f', str(runtime / 'site.json')]
        if (not previous.is_absolute() or command != canonical or saved.get('canonical') != canonical[1:]
                or plan.get('state') != str(state) or plan.get('project') != 'cloud-soc-central'
                or plan.get('image_id') != current['image_id']
                or plan.get('source_sha256') != current.get('source_sha256')
                or digest(plan.get('source')) != current.get('source_sha256')
                or hashlib.sha256(regular(base).read_bytes()).hexdigest() != plan['source'].get('deploy/server/compose.yaml')):
            raise ValueError('Previous applied release proof differs from the active command/source')
        return previous
    raise ValueError('No protected successful run proves the previous external release')


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
                # A reviewed release may live next to the original checkout.
                # Only its exact canonical pair gains this additional root.
                base = Path(workspace).resolve() / 'deploy/server/compose.yaml' if workspace else None
                canonical = base and observed == [str(base), str(Path(state) / 'runtime/site.json')]
                previous_root = None
                for name in observed:
                    root = Path(workspace).resolve() if canonical and Path(name) == base else Path(state).parent.parent
                    if (not Path(name).resolve().is_relative_to(root.resolve()) and not canonical
                            and (Path(state) / 'runtime/current.json').is_file()):
                        from cloud_soc.deployment.compose_review import regular
                        regular(path, protected=True)
                        previous_root = previous_root or applied_release_root(state, objects, value)
                        if Path(name) == previous_root / 'deploy/server/compose.yaml':
                            root = previous_root
                    if not Path(name).resolve().is_relative_to(root.resolve()):
                        raise ValueError('Active Compose file escapes approved root (state/workspace)')
                    checked_path(name, root, file=True)
                return value[2:]
    from cloud_soc.deployment.compose_review import ComposeReviewError
    raise ComposeReviewError('Cannot identify the exact active Compose command. 실행 중인 Compose 설정과 보호 기록이 다릅니다. '
                             '기존 설정 파일을 확인해 manage.py review-compose로 검토한 뒤 '
                             'plan --compose-review에 보호된 검토 기록을 지정하세요')


def public_environment(obj):
    allowed = {'SOC_PUBLIC_URL', 'SOC_PUBLIC_HOST', 'SOC_PORTAL_LAN_ORIGIN', 'SOC_ENROLLMENT_ENABLED',
        'SOC_ELASTIC_ENDPOINT', 'SOC_AGENT_ENDPOINT', 'SOC_ADMIN_ALLOWED_CIDRS', 'SOC_USERS_FILE',
        'SOC_LOG_ACCESS_POLICY_FILE', 'SOC_LOG_FORMAT', 'SOC_INTERNAL_ES_URL', 'SOC_CA_FILE',
        'SOC_STATE_DIR', 'SOC_ADMIN_USER', 'SOC_ADMIN_HASH_FILE', 'SOC_ISSUER_PASSWORD_FILE', 'SOC_MONITOR_PASSWORD_FILE'}
    allowed |= {'SOC_PORTAL_ORIGINS', 'SOC_PORTAL_TLS_ORIGINS'}
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


def snapshot(engine, workspace, state, image, project='cloud-soc-central', *, compose_review=None, access_path=None,
             allow_missing_images=False):
    workspace, state = Path(workspace).resolve(), Path(state).resolve()
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', project) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}', image):
        raise ValueError('Invalid image/project identity')
    checked_path(state / 'compose.env', state, file=True)
    checked_path(state / 'notifications', state)
    if (state / 'runtime/pending.json').exists():
        raise ValueError('Interrupted upgrade retained; run manage.py recover before making a new plan')
    value = policy(workspace);objects = containers(engine, project)
    inventory = worker_inventory(engine, project)
    reviewed_files = {}
    if compose_review:
        from cloud_soc.deployment.compose_review import load
        active, reviewed_files = load(engine, state, compose_review, objects, project)
    else:
        active = active_command(state, objects, workspace=workspace)
    previous_hashes = previous_compose_hashes(active, state / 'runtime')
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
    fingerprints.update(reviewed_files)
    alias_request = None
    if access_path:
        from cloud_soc.deployment.access import read_profile
        alias_request = read_profile(access_path)
        fingerprints[alias_request['path']] = alias_request['sha256']
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
    if engine.run(['run', '--rm', '--network', 'none', '-i', '--entrypoint', 'python', candidate, '-c', script], input=json.dumps(source)).strip() != 'verified':
        raise ValueError('Candidate source verification failed')
    if objects and not active and not fresh:
        raise ValueError('Existing infrastructure has no adoption receipt; not a fresh installation')
    prerequisites = {'state': 'fresh_bootstrap_required'}
    if not fresh:
        prerequisites = inspect_prerequisites(engine, state, candidate, project, value, contract, adoption)
    # Only stable configuration participates in the stale-plan guard, not progress counters.
    identity = {'containers': selected, 'protected_sha256': fingerprints, 'image': candidate,
                'source_sha256': digest(source), 'prerequisites': prerequisites,
                'previous_compose': active, 'previous_compose_sha256': previous_hashes}
    result = {'plan_version': 1, 'policy': value, 'workspace': str(workspace), 'state': str(state), 'project': project,
        'image': image, 'image_id': candidate, 'source': source, 'source_sha256': digest(source),
        'fresh': fresh, 'contract': contract, 'adoption': adoption, 'resources': resources,
        'observed': selected, 'protected_sha256': fingerprints, 'previous_compose': active,
        'previous_compose_sha256': previous_hashes,
        'site': site_overlay(original, objects) if original else {}, 'compose_environment': env,
        'new_workers': [n for n in ALL_WORKERS if n not in objects], 'prerequisites': prerequisites,
        'worker_inventory': inventory, 'fingerprint': digest(identity)}
    if compose_review:
        result['compose_review'] = str(compose_review)
    if alias_request:
        result['alias_request'] = alias_request
    desired = engine.json(['compose', '--profile', 'initialization', '--project-name', project, '--env-file', str(state / 'compose.env'),
        '-f', str(workspace / 'deploy/server/compose.yaml'), '-f', '-', 'config', '--format', 'json'],
        input=json.dumps(configure_site(result, runtime)), env=env)
    if compose_review:
        from cloud_soc.deployment.compose_review import preserved_site
        preserved_site(original, desired, objects, **({'alias_request': alias_request, 'workspace': workspace}
                                                     if alias_request else {}))
    result['compose_validation'] = validate_rendered(value, desired, candidate)
    result['infrastructure_images'] = image_safety.infrastructure_images(
        engine, desired, allow_missing=allow_missing_images and fresh)
    result['previous_image_mode'] = image_safety.recovery_mode(engine, runtime, active, objects, original)
    identity.update({key: result[key] for key in ('infrastructure_images', 'previous_image_mode')})
    result['fingerprint'] = digest(identity)
    return result


def summary(plan):
    return {k: plan[k] for k in ('plan_version', 'image_id', 'source_sha256', 'fresh', 'resources', 'new_workers', 'fingerprint', 'prerequisites')} | {
        'required_workers': list(ALL_WORKERS), 'verified_rules': list(plan['policy']['verified_rules']),
        'preserve': ['data', 'state_identity', 'checkpoints', 'certificates', 'existing_key_material', 'site_endpoints'],
        'permissions': 'additive_exact_runtime_grants_with_restricted_scope_refusal',
        'infrastructure_changes': {'kibana': '1536MiB limit / 1024MiB Node heap', 'elasticsearch': '3072MiB limit / 1536MiB heap'},
        'compose_review': plan.get('compose_review'),
        'additional_portal_addresses': (plan.get('alias_request') or {}).get('profile', {}).get('aliases', []),
        'post_apply_checks': ['portal_direct_login', 'portal_external_link_login', 'mobile_portal_login', 'new_agent_log_receipt']}


def configure_site(plan, runtime):
    site = deepcopy(plan['site']) or {'services': {}}
    portal = site.setdefault('services', {}).setdefault('portal', {})
    mounts = portal.setdefault('volumes', [])
    # Compose merges by target: preserve the inspected site mounts and add the managed contract.
    mounts.append({'type': 'bind', 'source': str(runtime / 'contract.json'), 'target': '/run/runtime/contract.json', 'read_only': True})
    for name in (*APP_SERVICES, 'bootstrap'):
        site['services'].setdefault(name, {})['image'] = plan.get('image_id', plan['image'])
    for name, row in plan.get('infrastructure_images', {}).items():
        if row['image_id']:
            site['services'].setdefault(name, {})['image'] = row['image_id']
    if plan.get('alias_request'):
        from cloud_soc.deployment.access import overlay
        site = overlay(site, plan['alias_request'], Path(plan['state']), plan['workspace'])
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
                backup_stopped_database(path, dest)
                if os.name == 'posix':
                    os.chown(dest, 1000, 1000)
        if os.name == 'posix':
            os.chown(folder, 1000, 1000)


def save_previous_site(runtime, run):
    """Keep the exact Compose site file needed to restart the previous release."""
    path = checked_path(runtime / 'site.json', runtime)
    if not path.exists():
        return None
    checked_path(path, runtime, file=True)
    backup = checked_path(run / 'site.before.json', run)
    if backup.exists():
        raise ValueError('Previous site backup already exists')
    shutil.copy2(path, backup)
    info = path.stat()
    checksum = hashlib.sha256(path.read_bytes()).hexdigest()
    if hashlib.sha256(backup.read_bytes()).hexdigest() != checksum:
        raise ValueError('Previous site backup verification failed')
    return {'sha256': checksum, 'uid': info.st_uid, 'gid': info.st_gid}


def validate_previous_site(runtime, run, saved):
    """Read and validate once before stop; return the exact bytes to restore."""
    if saved is None:
        return
    if (not isinstance(saved, dict) or not isinstance(saved.get('sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', saved['sha256'])
            or any(type(saved.get(key)) is not int or not 0 <= saved[key] < 2**32 - 1 for key in ('uid', 'gid'))):
        raise ValueError('Previous site backup metadata is invalid; recovery stopped')
    backup = checked_path(run / 'site.before.json', run, file=True)
    data = backup.read_bytes()
    if hashlib.sha256(data).hexdigest() != saved['sha256']:
        raise ValueError('Previous site backup changed; recovery stopped')
    def object_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate site field')
            result[key] = value
        return result
    def reject_constant(_):
        raise ValueError('Non-JSON site value')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=object_fields, parse_constant=reject_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('Previous site backup JSON is invalid; recovery stopped') from None
    if (not isinstance(value, dict) or not isinstance(value.get('services', {}), dict)
            or any(not isinstance(service, dict) for service in value.get('services', {}).values())):
        raise ValueError('Previous site backup structure is invalid; recovery stopped')
    target = checked_path(runtime / 'site.json', runtime)
    if target.exists():
        checked_path(target, runtime, file=True)
    return data, backup.stat()


def restore_previous_site(runtime, run, saved, validated=None):
    if saved is None:
        return
    data, metadata = validated if validated is not None else validate_previous_site(runtime, run, saved)
    target = checked_path(runtime / 'site.json', runtime)
    fd, name = tempfile.mkstemp(prefix='.site-recovery-', dir=runtime)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        os.utime(temporary, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        info = temporary.stat()
        if os.name == 'posix' and (info.st_uid, info.st_gid) != (saved['uid'], saved['gid']):
            os.chown(temporary, saved['uid'], saved['gid'])
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply(engine, plan, *, poll=None):
    workspace, state = Path(plan['workspace']), Path(plan['state']);runtime = state / 'runtime'
    if not plan['resources']['ok']:
        raise ValueError('Server resource preflight failed; no mutation performed')
    with lock(runtime):
        request = plan.get('alias_request')
        extra = {'compose_review': plan['compose_review']} if plan.get('compose_review') else {}
        if request:
            extra['access_path'] = request['path']
        current = snapshot(engine, workspace, state, plan['image'], plan['project'],
                           **extra)
        if current['fingerprint'] != plan['fingerprint']:
            raise ValueError('Deployment changed after planning; no mutation performed')
        if not current['resources']['ok']:
            raise ValueError('Resource budget changed after review; no mutation performed')
        for field in ('policy', 'site', 'observed', 'protected_sha256', 'previous_compose', 'source', 'image_id', 'adoption',
                      'infrastructure_images', 'previous_image_mode'):
            if current[field] != plan[field]:
                raise ValueError('Reviewed plan was modified; no mutation performed')
        if (current.get('alias_request') != request
                or current.get('compose_environment') != plan.get('compose_environment')):
            from cloud_soc.deployment.compose_review import ComposeReviewError
            raise ComposeReviewError('추가 주소 또는 실행 환경이 계획 이후 변경됐습니다. 새 계획을 만드세요')
        if current.get('previous_compose_sha256') != plan.get('previous_compose_sha256'):
            raise ValueError('Previous Compose file review changed after planning; no services stopped')
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
        image_pins = {name: obj['Image'] for name, obj in old_objects.items()}
        for identity in set(image_pins.values()):
            if image_safety.local_image(engine, identity) != identity:
                raise image_safety.DeploymentSafetyError('이전 실행의 이미지가 없습니다. 서비스는 중지하지 않았습니다')
        old_contract = (runtime / 'contract.json').read_bytes() if (runtime / 'contract.json').is_file() else None
        old_site = save_previous_site(runtime, run)
        canonical = ['compose', '--project-name', plan['project'], '--env-file', str(state / 'compose.env'),
                     '-f', str(workspace / 'deploy/server/compose.yaml'), '-f', str(runtime / 'site.json')]
        if plan.get('compose_review'):
            from cloud_soc.deployment.compose_review import load
            active_now, reviewed_now = load(engine, state, plan['compose_review'], old_objects, plan['project'])
            if active_now != active or any(plan['protected_sha256'].get(p) != h for p, h in reviewed_now.items()):
                raise ValueError('Compose review changed before activation; no services stopped')
        previous_hashes = verify_previous_compose(active, runtime, plan.get('previous_compose_sha256', {}))
        atomic_json(run / 'recovery.json', {'previous_compose': active, 'old_names': list(old_objects),
            'previous_compose_sha256': previous_hashes,
            'old_contract': json.loads(old_contract) if old_contract else None,
            'old_current': json.loads((runtime / 'current.json').read_text()) if (runtime / 'current.json').is_file() else None,
            'old_site': old_site, 'canonical': canonical, 'environment': plan['compose_environment'],
            'reviewed_compose_files': {name: h for name, h in plan['protected_sha256'].items()
                                      if plan.get('compose_review') and Path(name).is_relative_to(runtime / 'compose-reviews')},
            'previous_images': sorted(set(image_pins.values())), 'image_pins': image_pins,
            'image_mode': plan['previous_image_mode']})
        atomic_json(runtime / 'pending.json', {'run': str(run)})
        try:
            verify_previous_compose(active, runtime, previous_hashes)
            if active:
                stop = [n for n in APP_SERVICES if n in old_objects]
                engine.run(['compose', *active, 'stop', *stop])
            worker_inventory(engine, plan['project'], stopped=True)
            for p in databases(state):
                try:
                    backup_stopped_database(p, run / 'stopped' / p.relative_to(state))
                except sqlite3.Error as error:
                    atomic_json(run / 'backup-failed.json', {
                        'phase': 'stopped', 'database': p.relative_to(state).as_posix(),
                        'sqlite_error': getattr(error, 'sqlite_errorname', None)})
                    raise
            saved_rows = portal_rows(state, stopped=True)
            saved_docs = {} if plan['fresh'] else immutable_documents(engine, state, plan['image_id'], plan['project'])
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
                if rendered['services'][name]['image'] != plan['image_id']:
                    raise ValueError('Mixed application image versions refused')
            if plan['fresh']:
                print('[설치] Elasticsearch를 시작하고 준비 상태를 기다립니다.', file=sys.stderr, flush=True)
                engine.run(canonical + ['up', '-d', '--no-deps', '--no-build', '--pull', 'never', 'elasticsearch'], env=env)
                if poll:
                    poll(engine, 'elasticsearch', plan['project'])
                print('[설치] 최초 서버 계정을 준비합니다.', file=sys.stderr, flush=True)
                engine.run(canonical + ['--profile', 'initialization', 'run', '--rm', '--no-deps', '--pull', 'never', 'bootstrap'], env=env)
            print('[설치] 처리 워커와 데이터 구성을 준비합니다.', file=sys.stderr, flush=True)
            keys = {name: Path(row['key_source']).read_text().strip() for name, row in plan['adoption'].items() if 'key_source' in row}
            password = (state / 'secrets/elastic_password').read_text().strip()
            migration = engine.json(['run', '--rm', '-i', '--network', plan['project'] + '_default', '--user', '0:0',
                '-v', str(state / 'tls/ca.crt') + ':/run/certs/ca.crt:ro', '-v', str(runtime) + ':/deployment',
                '-v', str(state / 'notifications') + ':/notifications',
                '--entrypoint', 'python', plan['image_id'], '-m', 'cloud_soc.deployment.migrations'],
                input=json.dumps({'password': password, 'policy': plan['policy'], 'contract': contract, 'existing_keys': keys}))
            contract['prepared'] = True
            atomic_json(runtime / 'contract.json', contract, uid=1000)
            print('[설치] Portal과 수집·탐지 워커를 시작합니다.', file=sys.stderr, flush=True)
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
            preservation = immutable_documents(engine, state, plan['image_id'], plan['project'], before=saved_docs)
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
                'old_execution_restored': bool(active), 'recovery_startup_verified': bool(active), 'databases_rewound': False})
            (runtime / 'pending.json').unlink()
            raise


def _restore_execution(engine, runtime, run, saved):
    active = saved['previous_compose']
    pins = saved.get('image_pins')
    mode = saved.get('image_mode')
    if active and pins is None:
        # Older protected journals already recorded actual container image IDs.
        old_plan = json.loads(checked_path(run / 'plan.json', run, file=True).read_text())
        pins = {name: old_plan.get('observed', {}).get(name, {}).get('image') for name in saved['old_names']}
        files = [active[i + 1] for i, word in enumerate(active[:-1]) if word == '-f']
        mode = 'site' if str(runtime / 'site.json') in files else 'immutable'
    pins = pins or {}
    if active and (not pins or set(pins) != set(saved['old_names']) or not all(pins.values())):
        raise image_safety.DeploymentSafetyError('이전 실행 이미지의 증거가 부족합니다. 복구 기록을 보존했습니다')
    previous_hashes = recovery_compose_hashes(active, runtime, run, saved)
    # A changed/missing frozen configuration must not be used to stop or replace services.
    for name, expected in saved.get('reviewed_compose_files', {}).items():
        path = checked_path(name, runtime / 'compose-reviews', file=True)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Reviewed recovery configuration changed; pending recovery retained')
    for image in set(pins.values()) | set(saved.get('previous_images', [])):
        if image_safety.local_image(engine, image) != image:
            raise ValueError('Previous recovery image is not available locally')
    if active and mode == 'immutable':
        rendered = engine.json(['compose', *active, 'config', '--format', 'json'])
        image_safety.recovery_mode(engine, runtime, active,
                                   {name: {'Image': image} for name, image in pins.items()}, rendered)
    elif active and (mode != 'site' or not saved.get('old_site')):
        raise image_safety.DeploymentSafetyError('이전 실행 설정을 안전하게 고정할 수 없습니다. 복구 기록을 보존했습니다')
    project = saved['canonical'][saved['canonical'].index('--project-name') + 1]
    present = containers(engine, project)
    targets = [project + '-' + name + '-1' for name in APP_SERVICES if name in present]
    verify_previous_compose(active, runtime, previous_hashes)
    validated_site = validate_previous_site(runtime, run, saved.get('old_site'))
    if targets:
        engine.run(['stop', *targets])
    restore_previous_site(runtime, run, saved.get('old_site'), validated_site)
    if active and mode == 'site':
        path = checked_path(runtime / 'site.json', runtime, file=True)
        info = path.stat()
        site = json.loads(path.read_text(encoding='utf-8'))
        for name, image in pins.items():
            site.setdefault('services', {}).setdefault(name, {})['image'] = image
        atomic_json(path, site)
        os.chmod(path, info.st_mode & 0o777)
        if os.name == 'posix' and (path.stat().st_uid, path.stat().st_gid) != (info.st_uid, info.st_gid):
            os.chown(path, info.st_uid, info.st_gid)
    # Restore metadata before starting the previous image; never restore a database.
    for name, value in (('contract.json', saved['old_contract']), ('current.json', saved['old_current'])):
        path = runtime / name
        if value is not None:
            atomic_json(path, value, uid=1000 if name == 'contract.json' else None)
        elif path.exists() and (active or name != 'contract.json'):
            shutil.copy2(path, run / ('interrupted-' + name));path.unlink()
    if active:
        verify_previous_compose(active, runtime, previous_hashes)
        engine.run(['compose', *active, 'up', '-d', '--no-build', '--pull', 'never', *saved['old_names']], timeout=300)
        wait_for_recovery(engine, project, pins)
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
        atomic_json(run / 'recovered.json', {'old_execution_restored': bool(active),
                                          'recovery_startup_verified': bool(active), 'databases_rewound': False})
        pending.unlink()
        return {'recovery_required': True, 'old_execution_restored': bool(active), 'databases_rewound': False,
                'recovery_startup_verified': bool(active),
                'fresh_install_can_resume': not bool(active)}
