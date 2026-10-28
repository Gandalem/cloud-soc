"""Explicit adoption of existing local Portal/gateway overrides, without activation.

Original inputs remain outside the normal trusted root. Only an integrity-bound,
resolved Compose snapshot is ever returned as an executable recovery command.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from cloud_soc.deployment.contract import SERVICES, digest
from cloud_soc.deployment.migrations import atomic_json


class ComposeReviewError(ValueError):
    """Messages contain only fixed diagnostics and public service identities."""


def private_directory(path):
    if path.is_symlink() or not path.is_dir():
        raise ComposeReviewError('보호 디렉터리 경로를 확인하세요')
    info = path.stat()
    if os.name == 'posix' and (info.st_uid != 0 or info.st_mode & 0o077):
        raise ComposeReviewError('보호 디렉터리는 root 소유이며 다른 사용자가 접근할 수 없어야 합니다')


def regular(path, *, protected=False):
    path = Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ComposeReviewError('구성 검토 경로는 링크가 아닌 절대 경로여야 합니다')
    if not path.is_file():
        raise ComposeReviewError('구성 검토에 필요한 일반 파일이 없습니다')
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ComposeReviewError('일반 파일이 아닌 구성은 인수할 수 없습니다')
    if protected and os.name == 'posix' and (info.st_uid != 0 or info.st_mode & 0o077):
        raise ComposeReviewError('검토 기록은 root 소유이며 다른 사용자가 접근할 수 없어야 합니다')
    return path


def checksum(path):
    return hashlib.sha256(regular(path).read_bytes()).hexdigest()


def labels(obj):
    return obj['Config'].get('Labels') or {}


def command(state, files, directory, project):
    return ['--project-name', project, '--project-directory', directory,
            '--env-file', str(state / 'compose.env'),
            *[v for path in files for v in ('-f', path)]]


def baseline(state, files, directory, project):
    """Do not reconstruct arbitrary CLI arguments from container labels."""
    receipt = regular(state / 'runtime/compose.active.json', protected=True)
    value = json.loads(receipt.read_text())
    if (not isinstance(value, list) or value[:2] != ['docker', 'compose']
            or len(value[2:]) % 2 or not all(isinstance(v, str) for v in value)):
        raise ComposeReviewError('기존 Compose 실행 기록 형식을 확인할 수 없습니다')
    pairs = list(zip(value[2::2], value[3::2]))
    if any(k not in ('--project-name', '--project-directory', '--env-file', '-f') for k, _ in pairs):
        raise ComposeReviewError('기존 실행 기록의 추가 옵션은 자동 인수하지 않습니다')
    for key, expected in (('--project-name', [project]), ('--env-file', [str(state / 'compose.env')])):
        if [v for k, v in pairs if k == key] != expected:
            raise ComposeReviewError('기존 프로젝트 또는 환경 파일이 일치하지 않습니다')
    if [v for k, v in pairs if k == '--project-directory'] not in ([], [directory]):
        raise ComposeReviewError('Compose 기준 디렉터리가 일치하지 않습니다')
    original = [v for k, v in pairs if k == '-f']
    if len(original) != 2 or files[:2] != original or len(files) <= 2:
        raise ComposeReviewError('기존 두 설정과 명시한 추가 설정의 순서가 일치하지 않습니다')
    from cloud_soc.deployment.host import checked_path
    for name in original:
        checked_path(regular(name), state.parent.parent, file=True)
    # Narrowly accept the observed site overrides. No command/mount/port changes.
    from cloud_soc.deployment.host import public_environment
    allowed = set(public_environment({'Config': {'Env': [k + '=x' for k in (
        'SOC_PUBLIC_URL', 'SOC_PUBLIC_HOST', 'SOC_PORTAL_LAN_ORIGIN', 'SOC_AGENT_ENDPOINT',
        'SOC_ADMIN_ALLOWED_CIDRS', 'SOC_ENROLLMENT_ENABLED')]}}))
    for name in files[2:]:
        obj = json.loads(regular(name).read_text())
        if not isinstance(obj, dict) or set(obj) != {'services'} or not isinstance(obj['services'], dict):
            raise ComposeReviewError('추가 설정은 Portal/gateway 서비스 설정만 인수할 수 있습니다')
        for service, row in obj['services'].items():
            if service not in ('portal', 'gateway') or not isinstance(row, dict) or set(row) - {'environment', 'image'}:
                raise ComposeReviewError('추가 설정에 범위를 벗어난 서비스 변경이 있습니다')
            if 'image' in row and (service != 'portal' or not isinstance(row['image'], str)):
                raise ComposeReviewError('Portal 외 이미지 변경은 자동 인수하지 않습니다')
            env = row.get('environment', {})
            if not isinstance(env, dict) or set(env) - allowed or any(not isinstance(v, str) for v in env.values()):
                raise ComposeReviewError('추가 환경 설정에 수동 검토가 필요한 항목이 있습니다')
    return receipt


def observed(objects, files, directory, project):
    if set(objects) != set(SERVICES):
        raise ComposeReviewError('필수 서비스 전체가 확인되어야 기존 구성을 인수할 수 있습니다')
    result = {}
    for name, obj in objects.items():
        meta = labels(obj)
        own = meta.get('com.docker.compose.project.config_files', '').split(',')
        if (meta.get('com.docker.compose.project') != project
                or meta.get('com.docker.compose.service') != name
                or meta.get('com.docker.compose.project.working_dir') != directory
                or own != files[:len(own)] or len(own) < 2
                or not obj.get('State', {}).get('Running')):
            raise ComposeReviewError('실행 중인 서비스의 구성 출처가 일치하지 않습니다: ' + name)
        config_hash = meta.get('com.docker.compose.config-hash', '')
        if not re.fullmatch(r'[0-9a-f]{64}', config_hash):
            raise ComposeReviewError('실행 중인 서비스의 구성 지문이 없습니다: ' + name)
        result[name] = {'id': obj['Id'], 'image': obj['Image'], 'config_files': own, 'config_hash': config_hash}
    if result['portal']['config_files'] != files:
        raise ComposeReviewError('명시한 전체 설정이 현재 Portal의 설정과 일치하지 않습니다')
    return result


def render(engine, args):
    return engine.json(['compose', *args, 'config', '--format', 'json'])


def verify_runtime(model, objects):
    """Container labels do not reflect later docker update/network mutations."""
    for name, obj in objects.items():
        row = model['services'][name]
        config, host = obj['Config'], obj.get('HostConfig', {})
        env = dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
        if any(env.get(k) != str(v) for k, v in row.get('environment', {}).items() if v is not None):
            raise ComposeReviewError('실제 서비스 환경값이 구성과 다릅니다: ' + name)
        for key, field in (('command', 'Cmd'), ('entrypoint', 'Entrypoint'), ('user', 'User')):
            if key in row and row[key] is not None and row[key] != config.get(field):
                raise ComposeReviewError('실제 서비스 실행 설정이 구성과 다릅니다: ' + name)
        mounts = {}
        for v in row.get('volumes', []):
            source = v['source']
            if v['type'] == 'volume':
                source = model['volumes'][source].get('name', source)
            mounts[v['target']] = (v['type'], source, not v.get('read_only', False))
        for kind in ('secrets', 'configs'):
            for v in row.get(kind, []):
                resource = model[kind][v['source']]
                if 'file' not in resource:
                    raise ComposeReviewError('파일이 아닌 비밀/설정 리소스는 자동 인수하지 않습니다')
                target = v.get('target', v['source'])
                if not target.startswith('/'):
                    target = ('/run/secrets/' if kind == 'secrets' else '/') + target
                mounts[target] = ('bind', resource['file'], False)
        actual = {m['Destination']: (m['Type'], m.get('Name') if m['Type'] == 'volume' else m['Source'], m['RW'])
                  for m in obj.get('Mounts', []) if m['Type'] != 'tmpfs'}
        if actual != mounts:
            raise ComposeReviewError('실제 서비스 연결 파일이 구성과 다릅니다: ' + name)
        ports = {}
        for p in row.get('ports', []):
            ports.setdefault(str(p['target']) + '/' + p.get('protocol', 'tcp'), []).append(
                {'HostIp': p.get('host_ip', ''), 'HostPort': str(p['published'])})
        normalize_ports = lambda value: {k: sorted(v, key=digest) for k, v in value.items() if v}
        if normalize_ports(host.get('PortBindings') or {}) != normalize_ports(ports):
            raise ComposeReviewError('실제 서비스 공개 포트가 구성과 다릅니다: ' + name)
        networks = {model['networks'][n].get('name', n) for n in row.get('networks', {})}
        if networks != set(obj.get('NetworkSettings', {}).get('Networks', {})):
            raise ComposeReviewError('실제 서비스 네트워크가 구성과 다릅니다: ' + name)
        if 'mem_limit' in row and int(row['mem_limit']) != host.get('Memory'):
            raise ComposeReviewError('실제 서비스 메모리 제한이 구성과 다릅니다: ' + name)
        if 'read_only' in row and row['read_only'] != host.get('ReadonlyRootfs'):
            raise ComposeReviewError('실제 서비스 읽기 전용 설정이 구성과 다릅니다: ' + name)
        if 'restart' in row and row['restart'] != host.get('RestartPolicy', {}).get('Name'):
            raise ComposeReviewError('실제 서비스 재시작 설정이 구성과 다릅니다: ' + name)


def verify_model(engine, args, model, inventory, objects):
    """Compose's own hash covers settings, independently of the image tag lookup."""
    lines = engine.run(['compose', *args, 'config', '--hash', '*']).splitlines()
    hashes = {}
    for line in lines:
        pair = line.split()
        if len(pair) != 2 or pair[0] in hashes or not re.fullmatch(r'[0-9a-f]{64}', pair[1]):
            raise ComposeReviewError('Compose 구성 지문 응답을 확인할 수 없습니다')
        hashes[pair[0]] = pair[1]
    for name, row in inventory.items():
        if hashes.get(name) != row['config_hash']:
            raise ComposeReviewError('파일의 설정과 실행 중인 설정이 다릅니다: ' + name)
        image = model.get('services', {}).get(name, {}).get('image')
        if not image or engine.json(['image', 'inspect', image])[0]['Id'] != row['image']:
            raise ComposeReviewError('이미지 태그와 실행 중인 이미지가 다릅니다: ' + name)
    verify_runtime(model, objects)


def pin_images(model, inventory):
    result = deepcopy(model)
    for name, row in inventory.items():
        result['services'][name]['image'] = row['image']
    return result


def preserved_site(original, desired, objects):
    """Refuse an upgrade that drops the adopted endpoints or broadens port binds."""
    from cloud_soc.deployment.host import public_environment
    for name in ('portal', 'gateway', 'elasticsearch', 'kibana'):
        old, new = original['services'][name], desired['services'][name]
        if sorted(old.get('ports', []), key=digest) != sorted(new.get('ports', []), key=digest):
            raise ComposeReviewError('기존 서비스 포트가 새 계획에서 달라집니다: ' + name)
        volumes = {v['target']: v for v in new.get('volumes', [])}
        if any(volumes.get(v['target']) != v for v in old.get('volumes', [])):
            raise ComposeReviewError('기존 서비스 연결 파일이 새 계획에서 달라집니다: ' + name)
        if name in ('portal', 'gateway'):
            expected = public_environment(objects[name])
            if any(new.get('environment', {}).get(k) != v for k, v in expected.items()):
                raise ComposeReviewError('기존 Portal/ngrok 환경 설정이 새 계획에서 달라집니다: ' + name)


def create(engine, state, files, objects, project='cloud-soc-central'):
    """Write only a new private review folder; do not change the active receipt."""
    state = Path(state).resolve()
    private_directory(state)
    if not 3 <= len(files) <= 16:
        raise ComposeReviewError('기존 두 설정과 추가 설정을 순서대로 지정하세요')
    files = [str(regular(p)) for p in files]
    if len(files) != len(set(files)):
        raise ComposeReviewError('같은 구성 파일을 중복 지정할 수 없습니다')
    directory = labels(objects.get('portal', {'Config': {}})).get('com.docker.compose.project.working_dir')
    if not directory or directory != str(Path(files[0]).parent):
        raise ComposeReviewError('기존 첫 Compose 파일의 기준 디렉터리를 확인해야 합니다')
    receipt = baseline(state, files, directory, project)
    inventory = observed(objects, files, directory, project)
    inputs = {p: checksum(p) for p in [*files, str(state / 'compose.env'), str(receipt)]}
    args = command(state, files, directory, project)
    model = render(engine, args)
    verify_model(engine, args, model, inventory, objects)
    from cloud_soc.deployment.host import checked_path
    root = checked_path(state / 'runtime/compose-reviews', state)
    root.mkdir(mode=0o700, exist_ok=True)
    private_directory(root)
    folder = Path(tempfile.mkdtemp(prefix='review-', dir=root))
    copy = folder / 'compose.json'
    # Check path rebasing using the same model before replacing image tags by IDs.
    atomic_json(copy, model)
    frozen_args = command(state, [str(copy)], directory, project)
    if render(engine, frozen_args) != model:
        raise ComposeReviewError('보호 사본으로 이동한 구성의 해석 결과가 달라졌습니다')
    frozen = pin_images(model, inventory)
    atomic_json(copy, frozen)
    if render(engine, frozen_args) != frozen:
        raise ComposeReviewError('고정 이미지 구성의 해석 결과가 달라졌습니다')
    if any(checksum(p) != h for p, h in inputs.items()):
        raise ComposeReviewError('검토 중 원본 구성이 변경됐습니다')
    review = {'version': 1, 'state': str(state), 'project': project, 'directory': directory,
              'files': files, 'inputs': inputs, 'inventory': inventory,
              'model_sha256': digest(model), 'frozen_sha256': checksum(copy), 'compose': str(copy)}
    path = folder / 'review.json'
    atomic_json(path, review)
    return {'review': str(path), 'sha256': checksum(path), 'services': sorted(inventory),
            'config_file_counts': {n: len(v['config_files']) for n, v in inventory.items()},
            'services_stopped': False, 'applied': False}


def load(engine, state, path, objects, project):
    """Revalidate the review against source inputs and actual service identities."""
    from cloud_soc.deployment.host import checked_path
    private_directory(state)
    path = checked_path(regular(path, protected=True), state / 'runtime/compose-reviews', file=True)
    private_directory(path.parent)
    private_directory(state / 'runtime/compose-reviews')
    review = json.loads(path.read_text())
    if review.get('version') != 1 or review.get('state') != str(state) or review.get('project') != project:
        raise ComposeReviewError('현재 서버의 구성 검토 기록이 아닙니다')
    baseline(state, review['files'], review['directory'], project)
    if any(checksum(p) != h for p, h in review['inputs'].items()):
        raise ComposeReviewError('검토 후 원본 설정이 변경됐습니다. 다시 검토하세요')
    if observed(objects, review['files'], review['directory'], project) != review['inventory']:
        raise ComposeReviewError('검토 후 실행 중인 서비스가 변경됐습니다')
    args = command(state, review['files'], review['directory'], project)
    model = render(engine, args)
    if digest(model) != review['model_sha256']:
        raise ComposeReviewError('검토 후 참조 설정의 해석 결과가 변경됐습니다')
    verify_model(engine, args, model, review['inventory'], objects)
    copy = checked_path(regular(review['compose'], protected=True), path.parent, file=True)
    if checksum(copy) != review['frozen_sha256']:
        raise ComposeReviewError('보호된 복구 구성 사본이 변경됐습니다')
    frozen_args = command(state, [str(copy)], review['directory'], project)
    if render(engine, frozen_args) != pin_images(model, review['inventory']):
        raise ComposeReviewError('보호된 복구 구성의 해석 결과가 다릅니다')
    return frozen_args, {str(path): checksum(path), str(copy): checksum(copy)}
